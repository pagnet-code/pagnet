package daemon

import (
	"bytes"
	"context"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) NativeTaskInputDisposition(p transport.NativeTaskInputReadPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	if ch := c.pendingTaskInputs[p.RequestID]; ch != nil {
		select {
		case ch <- p:
		default:
		}
	}
}

func (c *NativeObservationConnection) ReadOriginalTaskInput(ctx context.Context, instance, command, admission string, original *transport.NativeTaskSource) (transport.NativeTaskInputReadPayload, error) {
	var empty transport.NativeTaskInputReadPayload
	if original == nil || original.InputAAD.ValidateScope() != nil {
		return empty, ErrNativeObservationConflict
	}
	for _, id := range []string{instance, command, admission, original.TaskID} {
		if _, err := domain.ParseID(id); err != nil {
			return empty, ErrNativeObservationConflict
		}
	}
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	request := domain.NewID().String()
	ch := make(chan transport.NativeTaskInputReadPayload, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(true); err != nil {
		c.mu.Unlock()
		return empty, err
	}
	feature := false
	for _, name := range c.session.ProtocolFeatures {
		if name == transport.NativeTaskContentProtocol {
			feature = true
		}
	}
	if !feature {
		c.mu.Unlock()
		return empty, ErrNativeSourceUnsupported
	}
	if c.pendingCountLocked() >= 64 {
		c.mu.Unlock()
		return empty, ErrNativeObservationCapacity
	}
	if c.pendingTaskInputs == nil {
		c.pendingTaskInputs = map[string]chan transport.NativeTaskInputReadPayload{}
	}
	c.pendingTaskInputs[request] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingTaskInputs, request); c.mu.Unlock() }()
	if err := c.send(ctx, transport.MsgNativeTaskInput, transport.NativeTaskInputPayload{RequestID: request, SourceCommandID: command, SourceAdmissionID: admission, InstanceID: instance}); err != nil {
		return empty, err
	}
	select {
	case <-ctx.Done():
		return empty, ctx.Err()
	case <-c.closed:
		return empty, ErrNativeOriginAdmissionDeferred
	case reply := <-ch:
		c.mu.Lock()
		err := c.deliveryReadyLocked(true)
		c.mu.Unlock()
		if err != nil {
			return empty, err
		}
		if reply.RequestID != request || reply.InstanceID != instance || reply.SourceCommandID != command || reply.SourceAdmissionID != admission {
			return empty, ErrNativeObservationConflict
		}
		if reply.PublicError != "" {
			if reply.Retryable {
				return empty, ErrNativeOriginAdmissionDeferred
			}
			return empty, ErrNativeOriginAdmissionRejected
		}
		if reply.TaskSource == nil || reply.Envelope == nil || reply.TaskSource.TaskID != original.TaskID || !bytes.Equal(reply.TaskSource.InputAAD.CanonicalBytes(), original.InputAAD.CanonicalBytes()) || reply.Envelope.KeyEpochID != original.InputAAD.KeyEpochID || reply.Envelope.Validate() != nil {
			return empty, ErrNativeObservationConflict
		}
		return reply, nil
	}
}
