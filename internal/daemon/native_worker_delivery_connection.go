package daemon

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func (c *NativeObservationConnection) deliveryReadyLocked(content bool) error {
	select {
	case <-c.closed:
		return ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		return ErrNativeOriginAdmissionDeferred
	}
	if content {
		found := false
		for _, f := range c.session.ProtocolFeatures {
			if f == transport.NativeContentProtocol {
				found = true
			}
		}
		if !found {
			return ErrNativeSourceUnsupported
		}
	}
	return nil
}

// NativeContentDisposition must receive frames from this connection only.
func (c *NativeObservationConnection) NativeContentDisposition(p transport.NativeContentStagedPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	if ch := c.pendingContent[p.ContentID]; ch != nil {
		select {
		case ch <- p:
		default:
		}
	}
}

// NativeWorkerObservationDisposition routes committed/rejected receipt frames.
// Rejections are diagnostics only and never authorize a private worker ACK.
func (c *NativeObservationConnection) NativeWorkerObservationDisposition(typ string, p transport.NativeObservationReceiptPayload) {
	if typ != transport.MsgNativeObservationReceipt && typ != transport.MsgNativeObservationRejected {
		return
	}
	if typ == transport.MsgNativeObservationRejected && p.Disposition == "committed" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	if ch := c.pendingObservations[p.ObservationID]; ch != nil {
		select {
		case ch <- p:
		default:
		}
	}
}

func (c *NativeObservationConnection) contentExchange(ctx context.Context, typ string, p any, ref transport.NativeContentReference) (transport.NativeContentStagedPayload, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan transport.NativeContentStagedPayload, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(true); err != nil {
		c.mu.Unlock()
		return transport.NativeContentStagedPayload{}, err
	}
	if len(c.pending)+len(c.pendingSessions)+len(c.pendingContent)+len(c.pendingObservations) >= 64 {
		c.mu.Unlock()
		return transport.NativeContentStagedPayload{}, ErrNativeObservationCapacity
	}
	if c.pendingContent == nil {
		c.pendingContent = make(map[string]chan transport.NativeContentStagedPayload)
	}
	if c.pendingContent[ref.ContentID] != nil {
		c.mu.Unlock()
		return transport.NativeContentStagedPayload{}, ErrNativeObservationConflict
	}
	c.pendingContent[ref.ContentID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingContent, ref.ContentID); c.mu.Unlock() }()
	if err := c.send(ctx, typ, p); err != nil {
		return transport.NativeContentStagedPayload{}, err
	}
	select {
	case <-ctx.Done():
		return transport.NativeContentStagedPayload{}, ctx.Err()
	case <-c.closed:
		return transport.NativeContentStagedPayload{}, ErrNativeOriginAdmissionDeferred
	case reply := <-ch:
		c.mu.Lock()
		err := c.deliveryReadyLocked(true)
		c.mu.Unlock()
		if err != nil {
			return reply, err
		}
		if reply.ContentID != ref.ContentID || reply.CiphertextDigest != ref.CiphertextDigest {
			return reply, ErrNativeObservationConflict
		}
		if reply.PublicError != "" {
			if reply.Retryable {
				return reply, ErrNativeOriginAdmissionDeferred
			}
			return reply, ErrNativeOriginAdmissionRejected
		}
		if len(reply.MissingOrdinals) > 32 || (len(reply.MissingOrdinals) == 0 && reply.MoreMissing) {
			return reply, ErrNativeObservationConflict
		}
		previous := -1
		for _, ordinal := range reply.MissingOrdinals {
			if ordinal <= previous || ordinal >= ref.FragmentCount {
				return reply, ErrNativeObservationConflict
			}
			previous = ordinal
		}
		return reply, nil
	}
}

func (c *NativeObservationConnection) stageWorkerContent(ctx context.Context, o sessionworker.NativeObservation, ref transport.NativeContentReference, call func(context.Context, sessionworker.Request) (sessionworker.Response, error), budget *int) (bool, error) {
	if ref.FragmentCount < 1 || ref.FragmentCount > 320 || ref.ObservationID != o.ID || ref.NativeGeneration != o.NativeGeneration || ref.NativeSessionID != o.NativeSessionID {
		return false, ErrNativeObservationConflict
	}
	reply, err := c.contentExchange(ctx, transport.MsgNativeContentBegin, ref, ref)
	if err != nil {
		return false, err
	}
	for len(reply.MissingOrdinals) > 0 {
		for _, ordinal := range reply.MissingOrdinals {
			if *budget <= 0 {
				return false, nil
			}
			r, err := call(ctx, sessionworker.Request{Type: "content_fragment", ObservationID: o.ID, SourceDigest: o.SourceDigest, ContentID: ref.ContentID, ContentOrdinal: ordinal})
			if err != nil {
				return false, err
			}
			if r.Error != "" {
				return false, errors.New(r.Error)
			}
			f := r.ContentFragment
			if f == nil || f.ContentID != ref.ContentID || f.Ordinal != ordinal {
				return false, ErrNativeObservationConflict
			}
			raw, err := json.Marshal(f)
			if err != nil || len(raw) > 128<<10 {
				return false, ErrNativeObservationCapacity
			}
			if err = c.send(ctx, transport.MsgNativeContentFragment, f); err != nil {
				return false, err
			}
			*budget--
		}
		reply, err = c.contentExchange(ctx, transport.MsgNativeContentStatus, transport.NativeContentStatusPayload{ContentID: ref.ContentID, CiphertextDigest: ref.CiphertextDigest}, ref)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (c *NativeObservationConnection) deliverWorkerObservation(ctx context.Context, p transport.NativeObservationPayload) (transport.NativeObservationReceiptPayload, error) {
	ctx, cancel := nativeDeliveryContext(ctx)
	defer cancel()
	ch := make(chan transport.NativeObservationReceiptPayload, 1)
	c.mu.Lock()
	if err := c.deliveryReadyLocked(false); err != nil {
		c.mu.Unlock()
		return transport.NativeObservationReceiptPayload{}, err
	}
	if len(c.pending)+len(c.pendingSessions)+len(c.pendingContent)+len(c.pendingObservations) >= 64 {
		c.mu.Unlock()
		return transport.NativeObservationReceiptPayload{}, ErrNativeObservationCapacity
	}
	if c.pendingObservations == nil {
		c.pendingObservations = make(map[string]chan transport.NativeObservationReceiptPayload)
	}
	if c.pendingObservations[p.ObservationID] != nil {
		c.mu.Unlock()
		return transport.NativeObservationReceiptPayload{}, ErrNativeObservationConflict
	}
	c.pendingObservations[p.ObservationID] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pendingObservations, p.ObservationID); c.mu.Unlock() }()
	if err := c.send(ctx, transport.MsgNativeObservation, p); err != nil {
		return transport.NativeObservationReceiptPayload{}, err
	}
	select {
	case <-ctx.Done():
		return transport.NativeObservationReceiptPayload{}, ctx.Err()
	case <-c.closed:
		return transport.NativeObservationReceiptPayload{}, ErrNativeOriginAdmissionDeferred
	case reply := <-ch:
		c.mu.Lock()
		err := c.deliveryReadyLocked(false)
		c.mu.Unlock()
		if err != nil {
			return reply, err
		}
		if reply.ObservationID != p.ObservationID || reply.OriginID != p.OriginID || reply.Digest != p.Digest {
			return reply, ErrNativeObservationConflict
		}
		return reply, nil
	}
}
