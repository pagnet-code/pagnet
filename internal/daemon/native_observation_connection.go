package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrNativeOriginAdmissionDeferred = errors.New("native activation admission must retry")
var ErrNativeOriginAdmissionRejected = errors.New("native activation admission rejected")

// NativeObservationConnection belongs to one authenticated WebSocket only.
// Its writer must never select a replacement connection behind this object's
// back: registration and replies are fenced to the same runner admission.
type NativeObservationConnection struct {
	mu             sync.Mutex
	hostID, bootID string
	session        *transport.HostSessionPayload
	pending        map[string]chan transport.NativeOriginRegisteredPayload
	closed         chan struct{}
	send           func(context.Context, string, any) error
}

func NewNativeObservationConnection(hostID, bootID string, send func(context.Context, string, any) error) *NativeObservationConnection {
	return &NativeObservationConnection{hostID: hostID, bootID: bootID, send: send, pending: make(map[string]chan transport.NativeOriginRegisteredPayload), closed: make(chan struct{})}
}

func (c *NativeObservationConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	c.session = nil
}

func (c *NativeObservationConnection) Admit(p transport.HostSessionPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ErrNativeOriginAdmissionDeferred
	default:
	}
	if p.HostID != c.hostID || p.BootID != c.bootID || p.RunnerEpoch.IsZero() {
		return ErrNativeObservationConflict
	}
	if _, err := domain.ParseID(p.RunnerID); err != nil {
		return ErrNativeObservationConflict
	}
	negotiated := false
	for _, feature := range p.ProtocolFeatures {
		if feature == transport.NativeObservationReceiptProtocol {
			negotiated = true
		}
	}
	if !negotiated {
		return errors.New("native observation receipts unavailable")
	}
	if c.session != nil {
		if c.session.RunnerID != p.RunnerID || !c.session.RunnerEpoch.Equal(p.RunnerEpoch) {
			return ErrNativeObservationConflict
		}
		return nil
	}
	copy := p
	copy.ProtocolFeatures = append([]string(nil), p.ProtocolFeatures...)
	c.session = &copy
	return nil
}

func (c *NativeObservationConnection) RegisterOrigin(ctx context.Context, commandID, instanceID, runtime string) (*transport.NativeObservationOrigin, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request := domain.NewID().String()
	reply := make(chan transport.NativeOriginRegisteredPayload, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, ErrNativeOriginAdmissionDeferred
	default:
	}
	if c.session == nil {
		c.mu.Unlock()
		return nil, ErrNativeOriginAdmissionDeferred
	}
	if len(c.pending) >= 64 {
		c.mu.Unlock()
		return nil, ErrNativeObservationCapacity
	}
	expected := *c.session
	c.pending[request] = reply
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, request); c.mu.Unlock() }()
	if err := c.send(ctx, transport.MsgNativeOriginRegister, transport.NativeOriginRegisterPayload{RequestID: request, CommandID: commandID, InstanceID: instanceID, Runtime: runtime}); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrNativeOriginAdmissionDeferred
	case response := <-reply:
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return nil, ErrNativeOriginAdmissionDeferred
		default:
		}
		c.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if response.PublicError != "" || response.Origin == nil {
			if response.Retryable {
				return nil, ErrNativeOriginAdmissionDeferred
			}
			return nil, ErrNativeOriginAdmissionRejected
		}
		o := response.Origin
		// Existing same-boot origins retain their original epoch on reconnect.
		if o.HostID != expected.HostID || o.RunnerID != expected.RunnerID || o.BootID != expected.BootID || o.CommandID != commandID || o.InstanceID != instanceID || o.Runtime != runtime || o.RunnerEpoch.IsZero() || o.RunnerEpoch.After(expected.RunnerEpoch) || o.CreatedAt.IsZero() {
			return nil, ErrNativeObservationConflict
		}
		if _, err := domain.ParseID(o.ID); err != nil {
			return nil, ErrNativeObservationConflict
		}
		return o, nil
	}
}

func (c *NativeObservationConnection) OriginRegistered(p transport.NativeOriginRegisteredPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	reply := c.pending[p.RequestID]
	if reply == nil {
		return
	}
	select {
	case reply <- p:
	default:
	}
}
