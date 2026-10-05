package fabricnative

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric/registry"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// OriginalCaptureOwnership is a private accepted-worker source capability. It
// cannot be reconstructed from a checkpoint, decoded receipt or copied ref.
type OriginalCaptureOwnership struct{ stream *nativeStream }

func (*OriginalCaptureOwnership) OriginalSourceProtocol() string { return "native.original.v1" }
func (*OriginalCaptureOwnership) MarshalJSON() ([]byte, error)   { return nil, checkpointDenied() }
func (*OriginalCaptureOwnership) UnmarshalJSON([]byte) error     { return checkpointDenied() }
func (o *OriginalCaptureOwnership) Reference() (SourceReference, error) {
	if o == nil || o.stream == nil || o.stream.outputCapture == nil {
		return SourceReference{}, checkpointDenied()
	}
	return referenceFor(o.stream.checkpoint, o.stream.reservation), nil
}
func (o *OriginalCaptureOwnership) Close() error {
	if o == nil || o.stream == nil {
		return nil
	}
	s := o.stream
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.detached = true
		close(s.closeDone)
	}
	s.mu.Unlock()
	s.cancel()
	return nil
}
func (s *nativeStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, checkpointDenied()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outputCapture == nil || s.closed {
		return nil, checkpointDenied()
	}
	return &OriginalCaptureOwnership{stream: s}, nil
}
func (s *nativeStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || next == nil || s.outputCapture == nil || !s.captureClaim.CompareAndSwap(false, true) {
		return checkpointDenied()
	}
	s.mu.Lock()
	usable := !s.closed
	s.mu.Unlock()
	if !usable {
		return checkpointDenied()
	}
	call, cancel := context.WithCancel(context.WithoutCancel(s.lifetime))
	defer cancel()
	if deadline, ok := s.lifetime.Deadline(); ok {
		limited, stop := context.WithDeadline(call, deadline)
		defer stop()
		call = limited
	}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return s.outputCapture.WithOutput(call, func(c context.Context) error {
		if err := next(c); err != nil {
			return err
		}
		// Final projection committed the genuine terminal before acknowledging its
		// exact original cipher. No transformer or outer Next is replayed here.
		s.mu.Lock()
		terminal := s.terminal
		ack := s.pending
		s.mu.Unlock()
		if !terminal || ack == nil {
			return nil
		}
		resolver, ok := s.adapter.config.Workers.(OriginalOutputResolver)
		if !ok {
			return fabric.NewError(fabric.CodeUnsupported, "Original native output refresh unavailable")
		}
		h, err := resolver.RefreshOriginalOutput(c, s.outputCapture, s.reservation, s.ownership)
		if err != nil {
			return err
		}
		defer clear(h.ControlKey)
		if err = s.adapter.handle(c, h, s.ownership); err != nil {
			return err
		}
		err = s.adapter.config.Authority.FenceOriginalNativeOutput(c, s.adapter.config.Owner, h.Current, h.Binding, s.outputCapture, s.reservation, identity.NativeSourceAck, func(c context.Context) error {
			_, err := h.Client.Call(c, sessionworker.LocalRequest{Type: "stream_ack", Control: &nativeauthority.LocalControl{CurrentController: h.Current, CurrentBinding: h.Binding}, Sequence: s.reservation.Sequence, Cursor: ack.Cursor, Digest: ack.Digest})
			return err
		})
		if err == nil {
			s.mu.Lock()
			s.cursor = ack.Cursor
			s.pending = nil
			s.mu.Unlock()
		}
		return err
	})
}

func (s *nativeStream) refreshOutput(ctx context.Context) (WorkerHandle, error) {
	if s.outputCapture != nil && s.outputCapture.Active(ctx) {
		r, ok := s.adapter.config.Workers.(OriginalOutputResolver)
		if !ok {
			return WorkerHandle{}, fabric.NewError(fabric.CodeUnsupported, "Original native output refresh unavailable")
		}
		return r.RefreshOriginalOutput(ctx, s.outputCapture, s.reservation, s.ownership)
	}
	return s.adapter.config.Workers.Refresh(ctx, s.caller, s.ownership)
}
func (s *nativeStream) readOutput(ctx context.Context, h WorkerHandle, op identity.NativeSourceReadOperation, next func(context.Context) error) error {
	if s.outputCapture != nil && s.outputCapture.Active(ctx) {
		return s.adapter.config.Authority.FenceOriginalNativeOutput(ctx, s.adapter.config.Owner, h.Current, h.Binding, s.outputCapture, s.reservation, op, next)
	}
	return s.adapter.read(ctx, s.caller, h, s.checkpoint, s.reservation, op, next)
}

// Checkpoint returns immutable evidence metadata only; it never mints a source.
func (o *OriginalCaptureOwnership) Checkpoint() (OriginalCheckpoint, error) {
	if o == nil || o.stream == nil || o.stream.outputCapture == nil {
		return OriginalCheckpoint{}, checkpointDenied()
	}
	var c OriginalCheckpoint
	raw, err := json.Marshal(o.stream.checkpoint)
	if err != nil || fabric.DecodeJSON(raw, &c) != nil {
		return c, checkpointDenied()
	}
	return c, nil
}
func (a *Adapter) VerifyOriginalCaptureTx(ctx context.Context, tx *registry.AuthorityTx, o *OriginalCaptureOwnership) error {
	if a == nil || tx == nil || o == nil || o.stream == nil || o.stream.adapter != a {
		return checkpointDenied()
	}
	return a.config.Authority.VerifyOriginalOutputTx(ctx, tx, o.stream.outputCapture, o.stream.reservation)
}
