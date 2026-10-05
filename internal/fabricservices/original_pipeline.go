package fabricservices

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"sync/atomic"
)

type originalCaptureContextKey struct{}
type originalCaptureContext struct {
	source *sourceCapture
	active atomic.Bool
}

// OriginalCaptureOwnership has no exported minting fields or serializable
// capability. It refers to an actual fresh FULL admitted SDK source.
type OriginalCaptureOwnership struct{ source *sourceCapture }

func (*OriginalCaptureOwnership) OriginalSourceProtocol() string { return "service.original.v1" }
func (*OriginalCaptureOwnership) Close() error                   { return nil } // delivery, not effect cancellation
func (*OriginalCaptureOwnership) MarshalJSON() ([]byte, error)   { return nil, denied() }
func (*OriginalCaptureOwnership) UnmarshalJSON([]byte) error     { return denied() }
func (o *OriginalCaptureOwnership) Reference() (SourceReference, error) {
	if o == nil || o.source == nil {
		return SourceReference{}, denied()
	}
	return serviceReference(o.source.receipt), nil
}

// VerifyOriginalCaptureTx validates exact actual original SDK receipt inside the
// consumer's SAME transaction; neither a decoded reference nor protocol label
// suffices. No source/provider work or nested SQL is performed.
func (i *Invocations) VerifyOriginalCaptureTx(ctx context.Context, tx *registry.AuthorityTx, o *OriginalCaptureOwnership) error {
	if i == nil || ctx == nil || ctx.Err() != nil || tx == nil || o == nil || o.source == nil || o.source.ledger != i {
		return denied()
	}
	c := o.source
	proof, ok := ctx.Value(originalCaptureContextKey{}).(*originalCaptureContext)
	if !ok || proof == nil || proof.source != c || !proof.active.Load() {
		return denied()
	}
	var r Receipt
	if _, err := i.decode(tx, "invocation/"+invocationKey(c.receipt.Facts.Principal, c.receipt.Facts.InvocationID), &r); err != nil {
		return err
	}
	if !i.validOriginalReceipt(r) || receiptSHA(r) != c.commitment || r.Facts != c.receipt.Facts {
		return denied()
	}
	return nil
}
func (s *retainedStream) OriginalSourceOwnership(ctx context.Context) (fabric.OriginalSourceOwnership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || s.capture == nil || s.closed || s.detached {
		return nil, denied()
	}
	return &OriginalCaptureOwnership{s.capture}, nil
}
func (s *retainedStream) WithOriginalCapture(ctx context.Context, next func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || next == nil {
		return denied()
	}
	s.mu.Lock()
	c := s.capture
	usable := c != nil && !s.closed && !s.detached
	s.mu.Unlock()
	if !usable || c.closed.Load() || c.ctx.Err() != nil || !c.pipelineClaim.CompareAndSwap(false, true) {
		return denied()
	}
	proof := &originalCaptureContext{source: c}
	proof.active.Store(true)
	defer proof.active.Store(false)
	// Preserve the genuine downstream finalized request/selected-plan values,
	// while terminal source cleanup cannot cancel outer completion/unwind hooks.
	// This adds only the private original-output capability, never live caller
	// authority. Current admission/emit policy still validates original evidence.
	call, cancel := context.WithCancel(context.WithoutCancel(c.ctx))
	if deadline, ok := c.ctx.Deadline(); ok {
		limited, stop := context.WithDeadline(call, deadline)
		previous := cancel
		cancel = func() { stop(); previous() }
		call = limited
	}
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	return next(context.WithValue(call, originalCaptureContextKey{}, proof))
}
func (s *retainedStream) isOriginalCapture(ctx context.Context) bool {
	p, ok := ctx.Value(originalCaptureContextKey{}).(*originalCaptureContext)
	return ok && p != nil && p.source == s.capture && p.active.Load()
}

// Facts returns copied immutable routing commitments, not authority or keys.
func (o *OriginalCaptureOwnership) Facts() (InvocationFacts, error) {
	if o == nil || o.source == nil {
		return InvocationFacts{}, denied()
	}
	return o.source.receipt.Facts, nil
}
