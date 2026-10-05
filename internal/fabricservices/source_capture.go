package fabricservices

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// sourceCapture is a PRIVATE in-process append-only capability minted solely
// after a fresh FULL paid reservation and before the selected SDK operation.
// It authenticates source output retention, never caller/disclosure or another
// paid attempt. It cannot be constructed from a decoded receipt or serialized.
type sourceCapture struct {
	ledger        *Invocations
	receipt       Receipt
	commitment    [32]byte
	source        any
	ctx           context.Context
	cancel        context.CancelFunc
	stopParent    func() bool
	closed        atomic.Bool
	beginDrain    func() (func(), error)
	releaseSource func()
}

func (i *Invocations) reserveSource(ctx context.Context, caller fabric.ExecutionContext, scope registry.DescriptorBatchScope, fingerprint [32]byte, r fabric.InvokeRequest, parent context.Context, source any) (Receipt, bool, *sourceCapture, error) {
	receipt, fresh, e := i.Reserve(ctx, caller, scope, fingerprint, r)
	if e != nil || !fresh {
		return receipt, fresh, nil, e
	}
	capture, e := i.newAcceptedSource(ctx, receipt, parent, source, r.Deadline)
	return receipt, true, capture, e
}

// Only reserveSource and the genuine SDK AssociationStore's immediately fresh
// admission call this helper. There is deliberately no exported mint API.
func (i *Invocations) newAcceptedSource(ctx context.Context, receipt Receipt, parent context.Context, source any, deadline *time.Time) (*sourceCapture, error) {
	if i == nil || ctx == nil || parent == nil || source == nil || !i.validOriginalReceipt(receipt) || receipt.Frames != 0 || receipt.Terminal || receipt.Replay != nil {
		return nil, denied()
	}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	if deadline != nil {
		var stop context.CancelFunc
		lifetime, stop = context.WithDeadline(lifetime, *deadline)
		previous := cancel
		cancel = func() { stop(); previous() }
	}
	stopParent := context.AfterFunc(parent, cancel)
	c := &sourceCapture{ledger: i, receipt: receipt, commitment: receiptSHA(receipt), source: source, ctx: lifetime, cancel: cancel, stopParent: stopParent}
	// Recheck actual signed retained admission, not only the copied signature.
	if e := c.withReceipt(lifetime, func(context.Context, *registry.AuthorityTx, Receipt, registry.AuthorityRecord) error { return nil }); e != nil {
		c.close()
		return nil, e
	}
	return c, nil
}
func (c *sourceCapture) close() {
	if c != nil && c.closed.CompareAndSwap(false, true) {
		c.stopParent()
		c.cancel()
		if c.releaseSource != nil {
			c.releaseSource()
		}
	}
}
func (c *sourceCapture) withReceipt(ctx context.Context, step func(context.Context, *registry.AuthorityTx, Receipt, registry.AuthorityRecord) error) error {
	if c == nil || c.closed.Load() || c.ctx.Err() != nil || ctx == nil || ctx.Err() != nil || step == nil || c.source == nil {
		return denied()
	}
	call, cancel := context.WithCancel(c.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	return c.ledger.with(call, registry.DescriptorBatchScope{}, func(ctx context.Context, tx *registry.AuthorityTx) error {
		if c.closed.Load() || c.ctx.Err() != nil {
			return denied()
		}
		if _, _, e := c.ledger.state(tx); e != nil {
			return e
		}
		var r Receipt
		row, e := c.ledger.decode(tx, "invocation/"+invocationKey(c.receipt.Facts.Principal, c.receipt.Facts.InvocationID), &r)
		if e != nil {
			return e
		}
		if !c.ledger.validOriginalReceipt(r) || receiptSHA(r) != c.commitment || r.Facts != c.receipt.Facts {
			return denied()
		}
		return step(ctx, tx, r, row)
	})
}
func (c *sourceCapture) append(f fabric.InvocationFrame) error {
	if c == nil {
		return denied()
	}
	return c.ledger.appendSourceFrame(c.ctx, fabric.ExecutionContext{}, c.receipt, f, c)
}

type sourceCaptureSlotKey struct{}
type sourceCaptureSlot struct {
	ledger        *Invocations
	parent        context.Context
	provider      any
	beginDrain    func() (func(), error)
	releaseSource func()
	capture       atomic.Pointer[sourceCapture]
}
