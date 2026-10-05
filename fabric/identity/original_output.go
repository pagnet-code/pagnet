package identity

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// OriginalOutputCapture is nonserializable evidence minted only by successful
// FenceNativeIntent after an authenticated FULL worker acknowledgement. It is
// not current caller authority: it permits retaining that original output only.
type OriginalOutputCapture struct {
	authority *Authority
	source    Admission
	binding   Binding
	intent    NativeIntentCommitment
	receipt   NativeIntentReceipt
	plan      Witness
	deadline  time.Time
	claimed   atomic.Bool
}
type originalOutputContext struct {
	capture *OriginalOutputCapture
	active  atomic.Bool
}
type originalOutputContextKey struct{}

func (*OriginalOutputCapture) MarshalJSON() ([]byte, error) {
	return nil, invalid("Original capture cannot be serialized")
}
func (*OriginalOutputCapture) UnmarshalJSON([]byte) error {
	return invalid("Original capture cannot be decoded")
}
func newOriginalOutputCapture(a *Authority, s Admission, b Binding, i NativeIntentCommitment, r NativeIntentReceipt, w Witness) (*OriginalOutputCapture, error) {
	var owned struct {
		Source  Admission
		Binding Binding
		Intent  NativeIntentCommitment
		Receipt NativeIntentReceipt
	}
	raw, err := json.Marshal(struct {
		Source  Admission
		Binding Binding
		Intent  NativeIntentCommitment
		Receipt NativeIntentReceipt
	}{s, b, i, r})
	if err != nil || fabric.DecodeJSON(raw, &owned) != nil {
		return nil, invalid("Original capture source invalid")
	}
	var deadline time.Time
	if s.Deadline != "" {
		deadline, err = time.Parse(time.RFC3339Nano, s.Deadline)
		if err != nil {
			return nil, invalid("Original capture deadline invalid")
		}
	}
	return &OriginalOutputCapture{authority: a, source: owned.Source, binding: owned.Binding, intent: owned.Intent, receipt: owned.Receipt, plan: Witness{CurrentPlanVerifier: w.CurrentPlanVerifier}, deadline: deadline}, nil
}

// WithOutput owns one synchronous exact-source capture lifetime. It never
// renews the paid deadline or adds caller evidence to its callback context.
func (c *OriginalOutputCapture) WithOutput(ctx context.Context, next func(context.Context) error) error {
	if c == nil || c.authority == nil || ctx == nil || ctx.Err() != nil || next == nil {
		return invalid("Original capture unavailable")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour || !c.claimed.CompareAndSwap(false, true) {
		return invalid("Original capture must have one finite owned lifetime")
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	if !c.deadline.IsZero() {
		limited, stop := context.WithDeadline(call, c.deadline)
		defer stop()
		call = limited
	}
	p := &originalOutputContext{capture: c}
	p.active.Store(true)
	defer p.active.Store(false)
	return next(context.WithValue(call, originalOutputContextKey{}, p))
}
func (c *OriginalOutputCapture) active(ctx context.Context) bool {
	if c == nil || ctx == nil {
		return false
	}
	p, ok := ctx.Value(originalOutputContextKey{}).(*originalOutputContext)
	return ok && p != nil && p.capture == c && p.active.Load() && ctx.Err() == nil && (!c.deadline.IsZero() && time.Now().Before(c.deadline) || c.deadline.IsZero())
}

// VerifyOriginalOutputTx checks the same retained signed source and dispatch.
// A decoded receipt or signed reservation alone cannot mint this capability.
func (a *Authority) VerifyOriginalOutputTx(ctx context.Context, tx *registry.AuthorityTx, c *OriginalOutputCapture, r NativeDispatchReservation) error {
	if a == nil || tx == nil || c == nil || c.authority != a || !c.active(ctx) {
		return invalid("Missing original output capture")
	}

	if c.receipt.CommandID != r.CommandID || c.receipt.Sequence != r.Sequence || c.receipt.OperationDigest != r.Spec.OperationDigest || c.receipt.OriginalAdmissionID != c.source.ID || c.receipt.OwnershipGeneration != c.binding.Worker.OwnershipGeneration {
		return invalid("Original output receipt differs")
	}
	if err := VerifyNativeDispatchReservation(a.root, r, c.source, c.binding, r.Commitment()); err != nil {
		return err
	}
	if err := verifyCurrentPlanTx(tx, c.plan); err != nil {
		return err
	}
	if err := a.originalAdmission(tx, c.source); err != nil {
		return err
	}
	_, err := exactRecord(tx, a.root, r.Proof, dispatchKey(c.source.OriginalCaller, c.source.InvocationID))
	return err
}

// FenceOriginalNativeOutput admits only bounded original Page/ACK operations;
// external disclosure/cancellation retains its independent current-caller path.
func (a *Authority) FenceOriginalNativeOutput(ctx context.Context, owner fabric.ExecutionContext, current Controller, b Binding, c *OriginalOutputCapture, r NativeDispatchReservation, operation NativeSourceReadOperation, read func(context.Context) error) error {
	if ctx == nil || read == nil || c == nil || c.authority != a || !c.active(ctx) || (operation != NativeSourcePage && operation != NativeSourceAck) || current.Scope != b.Scope || c.binding.Worker != b.Worker || c.binding.Scope.Endpoint != b.Scope.Endpoint || c.binding.Scope.BindingID != b.Scope.BindingID {
		return invalid("Original output control differs")
	}
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return a.transact(lifetime, owner, current.Scope, false, func(tx *registry.AuthorityTx) error {
		if err := a.VerifyOriginalOutputTx(lifetime, tx, c, r); err != nil {
			return err
		}
		if err := a.currentController(tx, current); err != nil {
			return err
		}
		if err := a.currentBinding(tx, b); err != nil {
			return err
		}
		return read(lifetime)
	})
}

// OriginalBinding returns owned original metadata, never a current authorization.
func (c *OriginalOutputCapture) OriginalBinding() Binding {
	if c == nil {
		return Binding{}
	}
	var b Binding
	raw, _ := json.Marshal(c.binding)
	_ = fabric.DecodeJSON(raw, &b)
	return b
}

// ValidateOriginalOutput is a read-only source-proof fence for physical
// adoption. It cannot spawn or grant caller disclosure/new execution authority.
func (a *Authority) ValidateOriginalOutput(ctx context.Context, owner fabric.ExecutionContext, c *OriginalOutputCapture, r NativeDispatchReservation) error {
	if c == nil || c.authority != a || ctx == nil {
		return invalid("Original output capture missing")
	}
	return a.transact(ctx, owner, c.binding.Scope, true, func(tx *registry.AuthorityTx) error { return a.VerifyOriginalOutputTx(ctx, tx, c, r) })
}

// Active checks a callback-lived nonserializable capture context. It is never
// enough on its own: each source operation also consumes the signed TX fence.
func (c *OriginalOutputCapture) Active(ctx context.Context) bool {
	return c != nil && ctx != nil && c.active(ctx)
}
