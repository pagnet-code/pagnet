package fabricservices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// RetainedSourcePolicy is a SEPARATE current control/history authenticator.
// No original node invocation context, stored receipt or static principal can
// substitute for its purpose-specific current request evidence. All transaction
// checks are bounded local checks without provider IO or nested Store calls.
type RetainedSourcePolicy interface {
	WithRetainedSourceRequest(context.Context, fabric.ExecutionContext, fabric.Principal, string, string, func(context.Context) error) error
	AuthorizeRetainedSourceTx(context.Context, *registry.AuthorityTx, fabric.ExecutionContext, Receipt, string) error
}

// SourceReference is private encrypted association metadata. Its receipt digest
// commits immutable actual paid admission; growing frame count is independent.
type SourceReference struct {
	Version      int              `json:"version"`
	Principal    fabric.Principal `json:"principal"`
	InvocationID string           `json:"invocationId"`
	ReceiptSHA   [32]byte         `json:"receiptSha"`
}

func serviceReference(r Receipt) SourceReference {
	return SourceReference{1, r.Facts.Principal, r.Facts.InvocationID, receiptSHA(r)}
}
func (r SourceReference) valid() bool {
	return r.Version == 1 && validText(r.Principal.Ref, 4096) && validText(r.Principal.Issuer, 4096) && fabric.ValidNamespacedName(r.Principal.Kind) && validText(r.InvocationID, 256) && r.ReceiptSHA != ([32]byte{})
}

// RetainedSource owns no SDK session/execution. Closing detaches only this
// caller's history delivery; it cannot replay or cancel the original effect.
type RetainedSource struct {
	ledger    *Invocations
	reference SourceReference
	closed    atomic.Bool
}

func (s *RetainedSource) Reference() SourceReference {
	if s == nil {
		return SourceReference{}
	}
	return s.reference
}
func (s *RetainedSource) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	return nil
}

func (i *Invocations) withRetainedSource(ctx context.Context, caller fabric.ExecutionContext, principal fabric.Principal, invocation, action string, step func(context.Context, *registry.AuthorityTx, Receipt) error) error {
	if i == nil || ctx == nil || ctx.Err() != nil || step == nil || caller.VerifyAuthenticated(i.profiles.root.Namespace) != nil || !validText(principal.Ref, 4096) || !validText(principal.Issuer, 4096) || !fabric.ValidNamespacedName(principal.Kind) || !validText(invocation, 256) {
		return denied()
	}
	if action != "source_inspect" && action != "source_frame" && action != "source_verify" {
		return denied()
	}
	policy, ok := i.policy.(RetainedSourcePolicy)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Current retained-service source policy is unavailable")
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	active, called, misused := true, false, false
	var failure error
	err := policy.WithRetainedSourceRequest(life, caller, principal, invocation, action, func(current context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called || current == nil || current.Err() != nil || life.Err() != nil {
			misused = true
			return denied()
		}
		called = true
		failure = i.with(current, registry.DescriptorBatchScope{}, func(current context.Context, tx *registry.AuthorityTx) error {
			if _, _, e := i.state(tx); e != nil {
				return e
			}
			var receipt Receipt
			if _, e := i.decode(tx, "invocation/"+invocationKey(principal, invocation), &receipt); e != nil {
				return e
			}
			if receipt.Facts.Principal != principal || receipt.Facts.InvocationID != invocation || !i.validOriginalReceipt(receipt) {
				return denied()
			}
			// Do not expose a borrowed mutable signed receipt to trusted policy: a
			// callback cannot silently alter the exact source selected afterward.
			raw, e := json.Marshal(receipt)
			if e != nil {
				return e
			}
			var owned Receipt
			if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil {
				return denied()
			}
			if e = policy.AuthorizeRetainedSourceTx(current, tx, caller, owned, action); e != nil {
				return e
			}
			return step(current, tx, receipt)
		})
		return failure
	})
	mu.Lock()
	active = false
	valid := called && !misused
	captured := failure
	mu.Unlock()
	if captured != nil {
		return captured
	}
	if !valid {
		return denied()
	}
	return err
}
func (i *Invocations) RetainOriginal(ctx context.Context, caller fabric.ExecutionContext, principal fabric.Principal, invocation string) (*RetainedSource, error) {
	var ref SourceReference
	err := i.withRetainedSource(ctx, caller, principal, invocation, "source_inspect", func(_ context.Context, _ *registry.AuthorityTx, r Receipt) error {
		ref = serviceReference(r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &RetainedSource{ledger: i, reference: ref}, nil
}
func (i *Invocations) OpenRetainedSource(ctx context.Context, caller fabric.ExecutionContext, ref SourceReference) (*RetainedSource, error) {
	if !ref.valid() {
		return nil, denied()
	}
	source, err := i.RetainOriginal(ctx, caller, ref.Principal, ref.InvocationID)
	if err != nil {
		return nil, err
	}
	if source.reference != ref {
		source.Close()
		return nil, denied()
	}
	return source, nil
}

// Frame loads exactly one FULL-retained original frame in the current source
// authorization transaction. Missing/nonterminal history is unavailable, never
// EOF/completion and never permission to repeat a tools/call.
func (s *RetainedSource) Frame(ctx context.Context, caller fabric.ExecutionContext, ordinal uint64) (fabric.InvocationFrame, error) {
	if s == nil || s.closed.Load() {
		return fabric.InvocationFrame{}, denied()
	}
	var frame fabric.InvocationFrame
	err := s.ledger.withRetainedSource(ctx, caller, s.reference.Principal, s.reference.InvocationID, "source_frame", func(_ context.Context, tx *registry.AuthorityTx, r Receipt) error {
		if serviceReference(r) != s.reference {
			return denied()
		}
		var e error
		frame, e = s.ledger.frameTx(tx, r, ordinal)
		return e
	})
	return frame, err
}

// VerifyFrame validates the genuine original frame digest without altering the
// provider or pruning service history. Federation owns durable consumer ACK.
func (s *RetainedSource) VerifyFrame(ctx context.Context, caller fabric.ExecutionContext, ordinal uint64, digest [32]byte) error {
	if s == nil || s.closed.Load() || digest == ([32]byte{}) {
		return denied()
	}
	return s.ledger.withRetainedSource(ctx, caller, s.reference.Principal, s.reference.InvocationID, "source_verify", func(_ context.Context, tx *registry.AuthorityTx, r Receipt) error {
		if serviceReference(r) != s.reference {
			return denied()
		}
		frame, e := s.ledger.frameTx(tx, r, ordinal)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(frame)
		if e != nil || sha256.Sum256(raw) != digest {
			return denied()
		}
		return nil
	})
}

// VerifyFrameTx is the SAME-root transaction form for durable federation ACK.
// The caller must first obtain purpose-specific current control evidence outside
// SQL. This method consumes that evidence through the mandatory source policy
// in the supplied transaction; it never opens a Store or calls a provider.
func (s *RetainedSource) VerifyFrameTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext, ordinal uint64, digest [32]byte) error {
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || tx == nil || digest == ([32]byte{}) || caller.VerifyAuthenticated(s.ledger.profiles.root.Namespace) != nil {
		return denied()
	}
	policy, ok := s.ledger.policy.(RetainedSourcePolicy)
	if !ok {
		return denied()
	}
	if _, _, e := s.ledger.state(tx); e != nil {
		return e
	}
	var r Receipt
	if _, e := s.ledger.decode(tx, "invocation/"+invocationKey(s.reference.Principal, s.reference.InvocationID), &r); e != nil {
		return e
	}
	if !s.ledger.validOriginalReceipt(r) || serviceReference(r) != s.reference {
		return denied()
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	var owned Receipt
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 32, MaxMembers: 2048}) != nil {
		return denied()
	}
	if e = policy.AuthorizeRetainedSourceTx(ctx, tx, caller, owned, "source_verify"); e != nil {
		return e
	}
	frame, e := s.ledger.frameTx(tx, r, ordinal)
	if e != nil {
		return e
	}
	raw, e = json.Marshal(frame)
	if e != nil || sha256.Sum256(raw) != digest {
		return denied()
	}
	return nil
}

// VerifyReferenceTx verifies the immutable original source relation under the
// independently current disclosure policy. It returns no raw SDK frame.
func (s *RetainedSource) VerifyReferenceTx(ctx context.Context, tx *registry.AuthorityTx, caller fabric.ExecutionContext) error {
	if s == nil || s.closed.Load() || tx == nil || caller.VerifyAuthenticated(s.ledger.profiles.root.Namespace) != nil {
		return denied()
	}
	var r Receipt
	if _, e := s.ledger.decode(tx, "invocation/"+invocationKey(s.reference.Principal, s.reference.InvocationID), &r); e != nil {
		return e
	}
	if !s.ledger.validOriginalReceipt(r) || serviceReference(r) != s.reference {
		return denied()
	}
	policy, ok := s.ledger.policy.(RetainedSourcePolicy)
	if !ok {
		return fabric.NewError(fabric.CodeUnsupported, "Current retained-service source policy unavailable")
	}
	return policy.AuthorizeRetainedSourceTx(ctx, tx, caller, r, "source_verify")
}
