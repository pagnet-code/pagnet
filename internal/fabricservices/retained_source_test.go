package fabricservices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// Trusted control-policy fixture; never installed as product authorization.
type retainedPolicyFixture struct{ *aliasPolicyFixture }

func (p *retainedPolicyFixture) WithRetainedSourceRequest(ctx context.Context, c fabric.ExecutionContext, principal fabric.Principal, id, action string, next func(context.Context) error) error {
	if p.denied.Load() || c.PrincipalView() != principal {
		return denied()
	}
	switch p.mode {
	case "none":
		return nil
	case "swallow":
		_ = next(ctx)
		return nil
	case "repeat":
		_ = next(ctx)
		return next(ctx)
	case "late":
		p.escaped = next
		return nil
	}
	return next(ctx)
}
func (p *retainedPolicyFixture) AuthorizeRetainedSourceTx(ctx context.Context, tx *registry.AuthorityTx, c fabric.ExecutionContext, r Receipt, action string) error {
	if p.denied.Load() || c.PrincipalView() != r.Facts.Principal {
		return denied()
	}
	return nil
}
func TestRetainedServiceSourceExactRestartDetachAndCurrentDenial(t *testing.T) {
	p, i, base, scope, fp, dir := aliasSetup(t, DefaultInvocationConfig())
	caller, err := p.owner(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	policy := &retainedPolicyFixture{base}
	i.policy = policy
	var effects atomic.Int32
	result, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "original"), &effects, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	frames := aliasDrain(t, result)
	source, e := i.RetainOriginal(t.Context(), caller, p.root.Owner, "original")
	if e != nil {
		t.Fatal(e)
	}
	ref := source.Reference()
	source.Close()
	if _, e = source.Frame(t.Context(), caller, 0); e == nil {
		t.Fatal("closed delivery read")
	}
	if e = p.store.Close(); e != nil {
		t.Fatal(e)
	}
	root, e := registry.Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	reopenedProfiles, e := NewProfileStore(t.Context(), root, p.owner, p.protector)
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenInvocations(t.Context(), reopenedProfiles, DefaultInvocationConfig(), policy)
	if e != nil {
		t.Fatal(e)
	}
	source, e = reopened.OpenRetainedSource(t.Context(), caller, ref)
	if e != nil {
		t.Fatal(e)
	}
	for n, want := range frames {
		got, e := source.Frame(t.Context(), caller, uint64(n))
		if e != nil {
			t.Fatal(e)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			t.Fatal("original frame changed")
		}
		d := sha256.Sum256(a)
		if e = source.VerifyFrame(t.Context(), caller, uint64(n), d); e != nil {
			t.Fatal(e)
		}
		if e = reopened.with(t.Context(), registry.DescriptorBatchScope{}, func(ctx context.Context, tx *registry.AuthorityTx) error {
			return source.VerifyFrameTx(ctx, tx, caller, uint64(n), d)
		}); e != nil {
			t.Fatal("same-TX genuine ACK validation", e)
		}
		d[0] ^= 1
		if e = source.VerifyFrame(t.Context(), caller, uint64(n), d); e == nil {
			t.Fatal("forged frame digest")
		}
	}
	bad := ref
	bad.ReceiptSHA[0] ^= 1
	if _, e = reopened.OpenRetainedSource(t.Context(), caller, bad); e == nil {
		t.Fatal("forged source")
	}
	policy.denied.Store(true)
	if _, e = source.Frame(t.Context(), caller, 0); e == nil {
		t.Fatal("stale current permission")
	}
	if effects.Load() != 1 {
		t.Fatal("source read resent original")
	}
}
func TestRetainedServiceSourcePolicyCallbackMisuseAndUnknown(t *testing.T) {
	p, i, base, scope, fp, _ := aliasSetup(t, DefaultInvocationConfig())
	caller, err := p.owner(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	policy := &retainedPolicyFixture{base}
	i.policy = policy
	var effects atomic.Int32
	if _, e := aliasExecute(t.Context(), p, i, fp, scope, aliasRequest(scope, "unknown"), &effects, true, nil); e == nil {
		t.Fatal("fixture must expose unknown")
	}
	s, e := i.RetainOriginal(t.Context(), caller, p.root.Owner, "unknown")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Frame(t.Context(), caller, 0); e == nil {
		t.Fatal("unavailable source fabricated frame")
	}
	for _, mode := range []string{"none", "repeat", "late", "swallow"} {
		policy.mode = mode
		id := "unknown"
		if mode == "swallow" {
			id = "missing"
		}
		if _, e = i.RetainOriginal(t.Context(), caller, p.root.Owner, id); e == nil {
			t.Fatal("policy misuse accepted", mode)
		}
		if mode == "late" && policy.escaped(t.Context()) == nil {
			t.Fatal("escaped callback accepted")
		}
	}
	if effects.Load() != 1 {
		t.Fatal("unknown source resend")
	}
}
