package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type configuredPlanFence struct {
	original AdmissionFence
	verify   func(*registry.AuthorityTx) error
}

func (f configuredPlanFence) WithAdmission(ctx context.Context, facts AdmissionFacts, next func(Witness) error) error {
	return f.original.WithAdmission(ctx, facts, func(w Witness) error { w.CurrentPlanVerifier = f.verify; return next(w) })
}
func TestCurrentPlanWitnessConsumesSameRootBeforeEveryNativeEffectBoundary(t *testing.T) {
	wantStale := func(err error) {
		t.Helper()
		var e *fabric.Error
		if !errors.As(err, &e) || e.Code != fabric.CodeStaleContinuation {
			t.Fatal("did not reach actual configured-plan fence", err)
		}
	}
	f := fixture(t)
	key := registry.AuthorityKey{Kind: registry.AuthorityExtensionConfiguration, ID: "configured-plan"}
	var generation registry.AuthorityRecord
	if err := f.store.WithNativeAuthority(t.Context(), f.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		if _, err := tx.CAS(key, 0, []byte(`{"plan":1}`), false); err != nil {
			return err
		}
		var err error
		generation, err = tx.ExtensionPurposeGeneration()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	verifier := func(tx *registry.AuthorityTx) error {
		g, err := tx.ExtensionPurposeGeneration()
		if err != nil {
			return err
		}
		if g.Revision != generation.Revision || g.Sequence != generation.Sequence {
			return fabric.NewError(fabric.CodeStaleContinuation, "Configured plan changed")
		}
		return nil
	}
	a, err := New(f.store, configuredPlanFence{f.fence, verifier})
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	caller, original, final := f.invocation(t)
	source, err := a.Admit(t.Context(), f.owner, c, b, caller, original, final, "source-plan", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.WithNativeAuthority(t.Context(), f.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error { _, e := tx.CAS(key, 1, []byte(`{"plan":2}`), false); return e }); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Admit(t.Context(), f.owner, c, b, caller, original, final, "source-new-plan", "attempt-new", "replay-new"); err == nil {
		t.Fatal("changed plan admitted paid source")
	} else {
		wantStale(err)
	}
	spec := dispatchSpec(b)
	if _, err = a.ReserveNativeDispatch(t.Context(), f.owner, c, b, source, caller, original, final, spec); err == nil {
		t.Fatal("changed plan reserved native effect")
	} else {
		wantStale(err)
	}
	intent := NativeIntentCommitment{CommandID: "exact-retained", Sequence: 1, OperationDigest: spec.OperationDigest, SelectorDigest: spec.SelectorDigest, SpecDigest: spec.SpecDigest}
	paid := false
	if _, err = a.FenceNativeIntent(t.Context(), f.owner, c, b, source, caller, original, final, intent, func(context.Context) (NativeIntentReceipt, error) { paid = true; return NativeIntentReceipt{}, nil }); err == nil || paid {
		t.Fatal("changed plan reached durable native ACK", err)
	} else {
		wantStale(err)
	}
	if _, err = a.RegisterOrigin(t.Context(), f.owner, c, b, source, caller, original, final, "original-native", "native-generation"); err == nil {
		t.Fatal("changed plan registered new paid origin")
	} else {
		wantStale(err)
	}
}
