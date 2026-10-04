package identity

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestRestoreOriginalCallerRequiresActualRetainedProofAndExactBytesAcrossRestart(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	A := f.controller(t, 0, "A")
	binding := f.binding(t, A)
	caller, original, final := f.invocation(t)
	source, err := f.a.Admit(ctx, f.owner, A, binding, caller, original, final, "retained-source", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.RestoreOriginalCaller(ctx, f.owner, source, original, final); err == nil {
		t.Fatal("closed registry restored signature as authority")
	}
	store, err := registry.Open(ctx, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	a, err := New(store, f.fence)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := a.RestoreOriginalCaller(ctx, f.owner, source, original, final)
	if err != nil || restored.PrincipalView() != caller.PrincipalView() {
		t.Fatal("genuine restart lost original caller", err)
	}
	if _, err = restored.DecodeVerifiedEnvelope(original, store.Namespace()); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.DecodeVerifiedEnvelope(final, store.Namespace()); err == nil {
		t.Fatal("restored caller authenticated transformed bytes")
	}
	for _, change := range []string{"original", "final", "principal", "provenance", "signature", "unknown"} {
		t.Run(change, func(t *testing.T) {
			var altered Admission
			raw, _ := json.Marshal(source)
			_ = json.Unmarshal(raw, &altered)
			before, after := append([]byte(nil), original...), append([]byte(nil), final...)
			switch change {
			case "original":
				before = append(before, ' ')
			case "final":
				after = append(after, ' ')
			case "principal":
				altered.OriginalCaller.Issuer = "another"
			case "provenance":
				altered.Provenance.ExtensionChain = []string{"forged"}
			case "signature":
				altered.CallerSignature[0] ^= 1
			case "unknown":
				altered.ID = "another"
			}
			if _, err = a.RestoreOriginalCaller(ctx, f.owner, altered, before, after); err == nil {
				t.Fatal("forged source restored")
			}
		})
	}
}

func TestRestoreExpiredHistoricalSourceDoesNotAuthorizeNewEffect(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	A := f.controller(t, 0, "A")
	binding := f.binding(t, A)
	caller, original, final := f.invocation(t)
	var before, after fabric.Envelope
	_ = json.Unmarshal(original, &before)
	_ = json.Unmarshal(final, &after)
	deadline := time.Now().UTC().Add(time.Second)
	before.Context.Deadline = &deadline
	after.Context.Deadline = &deadline
	original, _ = json.Marshal(before)
	final, _ = json.Marshal(after)
	caller, err := fabric.NewAuthenticatedContext(caller.PrincipalView(), f.store.Namespace(), original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := f.a.Admit(ctx, f.owner, A, binding, caller, original, final, "expiring-source", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	// One short actual expiry checks history semantics without changing signed
	// timestamps/proofs or replacing the system clock with a fabricated source.
	timer := time.NewTimer(time.Until(deadline) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	restored, err := f.a.RestoreOriginalCaller(ctx, f.owner, source, original, final)
	if err != nil {
		t.Fatal("expiry erased authenticated history", err)
	}
	if _, err = f.a.Admit(ctx, f.owner, A, binding, restored, original, final, "new-source", "new-attempt", "new-replay"); err == nil {
		t.Fatal("historical restoration extended execution deadline")
	}
}
