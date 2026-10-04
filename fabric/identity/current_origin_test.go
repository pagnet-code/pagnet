package identity

import (
	"context"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type currentOriginFence struct {
	*ownerFence
	saved func() error
	deny  bool
}

func (f *currentOriginFence) WithNativeControl(_ context.Context, facts NativeControlFacts, check func() error) error {
	if f.deny || facts.Owner != f.owner {
		return invalid("Current native peer denied")
	}
	// A configured callback owns copies, not the verifier's retained proofs.
	clear(facts.Binding.Proof.Value)
	clear(facts.Controller.Proof.Signature)
	f.saved = check
	return check()
}

func TestCurrentNativeOriginKeepsOriginalGenerationAcrossRenameAndRejectsRetirement(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &currentOriginFence{ownerFence: f.fence}
	authority, err := New(f.store, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.a = authority
	A := f.controller(t, 0, "A")
	bindingA := f.binding(t, A)
	caller, original, final := f.invocation(t)
	source, err := f.a.Admit(ctx, f.owner, A, bindingA, caller, original, final, "source", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := f.a.RegisterOrigin(ctx, f.owner, A, bindingA, source, caller, original, final, "origin", "genuine-generation")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.VerifyCurrentNativeOrigin(ctx, f.owner, f.scope, origin); err != nil {
		t.Fatal(err)
	}
	checks := 0
	if err = f.a.FenceCurrentNativeOrigin(ctx, f.owner, f.scope, origin, func(context.Context) error { checks++; return nil }); err != nil || checks != 1 {
		t.Fatal("current authorization failed", err)
	}
	if err = policy.saved(); err == nil || checks != 1 {
		t.Fatal("escaped callback remained authorized")
	}
	policy.deny = true
	if err = f.a.FenceCurrentNativeOrigin(ctx, f.owner, f.scope, origin, func(context.Context) error { checks++; return nil }); err == nil || checks != 1 {
		t.Fatal("configured authority denial ignored")
	}
	policy.deny = false
	plain, _ := New(f.store, f.fence)
	if err = plain.FenceCurrentNativeOrigin(ctx, f.owner, f.scope, origin, func(context.Context) error { checks++; return nil }); err == nil || checks != 1 {
		t.Fatal("unsupported authority silently accepted")
	}
	descriptor, err := f.store.GetEndpoint(ctx, f.scope.Endpoint, f.scope.DescriptorRevision)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Name = "Renamed"
	descriptor.Revision = ""
	revision, err := f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: f.scope.DescriptorRevision})
	if err != nil {
		t.Fatal(err)
	}
	oldScope := f.scope
	f.scope.DescriptorRevision = revision
	B := f.controller(t, A.Epoch(), "B")
	bindingB, err := f.a.RenewWorkerBinding(ctx, f.owner, B, bindingA)
	if err != nil {
		t.Fatal(err)
	}
	c, b, err := f.a.VerifyCurrentNativeOrigin(ctx, f.owner, f.scope, origin)
	if err != nil || c.Epoch() != B.Epoch() || b.Proof.Revision != bindingB.Proof.Revision || origin.Scope != oldScope {
		t.Fatal("current authority overwrote original provenance", err)
	}
	if _, _, err = f.a.VerifyCurrentNativeOrigin(ctx, f.owner, oldScope, origin); err == nil {
		t.Fatal("old descriptor authenticated as current")
	}
	for _, modify := range []func(*Origin){func(o *Origin) { o.NativeGeneration = "forged" }, func(o *Origin) { o.Worker.WorkerID = "another" }, func(o *Origin) { o.AdmissionID = "another" }} {
		changed := origin
		modify(&changed)
		if _, _, err = f.a.VerifyCurrentNativeOrigin(ctx, f.owner, f.scope, changed); err == nil {
			t.Fatal("altered source accepted")
		}
	}
	if _, err = f.a.RetireOrigin(ctx, f.owner, origin, "original-process-joined"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.VerifyCurrentNativeOrigin(ctx, f.owner, f.scope, origin); err == nil {
		t.Fatal("retired signed origin admitted")
	}
	if err = f.a.FenceCurrentNativeOrigin(ctx, f.owner, f.scope, origin, func(context.Context) error { checks++; return nil }); err == nil || checks != 1 {
		t.Fatal("retired origin reached native check")
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.VerifyCurrentNativeOrigin(ctx, f.owner, f.scope, origin); err == nil {
		t.Fatal("closed store admitted historical signature")
	}
}
