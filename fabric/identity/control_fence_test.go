package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

type purposeFence struct {
	*ownerFence
	saved          func() error
	denyHistorical bool
}

func (f *purposeFence) WithNativeControl(_ context.Context, facts NativeControlFacts, commit func() error) error {
	if facts.Owner != f.owner || facts.Scope != facts.Binding.Scope || facts.Scope != facts.Controller.Scope {
		return invalid("control policy denied")
	}
	f.saved = commit
	return commit()
}
func (f *purposeFence) WithHistoricalNativeOrigin(_ context.Context, facts HistoricalNativeOriginFacts, commit func(Witness) error) error {
	if f.denyHistorical || facts.Current.Owner != f.owner || facts.Original.OriginalCaller != f.owner || facts.OriginalBinding.Worker != facts.Current.Binding.Worker {
		return invalid("historical policy denied")
	}
	return commit(Witness{Version: "explicit.historical.v1", FinalizedDigest: facts.Original.FinalizedDigest, Value: json.RawMessage(`{}`)})
}
func TestCurrentControlAndHistoricalOriginRenameRemainDistinct(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &purposeFence{ownerFence: f.fence}
	a, e := New(f.store, policy)
	if e != nil {
		t.Fatal(e)
	}
	f.a = a
	A := f.controller(t, 0, "A")
	bindingA := f.binding(t, A)
	caller, original, final := f.invocation(t)
	source, e := a.Admit(ctx, f.owner, A, bindingA, caller, original, final, "sourceA", "attempt", "replay")
	if e != nil {
		t.Fatal(e)
	}
	descriptor, e := f.store.GetEndpoint(ctx, f.scope.Endpoint, f.scope.DescriptorRevision)
	if e != nil {
		t.Fatal(e)
	}
	descriptor.Name = "Renamed"
	descriptor.Revision = ""
	rev, e := f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: f.scope.DescriptorRevision})
	if e != nil {
		t.Fatal(e)
	}
	f.scope.DescriptorRevision = rev
	B := f.controller(t, A.Epoch(), "B")
	bindingB, e := a.RenewWorkerBinding(ctx, f.owner, B, bindingA)
	if e != nil {
		t.Fatal(e)
	}
	callbacks := 0
	if e = a.FenceNativeControl(ctx, f.owner, B, bindingB, func(context.Context) error { callbacks++; return nil }); e != nil || callbacks != 1 {
		t.Fatal("current control", e)
	}
	if e = policy.saved(); e == nil || callbacks != 1 {
		t.Fatal("escaped callback remained live", e)
	}
	if e = a.FenceNativeControl(ctx, f.owner, A, bindingA, func(context.Context) error { callbacks++; return nil }); e == nil || callbacks != 1 {
		t.Fatal("stale controller callback", e)
	}
	if _, e = a.RegisterOrigin(ctx, f.owner, B, bindingB, source, caller, original, final, "fresh-invalid", "generation"); e == nil {
		t.Fatal("fresh origin silently substituted revision")
	}
	origin, e := a.RegisterHistoricalOrigin(ctx, f.owner, B, bindingB, bindingA, source, caller, original, final, "original-generation", "actual-gen-A")
	if e != nil {
		t.Fatal("explicit accepted-source continuation", e)
	}
	if origin.Scope != source.Scope || origin.Worker != bindingA.Worker || origin.OriginalControllerEpoch != A.Epoch() || origin.RegisteredControllerEpoch != B.Epoch() {
		t.Fatal("historical source rewritten")
	}
	again, e := a.RegisterHistoricalOrigin(ctx, f.owner, B, bindingB, bindingA, source, caller, original, final, "original-generation", "actual-gen-A")
	if e != nil || again.Proof.Sequence != origin.Proof.Sequence {
		t.Fatal("origin retry reminted", e)
	}
	changed := bindingA
	changed.Worker.WorkerID = "foreign"
	if _, e = a.RegisterHistoricalOrigin(ctx, f.owner, B, bindingB, changed, source, caller, original, final, "wrong", "actual-gen-A"); e == nil {
		t.Fatal("foreign physical binding accepted")
	}
	policy.denyHistorical = true
	if _, e = a.RegisterHistoricalOrigin(ctx, f.owner, B, bindingB, bindingA, source, caller, original, final, "denied", "actual-gen-denied"); e == nil {
		t.Fatal("current policy denial ignored")
	}
	plain, e := New(f.store, f.fence)
	if e != nil {
		t.Fatal(e)
	}
	if e = plain.FenceNativeControl(ctx, f.owner, B, bindingB, func(context.Context) error { t.Fatal("unsupported policy invoked control"); return nil }); e == nil {
		t.Fatal("unsupported fence accepted")
	}
	if _, e = plain.RegisterHistoricalOrigin(ctx, f.owner, B, bindingB, bindingA, source, caller, original, final, "unsupported", "actual-gen"); e == nil {
		t.Fatal("unsupported historical policy accepted")
	}
}
