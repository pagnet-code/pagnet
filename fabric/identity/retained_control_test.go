package identity

import (
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestRetainedNativeControlPreservesPartialTakeoverAcrossRegistryRestart(t *testing.T) {
	f := fixture(t)
	A := f.controller(t, 0, "A")
	original := f.binding(t, A)
	endpoint, err := f.store.GetEndpoint(t.Context(), f.scope.Endpoint, f.scope.DescriptorRevision)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Name = "Renamed endpoint"
	endpoint.Revision = ""
	revision, err := f.store.Update(t.Context(), f.owner, fabric.RegistryUpdate{Descriptor: endpoint, ExpectedRevision: f.scope.DescriptorRevision})
	if err != nil {
		t.Fatal(err)
	}
	selected := f.scope
	selected.DescriptorRevision = revision
	if _, _, err = f.a.CurrentNativeState(t.Context(), f.owner, selected); err == nil {
		t.Fatal("old scope authorized new descriptor")
	}
	retained, binding, err := f.a.RetainedNativeControl(t.Context(), f.owner, selected)
	if err != nil || retained.Scope != A.Scope || binding.Scope != original.Scope || binding.Worker != original.Worker {
		t.Fatal("retained state was reconstructed", err)
	}
	B, err := f.a.AcquireController(t.Context(), f.owner, selected, A.Proof.Revision, "B", "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	// Crash between the controller CAS and physical binding renewal.
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := registry.Open(t.Context(), f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := New(store, f.fence)
	if err != nil {
		t.Fatal(err)
	}
	retained, binding, err = authority.RetainedNativeControl(t.Context(), f.owner, selected)
	if err != nil || retained.Proof.Revision != B.Proof.Revision || retained.Scope != selected || binding.Scope != original.Scope || binding.Worker != original.Worker {
		t.Fatal("partial takeover lost original binding", err)
	}
	if _, _, err = authority.CurrentNativeState(t.Context(), f.owner, selected); err == nil {
		t.Fatal("partially renewed binding authorized new work")
	}
	renewed, err := authority.RenewWorkerBinding(t.Context(), f.owner, retained, binding)
	if err != nil || renewed.Worker != original.Worker {
		t.Fatal("renewal replaced physical worker", err)
	}
	if _, _, err = authority.CurrentNativeState(t.Context(), f.owner, selected); err != nil {
		t.Fatal(err)
	}
}
