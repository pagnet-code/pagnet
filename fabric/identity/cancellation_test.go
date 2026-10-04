package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type cancellationFence struct {
	*ownerFence
	saved func() error
	deny  bool
}

func (f *cancellationFence) WithNativeCancellation(_ context.Context, facts NativeCancellationFacts, ack func() error) error {
	if f.deny || facts.Owner != f.owner || facts.Caller != f.owner {
		return invalid("Current cancellation denied")
	}
	clear(facts.Admission.Proof.Value)
	clear(facts.Reservation.Proof.Signature)
	f.saved = ack
	return ack()
}

func TestNativeCancellationKeepsExpiredOriginalReservationAcrossRename(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &cancellationFence{ownerFence: f.fence}
	a, err := New(f.store, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	A := f.controller(t, 0, "A")
	bindingA := f.binding(t, A)
	caller, original, final := f.invocation(t)
	var before, after fabric.Envelope
	_ = json.Unmarshal(original, &before)
	_ = json.Unmarshal(final, &after)
	deadline := time.Now().UTC().Add(2 * time.Second)
	before.Context.Deadline = &deadline
	after.Context.Deadline = &deadline
	original, _ = json.Marshal(before)
	final, _ = json.Marshal(after)
	caller, err = fabric.NewAuthenticatedContext(caller.PrincipalView(), f.store.Namespace(), original)
	if err != nil {
		t.Fatal(err)
	}
	source, err := a.Admit(ctx, f.owner, A, bindingA, caller, original, final, "cancel-original", "attempt", "replay")
	if err != nil {
		t.Fatal(err)
	}
	spec := NativeDispatchSpec{OperationDigest: sha256.Sum256([]byte("exact-operation")), SelectorDigest: sha256.Sum256([]byte("exact-selector")), SpecDigest: bindingA.Worker.ProfileDigest, MaxCommandsPerWorker: 16}
	reservation, err := a.ReserveNativeDispatch(ctx, f.owner, A, bindingA, source, caller, original, final, spec)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.store.GetEndpoint(ctx, f.scope.Endpoint, f.scope.DescriptorRevision)
	if err != nil {
		t.Fatal(err)
	}
	d.Name = "Renamed"
	d.Revision = ""
	rev, err := f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: f.scope.DescriptorRevision})
	if err != nil {
		t.Fatal(err)
	}
	f.scope.DescriptorRevision = rev
	B := f.controller(t, A.Epoch(), "B")
	bindingB, err := a.RenewWorkerBinding(ctx, f.owner, B, bindingA)
	if err != nil {
		t.Fatal(err)
	}
	<-time.After(time.Until(deadline) + time.Millisecond)
	acks := 0
	ack := func(context.Context) error { acks++; return nil }
	if err = a.FenceNativeCancellation(ctx, f.owner, caller, B, bindingB, bindingA, source, reservation, ack); err != nil || acks != 1 {
		t.Fatal("expired original could not be stopped under current authority", err)
	}
	if err = policy.saved(); err == nil || acks != 1 {
		t.Fatal("escaped cancellation callback remained active")
	}
	if source.Deadline != deadline.Format(time.RFC3339Nano) || reservation.Sequence != 1 || reservation.OriginalAdmissionID != source.ID {
		t.Fatal("cancellation changed original reservation")
	}
	if err = a.FenceNativeCancellation(ctx, f.owner, caller, A, bindingA, bindingA, source, reservation, ack); err == nil || acks != 1 {
		t.Fatal("old controller stopped current endpoint")
	}
	wrong := reservation
	wrong.Sequence++
	if err = a.FenceNativeCancellation(ctx, f.owner, caller, B, bindingB, bindingA, source, wrong, ack); err == nil || acks != 1 {
		t.Fatal("another source sequence stopped endpoint")
	}
	foreign, _ := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "spiffe://another", Kind: "local.owner", Issuer: "other"}, f.store.Namespace(), original)
	if err = a.FenceNativeCancellation(ctx, f.owner, foreign, B, bindingB, bindingA, source, reservation, ack); err == nil || acks != 1 {
		t.Fatal("current caller cancellation denial ignored")
	}
	policy.deny = true
	if err = a.FenceNativeCancellation(ctx, f.owner, caller, B, bindingB, bindingA, source, reservation, ack); err == nil || acks != 1 {
		t.Fatal("current authority cancellation denial ignored")
	}
	plain, _ := New(f.store, f.fence)
	if err = plain.FenceNativeCancellation(ctx, f.owner, caller, B, bindingB, bindingA, source, reservation, ack); err == nil || acks != 1 {
		t.Fatal("unsupported cancellation purpose admitted")
	}
	if _, err = a.Admit(ctx, f.owner, B, bindingB, caller, original, final, "new", "new", "new"); err == nil {
		t.Fatal("cancellation re-enabled expired invocation")
	}
}
