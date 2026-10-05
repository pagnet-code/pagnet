package identity

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"testing"
)

type exactSourceWitnessFence struct {
	*ownerFence
	expected                             Admission
	readCalls, cancelCalls, genericCalls int
}

func (f *exactSourceWitnessFence) CurrentNativeCallerWitness(context.Context, fabric.ExecutionContext) (Witness, error) {
	f.genericCalls++
	return Witness{}, invalid("Generic source-less witness denied")
}
func (f *exactSourceWitnessFence) CurrentNativeSourceCallerWitness(_ context.Context, c fabric.ExecutionContext, x NativeSourceReadFacts) (Witness, error) {
	f.readCalls++
	if x.Admission.ID != f.expected.ID || x.Admission.Target != f.expected.Target || x.Admission.TargetRevision != f.expected.TargetRevision || x.Admission.InvocationID != f.expected.InvocationID || x.CurrentCaller.PrincipalView() != c.PrincipalView() {
		return Witness{}, invalid("Wrong source selection")
	}
	return f.witness(c), nil
}
func (f *exactSourceWitnessFence) CurrentNativeCancellationCallerWitness(_ context.Context, c fabric.ExecutionContext, x NativeCancellationFacts) (Witness, error) {
	f.cancelCalls++
	if x.Admission.ID != f.expected.ID || x.Admission.Target != f.expected.Target || x.Admission.TargetRevision != f.expected.TargetRevision || x.Admission.InvocationID != f.expected.InvocationID || x.CurrentCaller.PrincipalView() != c.PrincipalView() {
		return Witness{}, invalid("Wrong cancellation selection")
	}
	return f.witness(c), nil
}
func (f *exactSourceWitnessFence) witness(c fabric.ExecutionContext) Witness {
	return Witness{CurrentCallerKind: "local-peer.owner", CurrentCallerOpen: func() bool { return true }, CurrentPlanVerifier: func(tx *registry.AuthorityTx) error { return nil }}
}
func (f *exactSourceWitnessFence) WithNativeSourceRead(_ context.Context, _ NativeSourceReadFacts, next func() error) error {
	return next()
}
func (f *exactSourceWitnessFence) WithNativeCancellation(_ context.Context, _ NativeCancellationFacts, next func() error) error {
	return next()
}
func TestOriginalSourceWitnessSelectionAfterReservationValidation(t *testing.T) {
	f := fixture(t)
	policy := &exactSourceWitnessFence{ownerFence: f.fence}
	a, e := New(f.store, policy)
	if e != nil {
		t.Fatal(e)
	}
	f.a = a
	ctx := t.Context()
	A := f.controller(t, 0, "source-witness")
	binding := f.binding(t, A)
	source, caller, original, final := dispatchAdmission(t, f, A, binding, "source-witness")
	reservation, e := a.ReserveNativeDispatch(ctx, f.owner, A, binding, source, caller, original, final, dispatchSpec(binding))
	if e != nil {
		t.Fatal(e)
	}
	policy.expected = source
	calls := 0
	run := func(context.Context) error { calls++; return nil }
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, binding, binding, source, reservation, NativeSourcePage, run); e != nil {
		t.Fatal(e)
	}
	if e = a.FenceNativeCancellation(ctx, f.owner, caller, A, binding, binding, source, reservation, run); e != nil {
		t.Fatal(e)
	}
	if calls != 2 || policy.readCalls != 1 || policy.cancelCalls != 1 || policy.genericCalls != 0 {
		t.Fatal("source-aware gate bypass", calls, policy)
	}
	changed := reservation
	changed.CommandID = "altered"
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, binding, binding, source, changed, NativeSourcePage, run); e == nil {
		t.Fatal("forged original source passed")
	}
	if e = a.FenceNativeCancellation(ctx, f.owner, caller, A, binding, binding, source, changed, run); e == nil {
		t.Fatal("forged cancellation passed")
	}
	if policy.readCalls != 1 || policy.cancelCalls != 1 || calls != 2 {
		t.Fatal("provider called before original reservation verified")
	}
}
