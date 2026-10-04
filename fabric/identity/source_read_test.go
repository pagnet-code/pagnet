package identity

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"testing"
	"time"
)

type sourceReadFence struct {
	*ownerFence
	saved  func() error
	deny   bool
	ignore bool
	twice  bool
}

func (f *sourceReadFence) WithNativeSourceRead(_ context.Context, facts NativeSourceReadFacts, read func() error) error {
	if f.deny || facts.Owner != f.owner || facts.Caller != f.owner || facts.Admission.OriginalCaller != f.owner {
		return invalid("Current source disclosure denied")
	}
	// Extension facts must not alias any evidence subsequently checked by core.
	clear(facts.Admission.Proof.Value)
	clear(facts.Reservation.Proof.Signature)
	f.saved = read
	if f.ignore {
		_ = read()
		if f.twice {
			_ = read()
		}
		return nil
	}
	return read()
}
func TestNativeSourceReadCurrentPurposeAndImmutableHistoricalSource(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &sourceReadFence{ownerFence: f.fence}
	a, e := New(f.store, policy)
	if e != nil {
		t.Fatal(e)
	}
	f.a = a
	A := f.controller(t, 0, "A")
	old := f.binding(t, A)
	source, caller, original, final := dispatchAdmission(t, f, A, old, "read-history")
	reservation, e := a.ReserveNativeDispatch(ctx, f.owner, A, old, source, caller, original, final, dispatchSpec(old))
	if e != nil {
		t.Fatal(e)
	}
	d, e := f.store.GetEndpoint(ctx, f.scope.Endpoint, f.scope.DescriptorRevision)
	if e != nil {
		t.Fatal(e)
	}
	d.Name = "Renamed"
	d.Revision = ""
	rev, e := f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: f.scope.DescriptorRevision})
	if e != nil {
		t.Fatal(e)
	}
	f.scope.DescriptorRevision = rev
	B := f.controller(t, A.Epoch(), "B")
	current, e := a.RenewWorkerBinding(ctx, f.owner, B, old)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	read := func(context.Context) error { calls++; return nil }
	for _, op := range []NativeSourceReadOperation{NativeSourcePage, NativeSourceAck} {
		if e = a.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, reservation, op, read); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 {
		t.Fatal("Missing Page/ACK authorization")
	}
	if e = policy.saved(); e == nil || calls != 2 {
		t.Fatal("Escaped read callback was live")
	}
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, old, old, source, reservation, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Stale controller read")
	}
	foreign, _ := fabric.NewAuthenticatedContext(fabric.Principal{Ref: f.owner.PrincipalView().Ref, Kind: f.owner.PrincipalView().Kind, Issuer: "different"}, f.store.Namespace(), original)
	if e = a.FenceNativeSourceRead(ctx, f.owner, foreign, B, current, old, source, reservation, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Wrong issuer read")
	}
	changed := reservation
	changed.Sequence++
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, changed, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Another sequence read")
	}
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, reservation, "execute", read); e == nil || calls != 2 {
		t.Fatal("Invalid read purpose")
	}
	plain, _ := New(f.store, f.fence)
	if e = plain.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, reservation, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Missing configured policy accepted")
	}
	policy.deny = true
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, reservation, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Current policy revocation ignored")
	}
	policy.deny = false
	e = a.transact(ctx, f.owner, f.scope, false, func(tx *registry.AuthorityTx) error {
		_, err := tx.CAS(source.Proof.Key, source.Proof.Revision, source.Proof.Value, true)
		return err
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, B, current, old, source, reservation, NativeSourcePage, read); e == nil || calls != 2 {
		t.Fatal("Retired original source read")
	}
}

// Registry takeover must linearize AFTER the actual bounded authorized IPC read.
func TestNativeSourceReadLocksTakeoverThroughCallback(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &sourceReadFence{ownerFence: f.fence}
	a, _ := New(f.store, policy)
	f.a = a
	A := f.controller(t, 0, "A")
	b := f.binding(t, A)
	source, caller, original, final := dispatchAdmission(t, f, A, b, "linearized")
	reservation, e := a.ReserveNativeDispatch(ctx, f.owner, A, b, source, caller, original, final, dispatchSpec(b))
	if e != nil {
		t.Fatal(e)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- a.FenceNativeSourceRead(ctx, f.owner, caller, A, b, b, source, reservation, NativeSourcePage, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	takeover := make(chan error, 1)
	go func() {
		_, err := a.AcquireController(ctx, f.owner, f.scope, A.Epoch(), "B-lock", "B-lock")
		takeover <- err
	}()
	select {
	case e := <-takeover:
		t.Fatal("Takeover bypassed read fence", e)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = <-takeover; e != nil {
		t.Fatal(e)
	}
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, b, b, source, reservation, NativeSourcePage, func(context.Context) error { t.Fatal("Stale authority callback"); return nil }); e == nil {
		t.Fatal("Stale source access")
	}
}

func TestNativeSourceReadFenceCannotSwallowCallbackFailureOrReuse(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	policy := &sourceReadFence{ownerFence: f.fence, ignore: true}
	a, _ := New(f.store, policy)
	f.a = a
	A := f.controller(t, 0, "A")
	b := f.binding(t, A)
	source, caller, original, final := dispatchAdmission(t, f, A, b, "swallowed")
	reservation, e := a.ReserveNativeDispatch(ctx, f.owner, A, b, source, caller, original, final, dispatchSpec(b))
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, b, b, source, reservation, NativeSourceAck, func(context.Context) error { calls++; return invalid("Actual IPC ACK failed") }); e == nil || calls != 1 {
		t.Fatal("Ignored ACK failure reported success", e, calls)
	}
	policy.twice = true
	if e = a.FenceNativeSourceRead(ctx, f.owner, caller, A, b, b, source, reservation, NativeSourcePage, func(context.Context) error { calls++; return nil }); e == nil || calls != 2 {
		t.Fatal("Ignored callback reuse reported success", e, calls)
	}
}
