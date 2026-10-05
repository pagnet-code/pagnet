package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

func dispatchSpec(b Binding) NativeDispatchSpec {
	return NativeDispatchSpec{OperationDigest: sha256.Sum256([]byte("exact binder operation")), SelectorDigest: sha256.Sum256([]byte("exact native selector")), SpecDigest: b.Worker.ProfileDigest, MaxCommandsPerWorker: 100}
}
func dispatchInvocation(t *testing.T, f nativeFixture, id string) (fabric.ExecutionContext, []byte, []byte) {
	t.Helper()
	_, original, final := f.invocation(t)
	var one, two fabric.Envelope
	if fabric.DecodeJSON(original, &one) != nil || fabric.DecodeJSON(final, &two) != nil {
		t.Fatal("decode")
	}
	one.ID = id
	two.ID = id
	original, _ = json.Marshal(one)
	final, _ = json.Marshal(two)
	caller, e := fabric.NewAuthenticatedContext(one.Principal, f.store.Namespace(), original)
	if e != nil {
		t.Fatal(e)
	}
	return caller, original, final
}
func dispatchAdmission(t *testing.T, f nativeFixture, c Controller, b Binding, id string) (Admission, fabric.ExecutionContext, []byte, []byte) {
	t.Helper()
	caller, original, final := dispatchInvocation(t, f, id)
	a, e := f.a.Admit(context.Background(), f.owner, c, b, caller, original, final, "source-"+id, "attempt-"+id, "replay-"+id)
	if e != nil {
		t.Fatal(e)
	}
	return a, caller, original, final
}
func TestNativeDispatchReservationRetainedAcrossRestartAndController(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "first")
	spec := dispatchSpec(b)
	first, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	if first.Sequence != 1 || first.CommandID == "" || VerifyNativeDispatchReservation(f.a.Identity(), first, source, b, first.Commitment()) != nil {
		t.Fatal("invalid genuine reservation", first)
	}
	again, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	one, _ := digest(first)
	two, _ := digest(again)
	if one != two {
		t.Fatal("retry remapped command")
	}
	current := f.controller(t, c.Epoch(), "B")
	if _, e = f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e == nil {
		t.Fatal("stale controller reused mapping")
	}
	again, e = f.a.ReserveNativeDispatch(ctx, f.owner, current, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	two, _ = digest(again)
	if one != two {
		t.Fatal("B reallocated A original")
	}
	f.store.Close()
	store, e := registry.Open(ctx, f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	authority, e := New(store, f.fence)
	if e != nil {
		t.Fatal(e)
	}
	again, e = authority.ReserveNativeDispatch(ctx, f.owner, current, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	two, _ = digest(again)
	if one != two {
		t.Fatal("restart reallocated original reservation")
	}
	f.store, f.a = store, authority
	nextSource, nextCaller, nextOriginal, nextFinal := dispatchAdmission(t, f, current, b, "next")
	next, e := authority.ReserveNativeDispatch(ctx, f.owner, current, b, nextSource, nextCaller, nextOriginal, nextFinal, spec)
	if e != nil || next.Sequence != 2 || next.CommandID == first.CommandID {
		t.Fatal("physical counter not retained", next, e)
	}
}
func TestNativeDispatchConcurrentSameOriginalOneMapping(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "shared")
	spec := dispatchSpec(b)
	var wg sync.WaitGroup
	results := make(chan NativeDispatchReservation, 16)
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.a.ReserveNativeDispatch(context.Background(), f.owner, c, b, source, caller, original, final, spec)
			if e != nil {
				failures <- e
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var wanted [32]byte
	count := 0
	for r := range results {
		hash, e := digest(r)
		if e != nil || r.Sequence != 1 {
			t.Fatal(r, e)
		}
		if count > 0 && hash != wanted {
			t.Fatal("concurrent mappings differ")
		}
		wanted = hash
		count++
	}
	if count != 16 {
		t.Fatal(count)
	}
	source, caller, original, final = dispatchAdmission(t, f, c, b, "second")
	next, e := f.a.ReserveNativeDispatch(context.Background(), f.owner, c, b, source, caller, original, final, spec)
	if e != nil || next.Sequence != 2 {
		t.Fatal("duplicate consumed ordinal", next, e)
	}
}
func TestNativeDispatchChangedSourceFinalOperationAndQuotaDenied(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "immutable")
	spec := dispatchSpec(b)
	first, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*NativeDispatchSpec){func(s *NativeDispatchSpec) { s.OperationDigest = sha256.Sum256([]byte("other")) }, func(s *NativeDispatchSpec) { s.SelectorDigest = sha256.Sum256([]byte("other")) }, func(s *NativeDispatchSpec) { s.MaxCommandsPerWorker++ }} {
		changed := spec
		mutate(&changed)
		if _, e = f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, changed); e == nil {
			t.Fatal("changed original command reserved")
		}
	}
	var changed fabric.Envelope
	fabric.DecodeJSON(final, &changed)
	changed.Payload = json.RawMessage(`{"text":"another operation"}`)
	changedFinal, _ := json.Marshal(changed)
	if _, e = f.a.Admit(ctx, f.owner, c, b, caller, original, changedFinal, "fresh-source-same-invocation", "fresh-attempt", "fresh-replay"); e == nil {
		t.Fatal("fresh source ID bypassed global invocation fence before paid mapping")
	}
	nextSource, nextCaller, nextOriginal, nextFinal := dispatchAdmission(t, f, c, b, "next")
	next, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, nextSource, nextCaller, nextOriginal, nextFinal, spec)
	if e != nil || next.Sequence != first.Sequence+1 {
		t.Fatal("rejection consumed physical ordinal", next, e)
	}
}
func TestNativeDispatchChangedTargetAndBindingNeverFreshMapping(t *testing.T) {
	for _, mode := range []string{"target", "binding"} {
		t.Run(mode, func(t *testing.T) {
			f := fixture(t)
			ctx := context.Background()
			c := f.controller(t, 0, "A")
			b := f.binding(t, c)
			source, caller, original, final := dispatchAdmission(t, f, c, b, "same-invocation")
			spec := dispatchSpec(b)
			if _, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e != nil {
				t.Fatal(e)
			}
			scope := f.scope
			descriptor, e := f.store.GetEndpoint(ctx, scope.Endpoint, scope.DescriptorRevision)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "target" {
				descriptor.Ref, _ = fabric.NewEndpointRef(f.store.AuthorityIdentity().PublicKey)
			} else {
				descriptor.Bindings = append(descriptor.Bindings, fabric.BindingSummary{ID: "other", Protocol: "local.native", Version: "1"})
			}
			expected := fabric.Revision("")
			if mode == "binding" {
				expected = scope.DescriptorRevision
			}
			descriptor.Revision = ""
			var rev fabric.Revision
			if mode == "binding" {
				rev, e = f.store.Update(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor, ExpectedRevision: expected})
			} else {
				rev, e = f.store.Register(ctx, f.owner, fabric.RegistryUpdate{Descriptor: descriptor})
			}
			if e != nil {
				t.Fatal(e)
			}
			scope.Endpoint = descriptor.Ref
			scope.DescriptorRevision = rev
			if mode == "binding" {
				scope.BindingID = "other"
			}
			replacement, e := f.a.AcquireController(ctx, f.owner, scope, 0, "other-controller", "controller-other")
			if e != nil {
				t.Fatal(e)
			}
			worker := b.Worker
			worker.WorkerID = "worker-other"
			worker.StateDirectoryID = "directory-other"
			otherBinding, e := f.a.BindWorker(ctx, f.owner, replacement, 0, worker)
			if e != nil {
				t.Fatal(e)
			}
			var envelope fabric.Envelope
			fabric.DecodeJSON(final, &envelope)
			envelope.Target = &scope.Endpoint
			envelope.ExpectedRevision = rev
			otherFinal, _ := json.Marshal(envelope)
			if _, e = f.a.Admit(ctx, f.owner, replacement, otherBinding, caller, original, otherFinal, "new-source", "new-attempt", "new-replay"); e == nil {
				t.Fatal("changed target/binding acquired second admission before paid mapping")
			}
		})
	}
}
func TestNativeDispatchRetiredSourceAndCapacityCanceledNoWrites(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "retired")
	spec := dispatchSpec(b)
	spec.MaxCommandsPerWorker = 1
	reserved, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.transact(ctx, f.owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		_, e := tx.CAS(admissionKey(c.Scope, source.ID), source.Proof.Revision, source.Proof.Value, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e == nil {
		t.Fatal("retired source returned executable reservation")
	}
	nextSource, nextCaller, nextOriginal, nextFinal := dispatchAdmission(t, f, c, b, "quota")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = f.a.ReserveNativeDispatch(canceled, f.owner, c, b, nextSource, nextCaller, nextOriginal, nextFinal, spec); e == nil {
		t.Fatal("canceled context reserved")
	}
	if _, e = f.a.ReserveNativeDispatch(ctx, f.owner, c, b, nextSource, nextCaller, nextOriginal, nextFinal, spec); e == nil {
		t.Fatal("capacity ignored")
	}
	// Both rejection paths left no second mapping and preserved original counter.
	if e = f.a.transact(ctx, f.owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		if _, e := tx.Get(dispatchKey(nextCaller.PrincipalView(), "quota")); !missingDispatchRecord(e) {
			t.Fatalf("failed reservation wrote mapping: %v", e)
		}
		record, e := tx.Get(dispatchCounterKey(b.Worker))
		if e != nil {
			return e
		}
		var counter nativeDispatchCounter
		if decodeValue(record, &counter) != nil || counter.LastSequence != reserved.Sequence {
			t.Fatal("failure advanced counter")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestNativeDispatchProofForgeryAndFullPrincipalKey(t *testing.T) {
	f := fixture(t)
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "proof")
	r, e := f.a.ReserveNativeDispatch(context.Background(), f.owner, c, b, source, caller, original, final, dispatchSpec(b))
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*NativeDispatchReservation){func(r *NativeDispatchReservation) { r.Sequence++ }, func(r *NativeDispatchReservation) { r.CommandID = "forged" }, func(r *NativeDispatchReservation) { r.Worker.OwnershipGeneration = "other" }, func(r *NativeDispatchReservation) { r.OriginalCaller.Issuer = "other" }, func(r *NativeDispatchReservation) { r.Spec.OperationDigest = sha256.Sum256([]byte("other")) }} {
		forged := r
		mutate(&forged)
		if VerifyNativeDispatchReservation(f.a.Identity(), forged, source, b, forged.Commitment()) == nil {
			t.Fatal("altered signed reservation accepted")
		}
	}
	root := f.a.Identity()
	root.StoreID = "other"
	if VerifyNativeDispatchReservation(root, r, source, b, r.Commitment()) == nil {
		t.Fatal("other root store accepted")
	}
	p := caller.PrincipalView()
	key := dispatchKey(p, "proof")
	p.Kind = "actor.other"
	if dispatchKey(p, "proof") == key {
		t.Fatal("kind omitted")
	}
	p = caller.PrincipalView()
	p.Issuer = "other"
	if dispatchKey(p, "proof") == key {
		t.Fatal("issuer omitted")
	}
}

func TestNativeDispatchRegistryCapacityRollsBackCounterAndMapping(t *testing.T) {
	ctx := context.Background()
	options := registry.DefaultOptions()
	options.Limits.MaxRecords = 5
	store, e := registry.BootstrapWithOptions(ctx, filepath.Join(t.TempDir(), "capacity-domain"), localOwner, options)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	owner, e := fabric.NewAuthenticatedContext(localOwner, store.Namespace(), []byte("actual owner setup"))
	if e != nil {
		t.Fatal(e)
	}
	ref, _ := fabric.NewEndpointRef(store.AuthorityIdentity().PublicKey)
	revision, e := store.Register(ctx, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "agent.local", Name: "Bounded", Description: "Bounded dispatch", Bindings: []fabric.BindingSummary{{ID: "native", Protocol: "local.native", Version: "1"}}}})
	if e != nil {
		t.Fatal(e)
	}
	fence := &ownerFence{owner: localOwner}
	authority, e := New(store, fence)
	if e != nil {
		t.Fatal(e)
	}
	f := nativeFixture{store: store, a: authority, owner: owner, scope: Scope{ref, revision, "native"}, fence: fence}
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "capacity")
	// Controller+receipt, binding and admission occupy four records. Counter is
	// fifth inside transaction; mapping hits finite capacity and must roll back.
	if r, e := authority.ReserveNativeDispatch(ctx, owner, c, b, source, caller, original, final, dispatchSpec(b)); e == nil || r.CommandID != "" {
		t.Fatal("capacity returned alleged committed reservation", r, e)
	}
	if e = authority.transact(ctx, owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		if _, e := tx.Get(dispatchCounterKey(b.Worker)); !missingDispatchRecord(e) {
			t.Fatal("capacity left counter mutation", e)
		}
		if _, e := tx.Get(dispatchKey(caller.PrincipalView(), "capacity")); !missingDispatchRecord(e) {
			t.Fatal("capacity left invocation mapping", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestNativeDispatchRetiredBindingAndDeniedPermissionCannotReuse(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	c := f.controller(t, 0, "A")
	b := f.binding(t, c)
	source, caller, original, final := dispatchAdmission(t, f, c, b, "binding-retired")
	spec := dispatchSpec(b)
	if _, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e != nil {
		t.Fatal(e)
	}
	f.fence.mu.Lock()
	f.fence.reject = true
	f.fence.mu.Unlock()
	if _, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e == nil {
		t.Fatal("revoked permission returned mapping")
	}
	f.fence.mu.Lock()
	f.fence.reject = false
	f.fence.mu.Unlock()
	if e := f.a.transact(ctx, f.owner, c.Scope, false, func(tx *registry.AuthorityTx) error {
		_, e := tx.CAS(bindingKey(c.Scope), b.Proof.Revision, b.Proof.Value, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.a.ReserveNativeDispatch(ctx, f.owner, c, b, source, caller, original, final, spec); e == nil {
		t.Fatal("retired binding returned executable mapping")
	}
}
