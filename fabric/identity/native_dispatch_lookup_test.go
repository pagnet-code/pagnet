package identity

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"testing"
)

func TestNativeDispatchLookupOriginalHistoryRestartAndNoAllocation(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	A := f.controller(t, 0, "A")
	binding := f.binding(t, A)
	source, caller, original, final := dispatchAdmission(t, f, A, binding, "lookup")
	if _, e := f.a.LookupNativeDispatch(ctx, f.owner, source, binding); !missingDispatchRecord(e) {
		t.Fatal("Missing reservation invented", e)
	}
	reservation, e := f.a.ReserveNativeDispatch(ctx, f.owner, A, binding, source, caller, original, final, dispatchSpec(binding))
	if e != nil {
		t.Fatal(e)
	}
	B := f.controller(t, A.Epoch(), "B")
	_ = B
	got, e := f.a.LookupNativeDispatch(ctx, f.owner, source, binding)
	if e != nil {
		t.Fatal(e)
	}
	one, _ := digest(reservation)
	two, _ := digest(got)
	if one != two {
		t.Fatal("Lookup remapped original A")
	}
	f.store.Close()
	store, e := registry.Open(ctx, f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	a, e := New(store, f.fence)
	if e != nil {
		t.Fatal(e)
	}
	got, e = a.LookupNativeDispatch(ctx, f.owner, source, binding)
	if e != nil {
		t.Fatal(e)
	}
	two, _ = digest(got)
	if one != two {
		t.Fatal("Restart changed reservation")
	}
	changed := source
	changed.OriginalCaller.Issuer = "foreign"
	if _, e = a.LookupNativeDispatch(ctx, f.owner, changed, binding); e == nil {
		t.Fatal("Foreign source assertion accepted")
	}
	changed = source
	changed.InvocationID = "different"
	if _, e = a.LookupNativeDispatch(ctx, f.owner, changed, binding); e == nil {
		t.Fatal("Foreign invocation accepted")
	}
	changedBinding := binding
	changedBinding.Worker.WorkerID = "other"
	if _, e = a.LookupNativeDispatch(ctx, f.owner, source, changedBinding); e == nil {
		t.Fatal("Foreign physical binding accepted")
	}
}
