package identity

import (
	"context"
	"testing"

	"github.com/pagnet-code/pagnet/fabric/registry"
)

func TestCurrentNativeStateUsesGenuineRetainedHeadAcrossTakeoverAndRestart(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a := f.controller(t, 0, "A")
	w := f.binding(t, a)
	c, b, err := f.a.CurrentNativeState(ctx, f.owner, f.scope)
	if err != nil || c.Epoch() != a.Epoch() || b.Proof.Revision != w.Proof.Revision || b.Worker != w.Worker {
		t.Fatal("current signed registry facts lost", err)
	}
	next := f.controller(t, a.Epoch(), "B")
	c, _, err = f.a.CurrentNativeState(ctx, f.owner, f.scope)
	if err != nil || c.Epoch() != next.Epoch() {
		t.Fatal("historical A appeared current", err)
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.CurrentNativeState(ctx, f.owner, f.scope); err == nil {
		t.Fatal("historical identity authenticated a closed current registry")
	}
	reopened, err := registry.Open(ctx, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	authority, err := New(reopened, f.fence)
	if err != nil {
		t.Fatal(err)
	}
	c, b, err = authority.CurrentNativeState(ctx, f.owner, f.scope)
	if err != nil || c.Epoch() != next.Epoch() || b.Worker != w.Worker {
		t.Fatal("restart replaced current controller or original physical binding", err)
	}
	changed := f.scope
	changed.BindingID = "caller-selected-alternative"
	if _, _, err = authority.CurrentNativeState(ctx, f.owner, changed); err == nil {
		t.Fatal("unknown binding substituted actual native ownership")
	}
}
