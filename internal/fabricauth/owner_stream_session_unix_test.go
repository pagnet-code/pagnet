//go:build linux || darwin

package fabricauth

import (
	"encoding/json"
	"testing"

	"context"
)

func TestOwnerStreamScopeRequiresFreshCallbackOnSameActualKernelConnection(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	session, e := a.BindOwner(t.Context(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	var scope *OwnerStreamSession
	var old *OwnerAdministration
	if e = session.WithOwnerAdministration(t.Context(), []byte(`{"read":"first"}`), func(ctx context.Context, access *OwnerAdministration) error {
		old = access
		var e error
		scope, e = access.StreamSession(ctx)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = scope.VerifyCurrent(t.Context(), old); e == nil {
		t.Fatal("expired callback authorized paging")
	}
	if _, e = json.Marshal(scope); e == nil {
		t.Fatal("private scope serialized")
	}
	done := scope.Done()
	select {
	case <-done:
		t.Fatal("live session signaled closed")
	default:
	}
	if e = session.WithOwnerAdministration(t.Context(), []byte(`{"read":"later"}`), func(ctx context.Context, access *OwnerAdministration) error { return scope.VerifyCurrent(ctx, access) }); e != nil {
		t.Fatal(e)
	}
	// Binding the same peer again does not transfer another connection's handle.
	other, e := a.BindOwner(t.Context(), conn)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = other.WithOwnerAdministration(t.Context(), []byte(`{"read":"other"}`), func(ctx context.Context, access *OwnerAdministration) error { return scope.VerifyCurrent(ctx, access) }); e == nil {
		t.Fatal("same principal's other session accepted")
	}
	session.Close()
	session.Close()
	select {
	case <-done:
	default:
		t.Fatal("actual session close did not signal")
	}
	if scope.Done() != done {
		t.Fatal("close notification identity changed")
	}
	if !scope.Revoked() {
		t.Fatal("actual close not observed")
	}
	if e = scope.VerifyCurrent(t.Context(), old); e == nil {
		t.Fatal("closed kernel session accepted")
	}
}
