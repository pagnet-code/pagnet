//go:build linux || darwin

package fabricauth

import (
	"context"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestOwnerResumerRetainedPagesRevocationAndPaidDenial(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	s, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var current fabric.ExecutionContext
	var release func()
	exact := []byte(`{"version":1,"operation":"continuation.resume"}`)
	err = s.WithOwnerAdministration(t.Context(), exact, func(ctx context.Context, admin *OwnerAdministration) error {
		return admin.WithResumerContext(ctx, func(ctx context.Context, c fabric.ExecutionContext) error {
			current = c
			if a.WithCurrentCaller(ctx, c, exact, func(context.Context) error { t.Fatal("paid control promotion"); return nil }) == nil {
				t.Fatal("control accepted as paid caller")
			}
			var e error
			release, e = a.RetainOwnerResumer(ctx, c)
			return e
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for range 2 {
		if err = a.WithCurrentFacts(t.Context(), current, func(context.Context, CurrentCallerFacts) error { return nil }); err != nil {
			t.Fatal("later page lost actual session", err)
		}
	}
	if _, err = a.RetainOwnerResumer(t.Context(), current); err == nil {
		t.Fatal("closed callback minted retention")
	}
	s.Close()
	if a.AssociationOpen(current) || a.WithCurrentContext(t.Context(), current, func(context.Context) error { return nil }) == nil {
		t.Fatal("session close did not revoke retained claim")
	}
	release()
	release()
}

func TestOwnerResumerCallbackCloseRacesRetention(t *testing.T) {
	for range 16 {
		a, _, path := ownerFixture(t)
		conn, _ := ownerSocket(t, path)
		s, err := a.BindOwner(t.Context(), conn)
		if err != nil {
			t.Fatal(err)
		}
		var current fabric.ExecutionContext
		start := make(chan struct{})
		var wg sync.WaitGroup
		var release func()
		wg.Add(1)
		err = s.WithOwnerAdministration(t.Context(), []byte(`{"operation":"continuation.resume"}`), func(ctx context.Context, admin *OwnerAdministration) error {
			return admin.WithResumerContext(ctx, func(ctx context.Context, c fabric.ExecutionContext) error {
				current = c
				go func() { defer wg.Done(); <-start; release, _ = a.RetainOwnerResumer(ctx, c) }()
				close(start)
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if release == nil && a.AssociationOpen(current) {
			t.Fatal("unretained callback escaped")
		}
		if release != nil {
			release()
			if a.AssociationOpen(current) {
				t.Fatal("released claim remained open")
			}
		}
		if _, err = a.RetainOwnerResumer(t.Context(), current); err == nil {
			t.Fatal("postcallback retention")
		}
		s.Close()
	}
}
