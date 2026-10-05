//go:build linux || darwin

package fabricauth

import (
	"context"
	"crypto/sha256"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"testing"
)

func TestOwnerAdministrationGenuineKernelCapabilityAndLifetime(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	s, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exact := []byte(`{"id":"management-1","input":{"n":9007199254740993}}`)
	var retained *OwnerAdministration
	err = s.WithOwnerAdministration(t.Context(), exact, func(ctx context.Context, c *OwnerAdministration) error {
		retained = c
		if c.RequestDigest() != sha256.Sum256(exact) || c.PrincipalView() != a.config.RootOwner {
			t.Fatal("request/kernel owner mismatch")
		}
		// A recursive root read/current check must not deadlock on Session.mu.
		return c.VerifyCurrent(ctx)
	})
	if err != nil {
		t.Fatal(err)
	}
	if retained.VerifyCurrent(t.Context()) == nil {
		t.Fatal("escaped callback capability remained valid")
	}
	if _, err = retained.MarshalJSON(); err == nil {
		t.Fatal("serialized management authority")
	}
	invoked := false
	if s.WithOwnerAdministration(t.Context(), []byte(`{"x":1,"x":2}`), func(context.Context, *OwnerAdministration) error { invoked = true; return nil }) == nil || invoked {
		t.Fatal("duplicate JSON reached management")
	}
	// A valid managed Session is distinct from owner authority even with same UID.
	s.mu.Lock()
	s.activation = &Activation{Scope: nativeauthority.Scope{}}
	s.mu.Unlock()
	if s.WithOwnerAdministration(t.Context(), exact, func(context.Context, *OwnerAdministration) error { invoked = true; return nil }) == nil || invoked {
		t.Fatal("managed session gained administration")
	}
	s.mu.Lock()
	s.activation = nil
	s.mu.Unlock()
	s.Close()
	if s.WithOwnerAdministration(t.Context(), exact, func(context.Context, *OwnerAdministration) error { invoked = true; return nil }) == nil {
		t.Fatal("closed peer management")
	}
}

func TestOwnerAdministrationDisconnectInvalidatesActiveCapability(t *testing.T) {
	a, _, path := ownerFixture(t)
	conn, peer := ownerSocket(t, path)
	s, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.WithOwnerAdministration(t.Context(), []byte(`{}`), func(ctx context.Context, c *OwnerAdministration) error {
		peer.Close()
		if c.VerifyCurrent(ctx) == nil {
			t.Fatal("disconnected kernel peer accepted")
		}
		return nil
	}); err == nil {
		t.Fatal("postcallback verification accepted disconnected peer")
	}
}

func TestOwnerAdministrationRechecksActualRootAfterCallback(t *testing.T) {
	a, store, path := ownerFixture(t)
	conn, _ := ownerSocket(t, path)
	s, err := a.BindOwner(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered := false
	err = s.WithOwnerAdministration(t.Context(), []byte(`{}`), func(context.Context, *OwnerAdministration) error {
		entered = true
		return store.Close()
	})
	if !entered || err == nil {
		t.Fatal("closed actual retained root accepted after management callback", err)
	}
}
