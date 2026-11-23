//go:build linux || darwin

package daemon

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/url"
	"os"
	"testing"

	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func assertNativeShareBindingOffer(t *testing.T, d *Daemon, want string) {
	t.Helper()
	u, err := url.Parse(d.wsURL(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("native_share_binding"); got != want {
		t.Fatalf("binding offer = %q, want %q", got, want)
	}
}

func TestNativeShareBindingProductionCompositionAndRestart(t *testing.T) {
	fixture, identity, request, session := nativeShareStoreFixture(t)
	stateDir := privateDaemonStateDir(t)
	if err := identity.Save(stateDir); err != nil {
		t.Fatal(err)
	}
	original, err := fixture.registry.Lookup(string(request.Binding.InstanceID))
	if err != nil {
		t.Fatal(err)
	}
	newDaemon := func() *Daemon {
		d, err := New(Config{StateDir: stateDir, ServerURL: original.Scope.ServerURL}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		store, ok := d.nativeShareBindings.(*NativeShareHolderStore)
		if !ok || store.registry != d.nativeRegistry {
			t.Fatal("production executor does not use authoritative registry")
		}
		assertNativeShareBindingOffer(t, d, transport.NativeShareBindingProtocol)
		return d
	}
	d := newDaemon()
	reserved, err := d.nativeRegistry.Reserve(original.Scope, original.Spec, original.Profile, original.OriginalOwnershipID)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.nativeShareBindings.Prepare(request, d.ServerURL, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Verify(request, prepared.Subject, identity.Ed25519Verifier()); err != nil {
		t.Fatal(err)
	}
	prove, _ := nativeShareProveChallenge(t, prepared)
	if _, err := d.nativeShareBindings.Prove(prove, d.ServerURL, session); err != nil {
		t.Fatal(err)
	}
	after, err := d.nativeRegistry.Lookup(reserved.Scope.InstanceID)
	beforeJSON, _ := json.Marshal(reserved)
	afterJSON, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("closed binding changed original worker authority", err)
	}
	d.Close()
	assertNativeShareBindingOffer(t, d, "")
	restarted := newDaemon()
	retry, err := restarted.nativeShareBindings.Prepare(request, restarted.ServerURL, session)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(prepared)
	retryJSON, _ := json.Marshal(retry)
	if !bytes.Equal(firstJSON, retryJSON) {
		t.Fatal("production restart changed durable closed binding")
	}
}

func TestNativeShareBindingCompositionUnavailable(t *testing.T) {
	for _, name := range []string{"missing registry", "closed registry", "malformed identity", "invalid signer"} {
		t.Run(name, func(t *testing.T) {
			store, identity, _, _ := nativeShareStoreFixture(t)
			d := &Daemon{Config: Config{StateDir: privateDaemonStateDir(t), ServerURL: "https://example.test?native_share_binding=forged"}, Log: slog.New(slog.DiscardHandler), nativeRegistry: store.registry}
			switch name {
			case "missing registry":
				d.nativeRegistry = nil
			case "closed registry":
				if err := store.registry.Close(); err != nil {
					t.Fatal(err)
				}
			case "malformed identity":
				if err := identity.Save(d.StateDir); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(hostcrypto.HostPath(d.StateDir), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid signer":
				identity.Ed25519Pub[0] ^= 1
				d.cryptoManager().identity = identity
			}
			d.initNativeShareBindings()
			if d.nativeShareBindings != nil {
				t.Fatal("unavailable dependencies composed a holder executor")
			}
			assertNativeShareBindingOffer(t, d, "")
		})
	}
}
