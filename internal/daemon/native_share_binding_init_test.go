//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

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

func TestNativeShareBindingReadinessBoundedWhenRegistryBusy(t *testing.T) {
	store, _, _, _ := nativeShareStoreFixture(t)
	conn, err := store.registry.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if store.nativeShareBindingReady() {
		t.Fatal("busy registry advertised binding capability")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness blocked websocket handshake for %s", elapsed)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !store.nativeShareBindingReady() {
		t.Fatal("released registry did not advertise capability")
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
	newDaemon := func() (*Daemon, func()) {
		d, err := New(Config{StateDir: stateDir, ServerURL: original.Scope.ServerURL}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		if d.nativeShareBindings != nil {
			t.Fatal("constructor composed binding before serve lock")
		}
		release, err := d.acquireServeLock()
		if err != nil {
			t.Fatal(err)
		}
		d.initNativeShareBindings()
		store, ok := d.nativeShareBindings.(*NativeShareHolderStore)
		if !ok || store.registry != d.nativeRegistry {
			t.Fatal("production executor does not use authoritative registry")
		}
		assertNativeShareBindingOffer(t, d, transport.NativeShareBindingProtocol)
		return d, release
	}
	d, release := newDaemon()
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
	release()
	assertNativeShareBindingOffer(t, d, "")
	restarted, releaseRestart := newDaemon()
	defer releaseRestart()
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

func TestNativeShareBindingIdentityCreatedOnlyUnderServeLock(t *testing.T) {
	stateDir := privateDaemonStateDir(t)
	newDaemon := func() *Daemon {
		d, err := New(Config{StateDir: stateDir, ServerURL: "https://example.test"}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		return d
	}
	first, contender := newDaemon(), newDaemon()
	if _, err := os.Stat(hostcrypto.HostPath(stateDir)); !os.IsNotExist(err) {
		t.Fatalf("constructor created host identity before serve lock: %v", err)
	}
	if first.cryptoManager().identity != nil || contender.cryptoManager().identity != nil || first.nativeShareBindings != nil || contender.nativeShareBindings != nil {
		t.Fatal("constructor cached an identity or holder before serve lock")
	}
	release, err := first.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	first.initNativeShareBindings()
	if _, err := contender.acquireServeLock(); err == nil {
		release()
		t.Fatal("contender acquired live serve lock")
	}
	if contender.nativeShareBindings != nil || contender.cryptoManager().identity != nil {
		t.Fatal("contender composed holder before owning serve lock")
	}
	firstStore, ok := first.nativeShareBindings.(*NativeShareHolderStore)
	if !ok {
		t.Fatal("owner did not compose holder")
	}
	first.Close()
	release()
	release, err = contender.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	contender.initNativeShareBindings()
	secondStore, ok := contender.nativeShareBindings.(*NativeShareHolderStore)
	if !ok || !bytes.Equal(firstStore.signer, secondStore.signer) {
		t.Fatal("restarted owner did not reuse stable host signer")
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
