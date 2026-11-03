//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func sourceHolderFixture(t *testing.T) (*NativeShareSourceHolderStore, NativeShareSourceHolderScope) {
	t.Helper()
	recipient, _, _, session := nativeShareStoreFixture(t)
	store, err := NewNativeShareSourceHolderStore(recipient.registry)
	if err != nil {
		t.Fatal(err)
	}
	return store, NativeShareSourceHolderScope{ServerURL: "https://example.test", TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), HostID: domain.ID(session.HostID)}
}

func sourceHolderPath(t *testing.T, store *NativeShareSourceHolderStore, scope NativeShareSourceHolderScope) string {
	t.Helper()
	_, name, err := nativeShareSourceHolderScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(store.registry.root, nativeShareSourceHolderNamespace, name+".json")
}

func TestNativeShareSourceHolderRetrySeparationAndReopen(t *testing.T) {
	recipient, host, request, session := nativeShareStoreFixture(t)
	store, err := NewNativeShareSourceHolderStore(recipient.registry)
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeShareSourceHolderScope{ServerURL: "https://example.test", TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), HostID: domain.ID(session.HostID)}
	d, err := store.Ensure(scope)
	if err != nil {
		t.Fatal(err)
	}
	path := sourceHolderPath(t, store, scope)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatal("source holder storage is not private", err)
		}
	}
	prepared, err := recipient.Prepare(request, scope.ServerURL, session)
	if err != nil {
		t.Fatal(err)
	}
	if d.X25519 == hex.EncodeToString(host.X25519Pub) || d.Ed25519 == hex.EncodeToString(host.Ed25519Pub) || d.X25519 == prepared.HolderX25519 || d.HolderID == prepared.HolderID {
		t.Fatal("source holder reused host or recipient identity")
	}
	canonical := scope
	canonical.ServerURL = "  https://EXAMPLE.TEST///  "
	if retry, err := store.Ensure(canonical); err != nil || retry != d {
		t.Fatal("canonical retry changed descriptor", err)
	}
	root := store.registry.root
	if err := store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenNativeWorkerRegistry(filepath.Dir(root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reopened, err := NewNativeShareSourceHolderStore(r)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := reopened.Ensure(scope); err != nil || retry != d {
		t.Fatal("reopen changed descriptor", err)
	}
	for _, field := range []string{"server", "tenant", "account", "host"} {
		other := scope
		switch field {
		case "server":
			other.ServerURL = "https://other.test"
		case "tenant":
			other.TenantID = domain.NewID()
		case "account":
			other.AccountID = domain.NewID()
		case "host":
			other.HostID = domain.NewID()
		}
		x, err := reopened.Ensure(other)
		if err != nil {
			t.Fatal(err)
		}
		if x.HolderID == d.HolderID || x.X25519 == d.X25519 || x.Ed25519 == d.Ed25519 || x.Fingerprint == d.Fingerprint {
			t.Fatalf("%s scope reused identity", field)
		}
	}
	other, _ := sourceHolderFixture(t)
	x, err := other.Ensure(scope)
	if err != nil {
		t.Fatal(err)
	}
	if x.InstallationID == d.InstallationID || x.HolderID == d.HolderID || x.X25519 == d.X25519 || x.Ed25519 == d.Ed25519 {
		t.Fatal("independent registry reused identity")
	}
}

func TestNativeShareSourceHolderKeyCapabilityLifetime(t *testing.T) {
	store, scope := sourceHolderFixture(t)
	d, err := store.Ensure(scope)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, err := hex.DecodeString(d.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := hex.DecodeString(d.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("callback stopped")
	for _, mode := range []string{"success", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var retained NativeShareSourceHolderKeyUse
			func() {
				defer func() {
					if p := recover(); p != nil && (mode != "panic" || p != callbackErr) {
						t.Fatal("unexpected panic", p)
					}
				}()
				err := store.WithKeys(scope, d, func(keys NativeShareSourceHolderKeyUse) error {
					retained = keys
					if got := fmt.Sprintf("%#v", keys); got != "NativeShareSourceHolderKeyUse{closed}" {
						t.Fatal("key capability formatting exposed internal state")
					}
					sig, err := keys.Sign([]byte("source message"))
					if err != nil || !ed25519.Verify(ed, []byte("source message"), sig) {
						t.Fatal("invalid holder signature", err)
					}
					secret, err := keys.SharedSecret(peer.PublicKey().Bytes())
					if err != nil || !bytes.Equal(secret, want) {
						t.Fatal("invalid shared secret", err)
					}
					clear(secret)
					if mode == "panic" {
						panic(callbackErr)
					}
					if mode == "error" {
						return callbackErr
					}
					return nil
				})
				if mode == "error" && !errors.Is(err, callbackErr) || mode == "success" && err != nil {
					t.Fatal("callback result lost", err)
				}
				if mode == "panic" {
					t.Fatal("callback panic swallowed")
				}
			}()
			if retained == nil {
				t.Fatal("callback did not run")
			}
			if _, err := retained.Sign(nil); err == nil {
				t.Fatal("retained signer remained usable")
			}
			if _, err := retained.SharedSecret(peer.PublicKey().Bytes()); err == nil {
				t.Fatal("retained key agreement remained usable")
			}
		})
	}
	wrong := d
	wrong.Generation++
	called := false
	if err := store.WithKeys(scope, wrong, func(NativeShareSourceHolderKeyUse) error { called = true; return nil }); err == nil || called {
		t.Fatal("mismatching descriptor accepted")
	}
	fresh := scope
	fresh.HostID = domain.NewID()
	if err := store.WithKeys(fresh, d, func(NativeShareSourceHolderKeyUse) error { called = true; return nil }); err == nil || called {
		t.Fatal("WithKeys enrolled missing scope")
	}
}

func TestNativeShareSourceHolderUnsafeStorage(t *testing.T) {
	for _, mutation := range []string{"symlink", "hardlink", "mode", "corrupt", "missing", "namespace-symlink", "namespace-mode", "lock-hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			store, scope := sourceHolderFixture(t)
			d, err := store.Ensure(scope)
			if err != nil {
				t.Fatal(err)
			}
			path := sourceHolderPath(t, store, scope)
			dir := filepath.Dir(path)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "symlink":
				must(os.Rename(path, path+".saved"))
				must(os.Symlink(path+".saved", path))
			case "hardlink":
				must(os.Link(path, path+".link"))
			case "mode":
				must(os.Chmod(path, 0644))
			case "corrupt":
				must(os.WriteFile(path, []byte("{}"), 0600))
			case "missing":
				must(os.Remove(path))
			case "namespace-symlink":
				must(os.Rename(dir, dir+".saved"))
				must(os.Symlink(dir+".saved", dir))
			case "namespace-mode":
				must(os.Chmod(dir, 0755))
			case "lock-hardlink":
				must(os.Link(filepath.Join(dir, "holder.lock"), filepath.Join(dir, "lock.link")))
			}
			if _, err := store.Ensure(scope); err == nil {
				t.Fatal("unsafe storage regenerated or accepted holder")
			}
			if err := store.WithKeys(scope, d, func(NativeShareSourceHolderKeyUse) error { t.Fatal("unsafe keys exposed"); return nil }); err == nil {
				t.Fatal("unsafe storage accepted for key use")
			}
		})
	}
}

func TestNativeShareSourceHolderInterruptedCreation(t *testing.T) {
	for _, fault := range []string{"pending-db", "pending-file", "file-sync", "directory-sync"} {
		t.Run(fault, func(t *testing.T) {
			store, scope := sourceHolderFixture(t)
			_, name, err := nativeShareSourceHolderScope(scope)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected durability failure")
			switch fault {
			case "pending-db":
				_, err = store.registry.db.Exec(`INSERT INTO native_source_holder_enrollments(scope,installation_id,descriptor) VALUES(?,?,NULL)`, name, store.installation)
			case "pending-file":
				dir := filepath.Join(store.registry.root, nativeShareSourceHolderNamespace)
				if err = os.Mkdir(dir, 0700); err == nil {
					err = os.WriteFile(filepath.Join(dir, name+".pending"), []byte("interrupted"), 0600)
				}
			default:
				store.sync = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if fault == "file-sync" && !info.IsDir() || fault == "directory-sync" && info.IsDir() {
						return injected
					}
					return f.Sync()
				}
				_, err = store.Ensure(scope)
				if !errors.Is(err, injected) {
					t.Fatal("sync fault was not reached", err)
				}
				err = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			store.sync = (*os.File).Sync
			if _, err := store.Ensure(scope); err == nil {
				t.Fatal("interrupted creation silently replaced identity")
			}
			root := store.registry.root
			if err := store.registry.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := OpenNativeWorkerRegistry(filepath.Dir(root))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			store, err = NewNativeShareSourceHolderStore(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Ensure(scope); err == nil {
				t.Fatal("reopen recovered uncertain enrollment implicitly")
			}
		})
	}
}

func TestNativeShareSourceHolderMetadataFailsClosed(t *testing.T) {
	for _, mutation := range []string{"missing", "mismatch"} {
		t.Run(mutation, func(t *testing.T) {
			store, scope := sourceHolderFixture(t)
			if _, err := store.Ensure(scope); err != nil {
				t.Fatal(err)
			}
			var err error
			if mutation == "missing" {
				_, err = store.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
			} else {
				_, err = store.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID())
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Ensure(scope); err == nil {
				t.Fatal("changed metadata accepted")
			}
			root := store.registry.root
			if err := store.registry.Close(); err != nil {
				t.Fatal(err)
			}
			if r, err := OpenNativeWorkerRegistry(filepath.Dir(root)); err == nil {
				r.Close()
				t.Fatal("reopen accepted lost installation provenance")
			}
		})
	}
}

func TestNativeShareSourceHolderConcurrentRegistryRetries(t *testing.T) {
	store, scope := sourceHolderFixture(t)
	r, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	second, err := NewNativeShareSourceHolderStore(r)
	if err != nil {
		t.Fatal(err)
	}
	const count = 12
	results := make(chan NativeShareSourceHolderDescriptor, count)
	errors := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := store
			if i%2 == 1 {
				s = second
			}
			d, err := s.Ensure(scope)
			if err != nil {
				errors <- err
				return
			}
			results <- d
		}(i)
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var first NativeShareSourceHolderDescriptor
	for d := range results {
		if first.HolderID == "" {
			first = d
		}
		if d != first {
			t.Fatal("concurrent retry changed identity")
		}
	}
}
