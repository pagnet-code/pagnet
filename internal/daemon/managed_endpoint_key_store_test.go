//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func managedEndpointFixture(t *testing.T) (*ManagedEndpointKeyStore, transport.ManagedEndpointBindingIntent, transport.HostSessionPayload) {
	t.Helper()
	holder, _, _, session := nativeShareStoreFixture(t)
	session.HostCredentialID = domain.NewID().String()
	store, err := NewManagedEndpointKeyStore(holder.registry)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	subject := transport.ManagedEndpointBindingIntent{
		ID: domain.NewID(), DirectIntentID: domain.NewID(), ProtocolVersion: transport.ManagedEndpointBindingProtocol,
		TenantID: domain.ID(session.TenantID), AccountID: domain.ID(session.AccountID), OwnershipScope: "personal",
		PrincipalID: domain.NewID(), EndpointID: domain.NewID(), InstanceID: domain.NewID(), OriginID: domain.NewID(),
		NativeGeneration: "native-generation", NativeSessionID: "native-session", OwnershipID: domain.NewID(), OwnershipGeneration: "ownership-generation",
		NativeAdmissionID: domain.ID(session.NativeAdmissionID), ConnectionIncarnationID: domain.ID(session.NativeAdmissionID), HostID: domain.ID(session.HostID), HostCredentialID: domain.ID(session.HostCredentialID), RunnerID: domain.ID(session.RunnerID), RunnerConnectedAt: session.RunnerEpoch, BootID: session.BootID,
		BindingGeneration: 1, State: "pending_closed", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	return store, subject, session
}
func managedEndpointPath(t *testing.T, s *ManagedEndpointKeyStore) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(s.registry.root, nativeManagedEndpointKeyNamespace, "*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatal("key file count", len(matches), err)
	}
	return matches[0]
}
func TestManagedEndpointKeyRetryRestartAndConcurrency(t *testing.T) {
	store, p, session := managedEndpointFixture(t)
	secondRegistry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer secondRegistry.Close()
	second, err := NewManagedEndpointKeyStore(secondRegistry)
	if err != nil {
		t.Fatal(err)
	}
	const count = 12
	results := make(chan transport.ManagedEndpointKeyReservation, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		current := store
		if i%2 == 1 {
			current = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := current.Reserve(p, "https://example.test", session)
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first transport.ManagedEndpointKeyReservation
	for r := range results {
		if first.X25519 == "" {
			first = r
		}
		if r != first {
			t.Fatal("concurrent reservation changed")
		}
	}
	path := managedEndpointPath(t, store)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key file mode", err)
	}
	root := store.registry.root
	if err = store.registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	reopened, err := NewManagedEndpointKeyStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reopened.Reserve(p, "https://EXAMPLE.TEST///", session)
	if err != nil || r != first {
		t.Fatal("restart changed enrollment", err)
	}
	// Independent installation, source holder and host identities never share keys.
	source, err := NewNativeShareSourceHolderStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := source.Ensure(NativeShareSourceHolderScope{ServerURL: "https://example.test", TenantID: p.TenantID, AccountID: p.AccountID, HostID: p.HostID})
	if err != nil || sd.X25519 == first.X25519 {
		t.Fatal("source identity reused", err)
	}
	other, _, _ := managedEndpointFixture(t)
	r, err = other.Reserve(p, "https://example.test", session)
	if err != nil || r.X25519 == first.X25519 || r.InstallationID == first.InstallationID {
		t.Fatal("installation identity reused", err)
	}
}
func TestManagedEndpointKeySubjectConflictAndReconnect(t *testing.T) {
	for _, field := range []string{"principal", "endpoint", "instance", "origin", "nativeGeneration", "nativeSession", "ownership", "ownershipGeneration", "expiry", "bindingGeneration", "directIntent", "server", "reconnect"} {
		t.Run(field, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if _, err := store.Reserve(p, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			server := "https://example.test"
			switch field {
			case "principal":
				p.PrincipalID = domain.NewID()
			case "endpoint":
				p.EndpointID = domain.NewID()
			case "instance":
				p.InstanceID = domain.NewID()
			case "origin":
				p.OriginID = domain.NewID()
			case "nativeGeneration":
				p.NativeGeneration = "other"
			case "nativeSession":
				p.NativeSessionID = "other"
			case "ownership":
				p.OwnershipID = domain.NewID()
			case "ownershipGeneration":
				p.OwnershipGeneration = "other"
			case "expiry":
				p.ExpiresAt = p.ExpiresAt.Add(-time.Second)
			case "bindingGeneration":
				p.BindingGeneration = 2
			case "directIntent":
				p.DirectIntentID = domain.NewID()
			case "server":
				server = "https://other.test"
			case "reconnect":
				p.NativeAdmissionID = domain.NewID()
				p.ConnectionIncarnationID = p.NativeAdmissionID
				session.NativeAdmissionID = p.NativeAdmissionID.String()
			}
			if _, err := store.Reserve(p, server, session); err == nil {
				t.Fatal("changed subject accepted")
			}
		})
	}
	// A genuinely new enrollment on a new connection gets a fresh endpoint key.
	store, p, session := managedEndpointFixture(t)
	first, err := store.Reserve(p, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = domain.NewID()
	p.NativeAdmissionID = domain.NewID()
	p.ConnectionIncarnationID = p.NativeAdmissionID
	session.NativeAdmissionID = p.NativeAdmissionID.String()
	next, err := store.Reserve(p, "https://example.test", session)
	if err != nil || first.X25519 == next.X25519 || first.EnrollmentDigest == next.EnrollmentDigest {
		t.Fatal("connection inherited endpoint key", err)
	}
}
func TestManagedEndpointKeyCapturedSession(t *testing.T) {
	for _, field := range []string{"tenant", "account", "ownership", "host", "credential", "admission", "runner", "epoch", "boot"} {
		t.Run(field, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			switch field {
			case "tenant":
				session.TenantID = domain.NewID().String()
			case "account":
				session.AccountID = domain.NewID().String()
			case "ownership":
				session.OwnershipScope = "network"
			case "host":
				session.HostID = domain.NewID().String()
			case "credential":
				session.HostCredentialID = domain.NewID().String()
			case "admission":
				session.NativeAdmissionID = domain.NewID().String()
			case "runner":
				session.RunnerID = domain.NewID().String()
			case "epoch":
				session.RunnerEpoch = session.RunnerEpoch.Add(time.Second)
			case "boot":
				session.BootID = "other"
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("wrong session accepted")
			}
			var count int
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys`).Scan(&count); err != nil || count != 0 {
				t.Fatal("mismatch reserved a key", err)
			}
		})
	}
}
func TestManagedEndpointKeyCorruptionAndInterruptedReservation(t *testing.T) {
	for _, failure := range []string{"missing", "corrupt", "private", "journal", "pending", "symlink", "sync", "reserved-missing", "installation"} {
		t.Run(failure, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if failure == "sync" || failure == "reserved-missing" {
				store.sync = func(*os.File) error { return errors.New("injected sync failure") }
				if _, err := store.Reserve(p, "https://example.test", session); err == nil {
					t.Fatal("sync failure accepted")
				}
				store.sync = (*os.File).Sync
				if failure == "reserved-missing" {
					pending, err := filepath.Glob(filepath.Join(store.registry.root, nativeManagedEndpointKeyNamespace, "*.pending"))
					if err != nil || len(pending) != 1 {
						t.Fatal("pending key count", err)
					}
					if err := os.Remove(pending[0]); err != nil {
						t.Fatal(err)
					}
				}
				var count int
				if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys WHERE reservation IS NULL`).Scan(&count); err != nil || count != 1 {
					t.Fatal("missing durable reservation", err)
				}
			} else {
				if _, err := store.Reserve(p, "https://example.test", session); err != nil {
					t.Fatal(err)
				}
				path := managedEndpointPath(t, store)
				switch failure {
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "corrupt":
					if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				case "private":
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var record managedEndpointSlotKeyRecord
					if json.Unmarshal(raw, &record) != nil {
						t.Fatal("decode")
					}
					record.Private = bytes.Repeat([]byte{7}, 32)
					raw, _ = json.Marshal(record)
					if os.WriteFile(path, raw, 0600) != nil {
						t.Fatal("write")
					}
				case "journal":
					if _, err := store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation=NULL`); err != nil {
						t.Fatal(err)
					}
				case "pending":
					if err := os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("uncertain"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Rename(path, path+".real"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".real", path); err != nil {
						t.Fatal(err)
					}
				case "installation":
					if _, err := store.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID()); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("unsafe reservation replaced")
			}
		})
	}
}
func TestManagedEndpointKeyScopeIsolationAndExpiry(t *testing.T) {
	for _, field := range []string{"server", "tenant", "account", "principal", "instance", "endpoint"} {
		t.Run(field, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			first, err := store.Reserve(p, "https://example.test", session)
			if err != nil {
				t.Fatal(err)
			}
			p.ID = domain.NewID()
			server := "https://example.test"
			switch field {
			case "server":
				server = "https://other.test"
			case "tenant":
				p.TenantID = domain.NewID()
				session.TenantID = p.TenantID.String()
			case "account":
				p.AccountID = domain.NewID()
				session.AccountID = p.AccountID.String()
			case "principal":
				p.PrincipalID = domain.NewID()
			case "instance":
				p.InstanceID = domain.NewID()
			case "endpoint":
				p.EndpointID = domain.NewID()
			}
			next, err := store.Reserve(p, server, session)
			if err != nil || next.X25519 == first.X25519 {
				t.Fatal("scope inherited key", err)
			}
		})
	}
	store, p, session := managedEndpointFixture(t)
	if _, err := store.Reserve(p, "https://example.test", session); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return p.ExpiresAt }
	if _, err := store.Reserve(p, "https://example.test", session); err == nil {
		t.Fatal("expired retry accepted")
	}
}
func TestManagedEndpointKeysRequireServeLock(t *testing.T) {
	store, _, _ := managedEndpointFixture(t)
	d := &Daemon{Config: Config{StateDir: filepath.Dir(store.registry.root)}, Log: discardLog(), nativeRegistry: store.registry}
	d.initManagedEndpointKeys()
	if d.managedEndpointKeys != nil {
		t.Fatal("initialized without serve lock")
	}
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	d.initManagedEndpointKeys()
	if d.managedEndpointKeys == nil {
		t.Fatal("closed store unavailable under serve lock")
	}
}
func TestManagedEndpointReservationPrivateKeyNotPublic(t *testing.T) {
	store, p, session := managedEndpointFixture(t)
	public, err := store.Reserve(p, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(managedEndpointPath(t, store))
	if err != nil {
		t.Fatal(err)
	}
	var record managedEndpointSlotKeyRecord
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("decode")
	}
	encoded, _ := json.Marshal(public)
	if bytes.Contains(encoded, []byte(hex.EncodeToString(record.Private))) || bytes.Contains(encoded, []byte(`"private"`)) {
		t.Fatal("private export")
	}
}

type managedEndpointRecoveryRandomReader struct {
	reads int
}

func (r *managedEndpointRecoveryRandomReader) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected recovery randomness")
}

func TestManagedEndpointKeyRecoverReservation(t *testing.T) {
	store, p, session := managedEndpointFixture(t)
	want, err := store.Reserve(p, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	secondRegistry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer secondRegistry.Close()
	reopened, err := NewManagedEndpointKeyStore(secondRegistry)
	if err != nil {
		t.Fatal(err)
	}
	reopened.sync = func(*os.File) error { return errors.New("unexpected recovery sync") }
	random := &managedEndpointRecoveryRandomReader{}
	originalRandom := rand.Reader
	rand.Reader = random
	defer func() { rand.Reader = originalRandom }()
	got, err := reopened.RecoverReservation(p, "https://EXAMPLE.TEST///", session)
	if err != nil || got != want {
		t.Fatal("exact recovery changed reservation", err)
	}
	if random.reads != 0 {
		t.Fatal("recovery generated randomness")
	}
}

func TestManagedEndpointKeyRecoveryNeverRepairs(t *testing.T) {
	for _, failure := range []string{"null", "pending", "missing", "corrupt", "private", "deleted", "unreserved", "namespace", "lock", "unsafe", "symlink", "scope", "session", "expired", "installation"} {
		t.Run(failure, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if _, err := store.Reserve(p, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			path := managedEndpointPath(t, store)
			switch failure {
			case "null":
				if _, err := store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation=NULL`); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("uncertain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing", "deleted":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if failure == "deleted" {
					if _, err := store.registry.db.Exec(`DELETE FROM native_managed_endpoint_keys`); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "private":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var record managedEndpointSlotKeyRecord
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				record.Private = bytes.Repeat([]byte{7}, 32)
				raw, _ = json.Marshal(record)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "unreserved":
				p.ID = domain.NewID()
				p.EndpointID = domain.NewID()
			case "namespace":
				if err := os.RemoveAll(filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Remove(filepath.Join(filepath.Dir(path), "holder.lock")); err != nil {
					t.Fatal(err)
				}
			case "unsafe":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "scope":
				p.EndpointID = domain.NewID()
			case "session":
				session.HostCredentialID = domain.NewID().String()
			case "expired":
				store.now = func() time.Time { return p.ExpiresAt }
			case "installation":
				if _, err := store.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID()); err != nil {
					t.Fatal(err)
				}
			}
			var beforeRows, afterRows int
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys`).Scan(&beforeRows); err != nil {
				t.Fatal(err)
			}
			beforeFiles, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
			if err != nil {
				t.Fatal(err)
			}
			random := &managedEndpointRecoveryRandomReader{}
			originalRandom := rand.Reader
			rand.Reader = random
			defer func() { rand.Reader = originalRandom }()
			if _, err := store.RecoverReservation(p, "https://example.test", session); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if random.reads != 0 {
				t.Fatal("failed recovery generated randomness")
			}
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys`).Scan(&afterRows); err != nil || afterRows != beforeRows {
				t.Fatal("recovery changed reservation rows", err)
			}
			afterFiles, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
			if err != nil || strings.Join(beforeFiles, "\n") != strings.Join(afterFiles, "\n") {
				t.Fatal("recovery changed key files", err)
			}
		})
	}
}
