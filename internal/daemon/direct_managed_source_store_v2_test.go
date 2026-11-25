//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func directSourceScopeOKV2(transport.DirectManagedSourcePrepareCommandV2, string, transport.HostSessionPayload) error {
	return nil
}

func directSourceStoreFixtureV2(t *testing.T) (*DirectManagedSourceKeyStoreV2, *DirectManagedSourcePrepareJournalV2, transport.DirectManagedSourcePrepareCommandV2, transport.HostSessionPayload) {
	t.Helper()
	endpoint, _, session := managedEndpointFixture(t)
	keys, err := NewDirectManagedSourceKeyStoreV2(endpoint.registry)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewDirectManagedSourcePrepareJournalV2(endpoint.registry)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../transport/testdata/direct_managed_source_v2/binding.json")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := transport.DecodeDirectManagedSourceBindingV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	subject.ID, subject.DirectIntentID = domain.NewID(), domain.NewID()
	subject.TenantID, subject.AccountID = domain.ID(session.TenantID), domain.ID(session.AccountID)
	subject.HostID, subject.HostCredentialID = domain.ID(session.HostID), domain.ID(session.HostCredentialID)
	subject.NativeAdmissionID = domain.ID(session.NativeAdmissionID)
	subject.ConnectionIncarnationID = subject.NativeAdmissionID
	subject.RunnerID, subject.RunnerConnectedAt, subject.BootID = domain.ID(session.RunnerID), session.RunnerEpoch, session.BootID
	subject.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	subject.EnrollmentExpiresAt = subject.CreatedAt.Add(5 * time.Minute)
	subject.AuthorizationExpiresAt = subject.CreatedAt.Add(time.Hour)
	return keys, journal, transport.DirectManagedSourcePrepareCommandV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: domain.NewID(), Subject: subject}, session
}

func directSourceGrantV2(t *testing.T, j *DirectManagedSourcePrepareJournalV2, c transport.DirectManagedSourcePrepareCommandV2, session transport.HostSessionPayload) *directManagedSourceKeyCreationGrantV2 {
	t.Helper()
	if _, err := j.Reserve(c, "https://example.test", session, directSourceScopeOKV2); err != nil {
		t.Fatal(err)
	}
	started, err := j.BeginKeyReservation(c, "https://example.test", session, directSourceScopeOKV2)
	if err != nil || !started.KeyStarted || started.keyCreationGrant == nil {
		t.Fatal("missing creation grant", err)
	}
	return started.keyCreationGrant
}

func directSourceKeyPathV2(t *testing.T, keys *DirectManagedSourceKeyStoreV2) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespaceV2, "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("key file count", len(paths), err)
	}
	return paths[0]
}

func TestDirectSourceV2CustodyReplayAndIsolation(t *testing.T) {
	keys, j, c, session := directSourceStoreFixtureV2(t)
	grant := directSourceGrantV2(t, j, c, session)
	reservation, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant); err == nil {
		t.Fatal("reused creation grant")
	}
	started, err := j.BeginKeyReservation(c, "https://example.test", session, directSourceScopeOKV2)
	if err != nil || started.KeyStarted || started.keyCreationGrant != nil {
		t.Fatal("second creation grant", err)
	}
	ack := transport.DirectManagedSourcePrepareACKV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: c.CommandID, Reservation: reservation}
	raw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = j.Succeed(c, "https://example.test", session, directSourceScopeOKV2, raw); err != nil {
		t.Fatal(err)
	}
	replay, err := j.Reserve(c, "https://EXAMPLE.TEST///", session, directSourceScopeOKV2)
	if err != nil || replay.State != "succeeded" || !bytes.Equal(replay.ACK, raw) {
		t.Fatal("ACK replay changed", err)
	}
	path := directSourceKeyPathV2(t, keys)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatal("custody permissions", err)
		}
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(keys.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	reopened, err := NewDirectManagedSourceKeyStoreV2(registry)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.RecoverReservation(c, "https://example.test", session, directSourceScopeOKV2)
	if err != nil || recovered != reservation {
		t.Fatal("custody replay changed", err)
	}
	request, _ := c.CanonicalBytes()
	digest := sha256.Sum256(request)
	var retained, retainedDigest, reserved []byte
	if err = registry.db.QueryRow(`SELECT request,request_digest,reservation FROM native_direct_managed_source_v2_keys WHERE binding_id=?`, c.Subject.ID).Scan(&retained, &retainedDigest, &reserved); err != nil {
		t.Fatal(err)
	}
	canonical, _ := reservation.CanonicalBytes()
	if !bytes.Equal(retained, request) || !bytes.Equal(retainedDigest, digest[:]) || !bytes.Equal(reserved, canonical) {
		t.Fatal("incomplete retained V2 evidence")
	}
	// The identical binding/command IDs may independently exist in V1. No V2
	// subject is projected through a V1 type in production custody code.
	oldKeys, old, oldSession := directSourceStoreFixture(t)
	v1, err := NewDirectManagedSourceKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	_ = oldKeys
	old.CommandID, old.Subject.ID = c.CommandID, c.Subject.ID
	old.Subject.TenantID, old.Subject.AccountID = c.Subject.TenantID, c.Subject.AccountID
	old.Subject.HostID, old.Subject.HostCredentialID = c.Subject.HostID, c.Subject.HostCredentialID
	old.Subject.NativeAdmissionID, old.Subject.ConnectionIncarnationID = c.Subject.NativeAdmissionID, c.Subject.ConnectionIncarnationID
	old.Subject.RunnerID, old.Subject.RunnerConnectedAt, old.Subject.BootID = c.Subject.RunnerID, c.Subject.RunnerConnectedAt, c.Subject.BootID
	oldSession = session
	v1Reservation, err := v1.Reserve(old, "https://example.test", oldSession, directSourceScopeOK)
	if err != nil || v1Reservation.X25519 == reservation.X25519 || v1Reservation.EnrollmentDigest == reservation.EnrollmentDigest {
		t.Fatal("V1/V2 custody overlap", err)
	}
	if filepath.Dir(directSourceKeyPath(t, v1)) == filepath.Dir(path) {
		t.Fatal("shared namespace")
	}
}

func TestDirectSourceV2CustodyRejectChangedEvidence(t *testing.T) {
	for _, field := range []string{"command", "budget", "authorization", "subject", "server", "session", "installation", "request-digest"} {
		t.Run(field, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			grant := directSourceGrantV2(t, j, c, session)
			if _, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant); err != nil {
				t.Fatal(err)
			}
			server := "https://example.test"
			switch field {
			case "command":
				c.CommandID = domain.NewID()
			case "budget":
				c.Subject.BudgetAcceptedRevision++
			case "authorization":
				c.Subject.AuthorizationExpiresAt = c.Subject.AuthorizationExpiresAt.Add(time.Minute)
			case "subject":
				c.Subject.InstanceID = domain.NewID()
			case "server":
				server = "https://other.test"
			case "session":
				session.HostCredentialID = domain.NewID().String()
			case "installation":
				_, err := keys.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID())
				if err != nil {
					t.Fatal(err)
				}
			case "request-digest":
				_, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_keys SET request_digest=zeroblob(32)`)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := keys.RecoverReservation(c, server, session, directSourceScopeOKV2); err == nil {
				t.Fatal("changed evidence recovered")
			}
			if field != "request-digest" {
				if _, err := j.Reserve(c, server, session, directSourceScopeOKV2); err == nil {
					t.Fatal("changed journal evidence accepted")
				}
			}
		})
	}
}

func TestDirectSourceV2CustodyCrashWindowsFailClosed(t *testing.T) {
	for _, window := range []string{"grant-only", "pending-sync", "directory-sync", "missing", "pending", "corrupt", "unsafe-mode", "null-reservation"} {
		t.Run(window, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			grant := directSourceGrantV2(t, j, c, session)
			if window != "grant-only" {
				syncCalls := 0
				if window == "pending-sync" || window == "directory-sync" {
					keys.sync = func(f *os.File) error {
						syncCalls++
						if window == "pending-sync" || syncCalls == 2 {
							return errors.New("injected sync failure")
						}
						return f.Sync()
					}
				}
				_, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant)
				if window == "pending-sync" || window == "directory-sync" {
					if err == nil {
						t.Fatal("sync failure accepted")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					path := directSourceKeyPathV2(t, keys)
					switch window {
					case "missing":
						err = os.Remove(path)
					case "pending":
						err = os.WriteFile(path[:len(path)-5]+".pending", []byte("uncertain"), 0600)
					case "corrupt":
						err = os.WriteFile(path, []byte("{}"), 0600)
					case "unsafe-mode":
						err = os.Chmod(path, 0644)
					case "null-reservation":
						_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_keys SET reservation=NULL`)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			keys.sync = (*os.File).Sync
			// Simulate losing every process-local grant by reopening both stores.
			restarted, err := NewDirectManagedSourceKeyStoreV2(keys.registry)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := NewDirectManagedSourcePrepareJournalV2(keys.registry)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := journal.BeginKeyReservation(c, "https://example.test", session, directSourceScopeOKV2)
			if err != nil || replay.KeyStarted || replay.keyCreationGrant != nil {
				t.Fatal("crash reissued grant", err)
			}
			if _, err = restarted.Reserve(c, "https://example.test", session, directSourceScopeOKV2, replay.keyCreationGrant); err == nil {
				t.Fatal("crash regenerated custody")
			}
			if _, err = restarted.RecoverReservation(c, "https://example.test", session, directSourceScopeOKV2); err == nil {
				t.Fatal("uncertain custody recovered")
			}
		})
	}
}

func TestDirectSourceV2CustodyInitialGenerationOnly(t *testing.T) {
	for _, field := range []string{"renewal", "predecessor", "credential"} {
		t.Run(field, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			switch field {
			case "renewal":
				c.Subject.BindingGeneration = "2"
				c.Subject.PredecessorBindingID = domain.NewID()
				c.Subject.PreviousCredentialID = domain.NewID()
			case "predecessor":
				c.Subject.PredecessorBindingID = domain.NewID()
			case "credential":
				c.Subject.PreviousCredentialID = domain.NewID()
			}
			if _, err := j.Reserve(c, "https://example.test", session, directSourceScopeOKV2); err == nil {
				t.Fatal("unsupported generation reserved")
			}
			if _, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, nil); err == nil {
				t.Fatal("unsupported generation key created")
			}
		})
	}
}

func TestDirectSourceV2CustodyGrantBindsExactCommand(t *testing.T) {
	keys, j, c, session := directSourceStoreFixtureV2(t)
	grant := directSourceGrantV2(t, j, c, session)
	changed := c
	changed.Subject.BudgetAcceptedRevision++
	if _, err := keys.Reserve(changed, "https://example.test", session, directSourceScopeOKV2, grant); err == nil {
		t.Fatal("substituted grant accepted")
	}
	if _, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant); err == nil {
		t.Fatal("failed attempt restored grant")
	}
}

func TestDirectSourceV2CustodyInstallationIntegrity(t *testing.T) {
	for _, change := range []string{"missing", "conflict", "namespace"} {
		t.Run(change, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			directSourceGrantV2(t, j, c, session)
			var err error
			switch change {
			case "missing":
				_, err = keys.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
			case "conflict":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_prepare_commands SET installation_id=?`, domain.NewID())
			case "namespace":
				_, err = keys.registry.db.Exec(`DELETE FROM native_direct_managed_source_v2_prepare_commands`)
				if err == nil {
					_, err = keys.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = keys.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("V2 evidence allowed installation replacement/conflict")
			}
		})
	}
}

func TestDirectSourceV2CustodyKeyRowsProtectInstallation(t *testing.T) {
	for _, change := range []string{"missing", "conflict"} {
		t.Run(change, func(t *testing.T) {
			keys, j, c, session := directSourceStoreFixtureV2(t)
			grant := directSourceGrantV2(t, j, c, session)
			if _, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.registry.db.Exec(`DELETE FROM native_direct_managed_source_v2_prepare_commands`); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespaceV2)); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(keys.registry.root, directManagedSourcePrepareJournalNamespaceV2)); err != nil {
				t.Fatal(err)
			}
			var err error
			if change == "missing" {
				_, err = keys.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
			} else {
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_keys SET installation_id=?`, domain.NewID())
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = keys.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("V2 key row integrity bypassed")
			}
		})
	}
}

func TestDirectSourceV2CustodyGrantRequiresLiveFence(t *testing.T) {
	keys, j, c, session := directSourceStoreFixtureV2(t)
	grant := directSourceGrantV2(t, j, c, session)
	if _, err := j.Fail(c, "https://example.test", session, directSourceScopeOKV2); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Reserve(c, "https://example.test", session, directSourceScopeOKV2, grant); err == nil {
		t.Fatal("terminal fence authorized creation")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_keys`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed command created custody", err)
	}
}
