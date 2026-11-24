//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func directSourceScopeOK(transport.DirectManagedSourcePrepareCommand, string, transport.HostSessionPayload) error {
	return nil
}
func directSourcePoPScopeOK(transport.DirectManagedSourcePoPChallenge, string, transport.HostSessionPayload) error {
	return nil
}

func directSourceStoreFixture(t *testing.T) (*DirectManagedSourceKeyStore, transport.DirectManagedSourcePrepareCommand, transport.HostSessionPayload) {
	t.Helper()
	endpoint, _, session := managedEndpointFixture(t)
	keys, err := NewDirectManagedSourceKeyStore(endpoint.registry)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../transport/testdata/direct_managed_source_v1/binding.json")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := transport.DecodeDirectManagedSourceBindingV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	subject.ID = domain.NewID()
	subject.DirectIntentID = domain.NewID()
	subject.TenantID = domain.ID(session.TenantID)
	subject.AccountID = domain.ID(session.AccountID)
	subject.HostID = domain.ID(session.HostID)
	subject.HostCredentialID = domain.ID(session.HostCredentialID)
	subject.NativeAdmissionID = domain.ID(session.NativeAdmissionID)
	subject.ConnectionIncarnationID = subject.NativeAdmissionID
	subject.RunnerID = domain.ID(session.RunnerID)
	subject.RunnerConnectedAt = session.RunnerEpoch
	subject.BootID = session.BootID
	subject.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	subject.ExpiresAt = subject.CreatedAt.Add(5 * time.Minute)
	return keys, transport.DirectManagedSourcePrepareCommand{ProtocolVersion: transport.DirectManagedSourcePrepareProtocol, CommandID: domain.NewID(), Subject: subject}, session
}

func directSourceKeyPath(t *testing.T, keys *DirectManagedSourceKeyStore) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(keys.registry.root, "closed-direct-managed-source-keys", "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("source key file count", len(paths), err)
	}
	return paths[0]
}

func directSourcePrepare(t *testing.T, keys *DirectManagedSourceKeyStore, command transport.DirectManagedSourcePrepareCommand, session transport.HostSessionPayload) transport.DirectManagedSourcePrepareACK {
	t.Helper()
	journal, err := NewDirectManagedSourcePrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Reserve(command, "https://example.test", session, directSourceScopeOK); err != nil {
		t.Fatal(err)
	}
	started, err := journal.BeginKeyReservation(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || !started.KeyStarted {
		t.Fatal("missing creation grant", err)
	}
	reservation, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	ack := transport.DirectManagedSourcePrepareACK{ProtocolVersion: transport.DirectManagedSourcePrepareProtocol, CommandID: command.CommandID, Reservation: reservation}
	raw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Succeed(command, "https://example.test", session, directSourceScopeOK, raw); err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestDirectSourceKeysBindingIsolationAndRestart(t *testing.T) {
	keys, command, session := directSourceStoreFixture(t)
	first, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := keys.Reserve(command, "https://EXAMPLE.TEST///", session, directSourceScopeOK)
	if err != nil || retry != first {
		t.Fatal("binding replay changed key", err)
	}
	path := directSourceKeyPath(t, keys)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("source key mode", err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(keys.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	reopened, err := NewDirectManagedSourceKeyStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.RecoverReservation(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || recovered != first {
		t.Fatal("restart changed reservation", err)
	}
	for _, selected := range []bool{false, true} {
		next := command
		next.CommandID, next.Subject.ID, next.Subject.DirectIntentID = domain.NewID(), domain.NewID(), domain.NewID()
		if selected {
			next.Subject.PrincipalID = domain.NewID()
			next.Subject.SourcePrincipalID = next.Subject.PrincipalID
			next.Subject.EndpointID = domain.NewID()
			next.Subject.InstanceID = domain.NewID()
		}
		reservation, err := keys.Reserve(next, "https://example.test", session, directSourceScopeOK)
		if err != nil || reservation.X25519 == first.X25519 || reservation.EnrollmentDigest == first.EnrollmentDigest {
			t.Fatal("fresh binding inherited key", err)
		}
	}
	// P and N key custody remain independent of this S binding.
	endpoint, err := NewManagedEndpointKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := managedEndpointFixture(t)
	p.TenantID, p.AccountID, p.HostID, p.HostCredentialID = command.Subject.TenantID, command.Subject.AccountID, command.Subject.HostID, command.Subject.HostCredentialID
	p.NativeAdmissionID, p.ConnectionIncarnationID, p.RunnerID = command.Subject.NativeAdmissionID, command.Subject.NativeAdmissionID, command.Subject.RunnerID
	p.RunnerConnectedAt, p.BootID = session.RunnerEpoch, session.BootID
	target, err := endpoint.Reserve(p, "https://example.test", session)
	if err != nil || target.X25519 == first.X25519 {
		t.Fatal("P identity reused", err)
	}
	native, err := NewNativeShareSourceHolderStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := native.Ensure(NativeShareSourceHolderScope{ServerURL: "https://example.test", TenantID: p.TenantID, AccountID: p.AccountID, HostID: p.HostID})
	if err != nil || holder.X25519 == first.X25519 {
		t.Fatal("N identity reused", err)
	}
}

func TestDirectSourceKeysRejectChangedBinding(t *testing.T) {
	for _, field := range []string{"role", "server", "subject", "budget", "session", "installation"} {
		t.Run(field, func(t *testing.T) {
			keys, command, session := directSourceStoreFixture(t)
			if _, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK); err != nil {
				t.Fatal(err)
			}
			server := "https://example.test"
			switch field {
			case "role":
				command.Subject.Role = "P"
			case "server":
				server = "https://other.test"
			case "subject":
				command.Subject.EndpointID = domain.NewID()
			case "budget":
				command.Subject.BudgetAcceptedRevision++
			case "session":
				session.HostCredentialID = domain.NewID().String()
			case "installation":
				if _, err := keys.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := keys.Reserve(command, server, session, directSourceScopeOK); err == nil {
				t.Fatal("changed binding accepted")
			}
			if _, err := keys.RecoverReservation(command, server, session, directSourceScopeOK); err == nil {
				t.Fatal("changed binding recovered")
			}
		})
	}
}

func TestDirectSourceKeysRecoveryNeverRepairs(t *testing.T) {
	for _, failure := range []string{"missing", "corrupt", "pending", "null", "request", "reservation", "public-key", "installation", "missing-installation", "unsafe-mode", "symlink", "sync"} {
		t.Run(failure, func(t *testing.T) {
			keys, command, session := directSourceStoreFixture(t)
			if failure == "sync" {
				keys.sync = func(*os.File) error { return errors.New("injected sync failure") }
				if _, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK); err == nil {
					t.Fatal("sync failure accepted")
				}
				keys.sync = (*os.File).Sync
			} else {
				if _, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK); err != nil {
					t.Fatal(err)
				}
				path := directSourceKeyPath(t, keys)
				var err error
				switch failure {
				case "missing":
					err = os.Remove(path)
				case "corrupt":
					err = os.WriteFile(path, []byte("{}"), 0600)
				case "pending":
					err = os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("uncertain"), 0600)
				case "null":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_keys SET reservation=NULL`)
				case "request":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_keys SET request=x'00'`)
				case "reservation":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_keys SET reservation=x'00'`)
				case "installation":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_keys SET installation_id='wrong'`)
				case "missing-installation":
					_, err = keys.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
				case "unsafe-mode":
					err = os.Chmod(path, 0644)
				case "symlink":
					err = os.Rename(path, path+".real")
					if err == nil {
						err = os.Symlink(path+".real", path)
					}
				case "public-key":
					var raw []byte
					err = keys.registry.db.QueryRow(`SELECT reservation FROM native_direct_managed_source_keys`).Scan(&raw)
					if err != nil {
						t.Fatal(err)
					}
					reservation, decodeErr := transport.DecodeDirectManagedSourceKeyReservation(raw)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					reservation.X25519 = strings.Repeat("12", 32)
					reservation.EnrollmentDigest, err = reservation.Digest()
					if err != nil {
						t.Fatal(err)
					}
					raw, err = reservation.CanonicalBytes()
					if err == nil {
						_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_keys SET reservation=?`, raw)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			var before, after int
			if err := keys.registry.db.QueryRow(`SELECT count(*) FROM native_direct_managed_source_keys`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			random := &managedEndpointRecoveryRandomReader{}
			original := rand.Reader
			rand.Reader = random
			defer func() { rand.Reader = original }()
			if _, err := keys.RecoverReservation(command, "https://example.test", session, directSourceScopeOK); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if random.reads != 0 {
				t.Fatal("recovery generated key")
			}
			if err := keys.registry.db.QueryRow(`SELECT count(*) FROM native_direct_managed_source_keys`).Scan(&after); err != nil || before != after {
				t.Fatal("recovery changed rows", err)
			}
		})
	}
}

func directSourcePoPFixture(t *testing.T) (*DirectManagedSourceKeyStore, transport.DirectManagedSourcePoPChallenge, transport.HostSessionPayload, []byte) {
	t.Helper()
	keys, command, session := directSourceStoreFixture(t)
	ack := directSourcePrepare(t, keys, command, session)
	receipt, err := transport.NewDirectManagedSourcePrepareReceiptReference(ack)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := command.Subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	challenge := transport.DirectManagedSourcePoPChallenge{ProtocolVersion: transport.DirectManagedSourcePoPProtocol, Suite: transport.DirectManagedSourcePoPSuite, ChallengeID: domain.NewID(), Nonce: strings.Repeat("ab", 32), ServerEphemeralX25519: hex.EncodeToString(server.PublicKey().Bytes()), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Prepare: command, ACK: ack, Receipt: receipt, SourceBindingDigest: digest}
	return keys, challenge, session, server.Bytes()
}

func TestDirectSourcePoPProofRestartAndInterruptedProof(t *testing.T) {
	keys, p, session, private := directSourcePoPFixture(t)
	defer clear(private)
	proof, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := transport.DecodeDirectManagedSourcePoPProofVerifier(proof)
	_, want, deriveErr := transport.DeriveDirectManagedSourcePoPVerifier(p, private, time.Now())
	if err != nil || deriveErr != nil || got != want {
		t.Fatal("invalid custody proof", err, deriveErr)
	}
	if _, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_pop_challenges SET proof=NULL`); err != nil {
		t.Fatal(err)
	}
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(keys.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	reopened, err := NewDirectManagedSourceKeyStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := reopened.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOK)
	if err != nil || !bytes.Equal(proof, replay) {
		t.Fatal("interrupted proof changed on restart", err)
	}
}

func TestDirectSourcePoPRejectsMismatchedEvidence(t *testing.T) {
	for _, failure := range []string{"role", "server", "installation", "subject", "budget", "key", "missing", "prepare", "proof", "scope"} {
		t.Run(failure, func(t *testing.T) {
			keys, p, session, private := directSourcePoPFixture(t)
			clear(private)
			server := "https://example.test"
			verify := DirectManagedSourcePoPScopeCheck(directSourcePoPScopeOK)
			var err error
			switch failure {
			case "role":
				p.Prepare.Subject.Role = "N"
			case "server":
				server = "https://other.test"
			case "installation":
				p.ACK.Reservation.InstallationID = domain.NewID()
			case "subject":
				p.Prepare.Subject.EndpointID = domain.NewID()
			case "budget":
				p.Prepare.Subject.BudgetTermsDigest = strings.Repeat("ef", 32)
			case "key":
				p.ACK.Reservation.X25519 = strings.Repeat("12", 32)
			case "missing":
				err = os.Remove(directSourceKeyPath(t, keys))
			case "prepare":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_prepare_commands SET ack=x'00'`)
			case "proof":
				if _, err = keys.ConfirmPoP(p, server, session, verify); err != nil {
					t.Fatal(err)
				}
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_pop_challenges SET proof=x'00'`)
			case "scope":
				verify = func(transport.DirectManagedSourcePoPChallenge, string, transport.HostSessionPayload) error {
					return errors.New("stale authority")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.ConfirmPoP(p, server, session, verify); err == nil {
				t.Fatal("mismatched proof evidence accepted")
			}
		})
	}
}

func TestDirectSourcePrepareJournalCrashFenceAndTerminal(t *testing.T) {
	keys, command, session := directSourceStoreFixture(t)
	journal, err := NewDirectManagedSourcePrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Reserve(command, "https://example.test", session, directSourceScopeOK); err != nil {
		t.Fatal(err)
	}
	start, err := journal.BeginKeyReservation(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || !start.KeyStarted {
		t.Fatal("missing initial creation grant", err)
	}
	reopened, err := NewDirectManagedSourcePrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.BeginKeyReservation(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || retry.KeyStarted {
		t.Fatal("crash regranted key creation", err)
	}
	if _, err := keys.RecoverReservation(command, "https://example.test", session, directSourceScopeOK); err == nil {
		t.Fatal("crash without key recovered")
	}
	failed, err := reopened.Fail(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || failed.State != "failed" {
		t.Fatal("failure was not retained", err)
	}
	replay, err := journal.Reserve(command, "https://example.test", session, directSourceScopeOK)
	if err != nil || !bytes.Equal(replay.ACK, failed.ACK) {
		t.Fatal("failure replay changed", err)
	}
	var failure transport.DirectManagedSourcePrepareFailureACK
	if err := json.Unmarshal(failed.ACK, &failure); err != nil || failure.Error != transport.DirectManagedSourcePrepareFailure {
		t.Fatal("invalid failure ACK", err)
	}
}

func TestDirectSourceKeysRequireCurrentAuthority(t *testing.T) {
	keys, command, session := directSourceStoreFixture(t)
	if _, err := keys.Reserve(command, "https://example.test", session, nil); err == nil {
		t.Fatal("nil authority accepted")
	}
	denied := func(transport.DirectManagedSourcePrepareCommand, string, transport.HostSessionPayload) error {
		keys.registry.mu.Lock()
		keys.registry.mu.Unlock()
		return errors.New("stale captured connection")
	}
	if _, err := keys.Reserve(command, "https://example.test", session, denied); err == nil {
		t.Fatal("stale authority created key")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT count(*) FROM native_direct_managed_source_keys`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied reservation changed database", err)
	}
	if _, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOK); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.RecoverReservation(command, "https://example.test", session, denied); err == nil {
		t.Fatal("stale authority recovered key")
	}
}

func TestDirectSourceInstallationEvidence(t *testing.T) {
	tables := []string{"native_direct_managed_source_keys", "native_direct_managed_source_prepare_commands", "native_direct_managed_source_pop_challenges"}
	for _, table := range tables {
		for _, missing := range []bool{false, true} {
			name := table + "/mismatch"
			if missing {
				name = table + "/missing"
			}
			t.Run(name, func(t *testing.T) {
				keys, p, session, private := directSourcePoPFixture(t)
				clear(private)
				if _, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOK); err != nil {
					t.Fatal(err)
				}
				for _, other := range tables {
					if other != table {
						if _, err := keys.registry.db.Exec("DELETE FROM " + other); err != nil {
							t.Fatal(err)
						}
					}
				}
				query := "UPDATE " + table + " SET installation_id='wrong'"
				if missing {
					query = "DELETE FROM native_registry_metadata WHERE name='installation_id'"
				}
				if _, err := keys.registry.db.Exec(query); err != nil {
					t.Fatal(err)
				}
				if err := keys.registry.initSourceHolderInstallation(); err == nil {
					t.Fatal("source custody installation evidence ignored")
				}
			})
		}
	}
}

func TestDirectSourcePoPRevocationDuringCustodyContention(t *testing.T) {
	keys, p, session, private := directSourcePoPFixture(t)
	clear(private)
	blocked := make(chan struct{})
	done := make(chan error, 1)
	var revoked atomic.Bool
	checks := 0
	verify := func(transport.DirectManagedSourcePoPChallenge, string, transport.HostSessionPayload) error {
		checks++
		if revoked.Load() {
			return errors.New("source authority revoked")
		}
		if checks == 2 {
			// Hold the next custody acquisition until the caller revokes authority.
			keys.registry.mu.Lock()
			close(blocked)
		}
		return nil
	}
	go func() {
		_, err := keys.ConfirmPoP(p, "https://example.test", session, verify)
		done <- err
	}()
	select {
	case <-blocked:
		revoked.Store(true)
		keys.registry.mu.Unlock()
	case <-time.After(10 * time.Second):
		t.Fatal("custody acquisition did not reach contention fence")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked authority produced proof")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("contended proof did not return")
	}
	var proof []byte
	if err := keys.registry.db.QueryRow(`SELECT proof FROM native_direct_managed_source_pop_challenges WHERE challenge_id=?`, p.ChallengeID).Scan(&proof); err != nil {
		t.Fatal(err)
	}
	if proof != nil {
		t.Fatal("proof persisted after authority revoked during custody contention")
	}
}
