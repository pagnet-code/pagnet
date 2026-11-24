//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
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

func directSourceCredentialScopeOK(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
	return nil
}

func directSourceCredentialFixture(t *testing.T) (*DirectManagedSourceKeyStore, transport.DirectManagedSourceCredentialIssue, transport.HostSessionPayload) {
	t.Helper()
	keys, p, session, private := directSourcePoPFixture(t)
	clear(private)
	p.ExpiresAt = p.Prepare.Subject.ExpiresAt
	return keys, directSourceIssue(t, keys, p, session), session
}
func directSourceIssue(t *testing.T, keys *DirectManagedSourceKeyStore, p transport.DirectManagedSourcePoPChallenge, session transport.HostSessionPayload) transport.DirectManagedSourceCredentialIssue {
	t.Helper()
	proofRaw, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := transport.DecodeDirectManagedSourcePoPProofVerifier(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := transport.NewDirectManagedSourceCredentialIssue(transport.DirectManagedSourceCredentialIssue{CredentialID: domain.NewID(), ChannelGeneration: 1, Nonce: strings.Repeat("cd", 32), ServerEphemeralX25519: hex.EncodeToString(key.PublicKey().Bytes()), IssuedAt: time.Now().UTC(), InstallExpiresAt: p.ExpiresAt, CredentialExpiresAt: p.ExpiresAt, BudgetExpiresAt: p.ExpiresAt.Add(time.Minute)}, p, proof)
	if err != nil {
		t.Fatal(err)
	}
	return issue
}
func directSourceCredentialPath(keys *DirectManagedSourceKeyStore, p transport.DirectManagedSourceCredentialIssue) string {
	return filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespace, directManagedSourceKeyScope(keys.installation, "https://example.test", p.PoP.Prepare.Subject)+".credential.json")
}

func TestDirectSourceCredentialReplayRestartAndIsolation(t *testing.T) {
	keys, p, session := directSourceCredentialFixture(t)
	first, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("replay changed ACK", err)
	}
	info, err := os.Stat(directSourceCredentialPath(keys, p))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe credential mode", err)
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
	evidence, err := reopened.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOK)
	if err != nil || evidence.State != "installed" || !bytes.Equal(evidence.ACK, first) || evidence.CredentialHash == "" {
		t.Fatal("restart lost evidence", err)
	}
	// A second native source on the same host gets separate custody and credential.
	pop := p.PoP
	pop.ChallengeID = domain.NewID()
	pop.Prepare.CommandID = domain.NewID()
	pop.Prepare.Subject.ID = domain.NewID()
	pop.Prepare.Subject.DirectIntentID = domain.NewID()
	pop.ACK = directSourcePrepare(t, keys, pop.Prepare, session)
	pop.Receipt, err = transport.NewDirectManagedSourcePrepareReceiptReference(pop.ACK)
	if err != nil {
		t.Fatal(err)
	}
	pop.SourceBindingDigest, err = pop.Prepare.Subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	other := directSourceIssue(t, keys, pop, session)
	otherACK, err := keys.InstallCredential(other, "https://example.test", session, directSourceCredentialScopeOK)
	if err != nil || bytes.Equal(first, otherACK) || directSourceCredentialPath(keys, p) == directSourceCredentialPath(keys, other) {
		t.Fatal("sources not isolated", err)
	}
	var count int
	for _, table := range []string{"native_managed_endpoint_key_slots", "native_managed_endpoint_keys", "native_source_holder_enrollments"} {
		if err := registry.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("generic storage used", table, err)
		}
	}
}

func TestDirectSourceCredentialRejectsChangedAuthorityAndEvidence(t *testing.T) {
	for _, kind := range []string{"server", "installation", "subject", "role", "budget", "proof", "prepare", "pop", "callback", "nil", "changed-issue", "changed-id", "expired"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			server := "https://example.test"
			verify := DirectManagedSourceCredentialScopeCheck(directSourceCredentialScopeOK)
			var err error
			switch kind {
			case "server":
				server = "https://other.test"
			case "installation":
				p.PoP.ACK.Reservation.InstallationID = domain.NewID()
			case "subject":
				session.RunnerID = domain.NewID().String()
			case "role":
				p.PoP.Prepare.Subject.OwnershipScope = "shared"
			case "budget":
				p.BudgetExpiresAt = p.IssuedAt
			case "proof":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_pop_challenges SET proof=x'00'`)
			case "prepare":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_prepare_commands SET ack=x'00'`)
			case "pop":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_pop_challenges SET request_digest=zeroblob(32)`)
			case "callback":
				verify = func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
					return errors.New("revoked")
				}
			case "nil":
				verify = nil
			case "changed-issue", "changed-id":
				if _, err = keys.InstallCredential(p, server, session, verify); err != nil {
					t.Fatal(err)
				}
				if kind == "changed-id" {
					p.CredentialID = domain.NewID()
				} else {
					p.Nonce = strings.Repeat("ef", 32)
				}
			case "expired":
				keys.now = func() time.Time { return p.CredentialExpiresAt }
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, server, session, verify); err == nil {
				t.Fatal("accepted invalid issue")
			}
		})
	}
}

func TestDirectSourceCredentialCompletedFileFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "symlink", "mode", "pending", "key-missing", "key-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err != nil {
				t.Fatal(err)
			}
			path := directSourceCredentialPath(keys, p)
			var err error
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("damaged"), 0600)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink("missing", path)
				}
			case "mode":
				err = os.Chmod(path, 0644)
			case "key-missing":
				err = os.Remove(strings.TrimSuffix(path, ".credential.json") + ".json")
			case "key-corrupt":
				err = os.WriteFile(strings.TrimSuffix(path, ".credential.json")+".json", []byte("damaged"), 0600)
			case "pending":
				err = os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("damaged"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
				t.Fatal("regenerated completed secret")
			}
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
				t.Fatal("returned invalid public evidence")
			}
		})
	}
}

func TestDirectSourceCredentialInterruptedPublication(t *testing.T) {
	for _, point := range []int{1, 2} {
		t.Run(string(rune('0'+point)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			syncFile := keys.sync
			count := 0
			keys.sync = func(f *os.File) error {
				count++
				if count == point {
					return errors.New("interrupted")
				}
				return syncFile(f)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
				t.Fatal("missing interruption")
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials`).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("attempt not committed", err)
			}
			keys.sync = syncFile
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err != nil {
				t.Fatal("exact recovery failed", err)
			}
		})
	}
}

func TestDirectSourceCredentialRevalidatesAfterContentionAndBeforeACK(t *testing.T) {
	for _, revokeCall := range []int{2, 3, 4} {
		t.Run(string(rune('0'+revokeCall)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			calls := 0
			verify := func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
				calls++
				if calls >= revokeCall {
					return errors.New("revoked")
				}
				return nil
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, verify); err == nil {
				t.Fatal("revoked authority returned ACK")
			}
		})
	}
}

func TestDirectSourceCredentialAuthorityRevokedDuringLock(t *testing.T) {
	keys, p, session := directSourceCredentialFixture(t)
	blocked := make(chan struct{})
	done := make(chan error, 1)
	var revoked atomic.Bool
	calls := 0
	verify := func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		calls++
		if calls == 1 {
			keys.registry.mu.Lock()
			close(blocked)
		}
		return nil
	}
	go func() { _, err := keys.InstallCredential(p, "https://example.test", session, verify); done <- err }()
	select {
	case <-blocked:
		revoked.Store(true)
		keys.registry.mu.Unlock()
	case <-time.After(10 * time.Second):
		t.Fatal("did not reach contention fence")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked authority returned ACK")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("contended install did not return")
	}
	if _, err := os.Lstat(directSourceCredentialPath(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret published after authority revoked", err)
	}
}

func TestDirectSourceCredentialInstallationMetadataFence(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing", false: "mismatch"}[missing], func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err != nil {
				t.Fatal(err)
			}
			query := `UPDATE native_direct_managed_source_credentials SET installation_id='wrong'`
			if missing {
				query = `DELETE FROM native_registry_metadata WHERE name='installation_id'`
			}
			if _, err := keys.registry.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if err := keys.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("credential installation identity ignored")
			}
		})
	}
}

func TestDirectSourceCredentialAttemptBeforeSecretAndExpiry(t *testing.T) {
	keys, p, session := directSourceCredentialFixture(t)
	calls := 0
	verify := func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
		calls++
		if calls == 2 {
			return errors.New("interrupted after attempt")
		}
		return nil
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, verify); err == nil {
		t.Fatal("missing interruption")
	}
	if _, err := os.Lstat(directSourceCredentialPath(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret before attempt recovery", err)
	}
	var state string
	if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials`).Scan(&state); err != nil || state != "attempted" {
		t.Fatal("missing durable attempt", err)
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err != nil {
		t.Fatal("validated attempt failed recovery", err)
	}
	keys.now = func() time.Time { return p.CredentialExpiresAt }
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
		t.Fatal("expired replay")
	}
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
		t.Fatal("expired evidence")
	}
}
