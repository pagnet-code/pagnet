//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

func directSourceCredentialScopeOK(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
	return nil
}

func directSourceCredentialFenceOK(*sql.Conn, transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
	return func() {}, nil
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
	first, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
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
	otherACK, err := keys.InstallCredential(other, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
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
				if _, err = keys.InstallCredential(p, server, session, verify, directSourceCredentialFenceOK); err != nil {
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
			if _, err := keys.InstallCredential(p, server, session, verify, directSourceCredentialFenceOK); err == nil {
				t.Fatal("accepted invalid issue")
			}
		})
	}
}

func TestDirectSourceCredentialCompletedFileFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "symlink", "mode", "pending", "linked-pending", "key-missing", "key-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err != nil {
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
			case "linked-pending":
				err = os.Link(path, strings.TrimSuffix(path, ".json")+".pending")
			case "pending":
				err = os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("damaged"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err == nil {
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
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err == nil {
				t.Fatal("missing interruption")
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials`).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("attempt not committed", err)
			}
			keys.sync = syncFile
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err != nil {
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
			if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOK); err == nil {
				t.Fatal("revoked authority returned ACK")
			}
		})
	}
}

func TestDirectSourceCredentialAuthorityRevokedDuringLock(t *testing.T) {
	for _, blockCall := range []int{1, 3} {
		t.Run(string(rune('0'+blockCall)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			blocked := make(chan struct{})
			done := make(chan error, 1)
			var revoked atomic.Bool
			calls := 0
			check := func(transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) error {
				if revoked.Load() {
					return errors.New("revoked")
				}
				return nil
			}
			verify := func(issue transport.DirectManagedSourceCredentialIssue, server string, host transport.HostSessionPayload) error {
				if !keys.registry.mu.TryLock() {
					return errors.New("scope callback ran under registry lock")
				}
				keys.registry.mu.Unlock()
				if err := check(issue, server, host); err != nil {
					return err
				}
				calls++
				if calls == blockCall {
					keys.registry.mu.Lock()
					close(blocked)
				}
				return nil
			}
			go func() {
				_, err := keys.InstallCredential(p, "https://example.test", session, verify, func(_ *sql.Conn, issue transport.DirectManagedSourceCredentialIssue, server string, host transport.HostSessionPayload) (func(), error) {
					return func() {}, check(issue, server, host)
				})
				done <- err
			}()
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
			for _, path := range []string{directSourceCredentialPath(keys, p), strings.TrimSuffix(directSourceCredentialPath(keys, p), ".json") + ".pending"} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("secret published after authority revoked", err)
				}
			}
			var installed int
			if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_credentials WHERE state='installed'`).Scan(&installed); err != nil || installed != 0 {
				t.Fatal("revocation committed installed state", err)
			}
		})
	}
}

func TestDirectSourceCredentialRequiresPublicationFence(t *testing.T) {
	keys, p, session := directSourceCredentialFixture(t)
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, nil); err == nil {
		t.Fatal("accepted missing publication fence")
	}
	if _, err := os.Lstat(directSourceCredentialPath(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published without fence", err)
	}
}

func TestDirectSourceCredentialInterruptedLinkedPublication(t *testing.T) {
	for _, kind := range []string{"exact", "different-inode", "extra-link", "corrupt", "mode"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			path := directSourceCredentialPath(keys, p)
			pending := strings.TrimSuffix(path, ".json") + ".pending"
			syncFile := keys.sync
			keys.sync = func(f *os.File) error {
				if err := syncFile(f); err != nil {
					return err
				}
				// Model a crash exactly after Linkat and before Unlinkat.
				if err := os.Link(pending, path); err != nil {
					return err
				}
				return errors.New("interrupted after link")
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err == nil {
				t.Fatal("missing interruption")
			}
			keys.sync = syncFile
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials`).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("attempt not retained", err)
			}
			var stat unix.Stat_t
			if err := unix.Stat(path, &stat); err != nil || stat.Nlink != 2 {
				t.Fatal("did not interrupt in two-link window", err)
			}
			var err error
			switch kind {
			case "different-inode":
				var record []byte
				record, err = os.ReadFile(path)
				defer clear(record)
				if err == nil {
					err = os.Remove(pending)
				}
				if err == nil {
					err = os.WriteFile(pending, record, 0600)
				}
				if err == nil {
					err = os.Link(path, path+".extra")
				}
				if err == nil {
					err = os.Link(pending, pending+".extra")
				}
			case "extra-link":
				err = os.Link(path, path+".extra")
			case "corrupt":
				err = os.WriteFile(path, []byte("damaged"), 0600)
			case "mode":
				err = os.Chmod(path, 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK)
			if kind != "exact" {
				if err == nil {
					t.Fatal("accepted unsafe linked pair")
				}
				if _, err := os.Lstat(pending); err != nil {
					t.Fatal("unsafe pending file changed", err)
				}
				return
			}
			if err != nil {
				t.Fatal("exact linked recovery failed", err)
			}
			if err := unix.Stat(path, &stat); err != nil || stat.Nlink != 1 {
				t.Fatal("recovery did not restore single link", err)
			}
			if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recovery left pending name", err)
			}
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOK); err != nil {
				t.Fatal("recovered evidence unavailable", err)
			}
		})
	}
}

func TestDirectSourceCredentialInstallationMetadataFence(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing", false: "mismatch"}[missing], func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err != nil {
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
	if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOK); err == nil {
		t.Fatal("missing interruption")
	}
	if _, err := os.Lstat(directSourceCredentialPath(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret before attempt recovery", err)
	}
	var state string
	if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials`).Scan(&state); err != nil || state != "attempted" {
		t.Fatal("missing durable attempt", err)
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err != nil {
		t.Fatal("validated attempt failed recovery", err)
	}
	keys.now = func() time.Time { return p.CredentialExpiresAt }
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, directSourceCredentialFenceOK); err == nil {
		t.Fatal("expired replay")
	}
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOK); err == nil {
		t.Fatal("expired evidence")
	}
}

func TestDirectSourceCredentialPublicationFenceThroughTransaction(t *testing.T) {
	for _, failure := range []string{"none", "publication", "update", "panic"} {
		t.Run(failure, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			if failure == "update" {
				if _, err := keys.registry.db.Exec(`CREATE TRIGGER reject_credential_install BEFORE UPDATE ON native_direct_managed_source_credentials BEGIN SELECT RAISE(ABORT, 'interrupted update'); END`); err != nil {
					t.Fatal(err)
				}
			}
			var authority sync.Mutex
			attempted := make(chan struct{})
			revoked := make(chan struct{})
			var releases, syncs int
			var releaseErr error
			syncFile := keys.sync
			keys.sync = func(file *os.File) error {
				syncs++
				if authority.TryLock() {
					authority.Unlock()
					return errors.New("publication escaped authority guard")
				}
				select {
				case <-revoked:
					return errors.New("revocation completed before publication")
				default:
				}
				if failure == "panic" {
					panic("interrupted publication")
				}
				if failure == "publication" {
					return errors.New("interrupted publication")
				}
				return syncFile(file)
			}
			fence := func(conn *sql.Conn, issue transport.DirectManagedSourceCredentialIssue, server string, host transport.HostSessionPayload) (func(), error) {
				// This must be the already-reserved connection, not a fresh transaction.
				if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
					return nil, errors.New("fence received unreserved connection")
				}
				authority.Lock()
				go func() {
					close(attempted)
					authority.Lock()
					close(revoked)
					authority.Unlock()
				}()
				<-attempted
				return func() {
					releases++
					// A new transaction can start only after the final install transaction
					// really ended. Inspect its committed or rolled-back result before
					// allowing the waiting revocation to proceed.
					_, releaseErr = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE")
					if releaseErr == nil {
						var state string
						releaseErr = conn.QueryRowContext(context.Background(), `SELECT state FROM native_direct_managed_source_credentials WHERE credential_id=?`, p.CredentialID).Scan(&state)
						want := "attempted"
						if failure == "none" {
							want = "installed"
						}
						if releaseErr == nil && state != want {
							releaseErr = errors.New("guard released before transaction result")
						}
						_, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK")
						if releaseErr == nil {
							releaseErr = rollbackErr
						}
					}
					authority.Unlock()
				}, nil
			}
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, err = keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, fence)
			}()
			if failure == "panic" {
				if recovered != "interrupted publication" {
					t.Fatalf("publication panic: %v", recovered)
				}
			} else if recovered != nil || (err != nil) != (failure != "none") {
				t.Fatalf("install error: %v; panic: %v", err, recovered)
			}
			if releases != 1 || syncs == 0 || releaseErr != nil {
				t.Fatalf("release count=%d syncs=%d transaction=%v", releases, syncs, releaseErr)
			}
			select {
			case <-revoked:
			case <-time.After(10 * time.Second):
				t.Fatal("revocation remained blocked after transaction")
			}
		})
	}
}

func TestDirectSourceCredentialPublicationFenceAcquisitionFailsClosed(t *testing.T) {
	for _, kind := range []string{"error", "error-with-release", "nil-release"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixture(t)
			releases := 0
			fence := func(*sql.Conn, transport.DirectManagedSourceCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
				if kind == "nil-release" {
					return nil, nil
				}
				if kind == "error-with-release" {
					return func() { releases++ }, errors.New("revoked")
				}
				return nil, errors.New("revoked")
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, fence); err == nil {
				t.Fatal("accepted failed fence acquisition")
			}
			want := 0
			if kind == "error-with-release" {
				want = 1
			}
			if releases != want {
				t.Fatalf("releases=%d, want %d", releases, want)
			}
			for _, path := range []string{directSourceCredentialPath(keys, p), strings.TrimSuffix(directSourceCredentialPath(keys, p), ".json") + ".pending"} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published after failed acquisition", err)
				}
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_credentials WHERE credential_id=?`, p.CredentialID).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("failed acquisition installed credential", err)
			}
		})
	}
}

func TestDirectSourceCredentialPublicationFenceRollbackErrorClosesBeforeRelease(t *testing.T) {
	keys, p, session := directSourceCredentialFixture(t)
	releases := 0
	var releaseErr error
	fence := func(conn *sql.Conn, _ transport.DirectManagedSourceCredentialIssue, _ string, _ transport.HostSessionPayload) (func(), error) {
		// End the transaction early to inject a failure in the helper's ROLLBACK.
		if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
			return nil, err
		}
		return func() {
			releases++
			if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); !errors.Is(err, sql.ErrConnDone) {
				releaseErr = errors.New("connection not closed before guard release")
				return
			}
			fresh, err := keys.registry.db.Conn(context.Background())
			if err != nil {
				releaseErr = err
				return
			}
			defer fresh.Close()
			if _, releaseErr = fresh.ExecContext(context.Background(), "BEGIN IMMEDIATE"); releaseErr == nil {
				_, releaseErr = fresh.ExecContext(context.Background(), "ROLLBACK")
			}
		}, errors.New("interrupted acquisition")
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOK, fence); err == nil {
		t.Fatal("accepted interrupted acquisition")
	}
	if releases != 1 || releaseErr != nil {
		t.Fatalf("releases=%d transaction=%v", releases, releaseErr)
	}
}
