//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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

func directSourceCredentialScopeOKV2(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
	return nil
}

func directSourceCredentialFenceOKV2(*sql.Conn, transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) (func(), error) {
	return func() {}, nil
}

func TestDirectSourceCredentialRejectsChangedAuthorityAndEvidenceV2(t *testing.T) {
	for _, kind := range []string{"server", "installation", "subject", "role", "budget", "proof", "prepare", "pop", "callback", "nil", "changed-issue", "changed-id", "expired"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			server := "https://example.test"
			verify := DirectManagedSourceCredentialScopeCheckV2(directSourceCredentialScopeOKV2)
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
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof=x'00'`)
			case "prepare":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_prepare_commands SET ack=x'00'`)
			case "pop":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET request_digest=zeroblob(32)`)
			case "callback":
				verify = func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
					return errors.New("revoked")
				}
			case "nil":
				verify = nil
			case "changed-issue", "changed-id":
				if _, err = keys.InstallCredential(p, server, session, verify, directSourceCredentialFenceOKV2); err != nil {
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
			if _, err := keys.InstallCredential(p, server, session, verify, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("accepted invalid issue")
			}
		})
	}
}

func TestDirectSourceCredentialCompletedFileFailsClosedV2(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "symlink", "mode", "pending", "linked-pending", "key-missing", "key-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
				t.Fatal(err)
			}
			path := directSourceCredentialPathV2(keys, p)
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
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("regenerated completed secret")
			}
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2); err == nil {
				t.Fatal("returned invalid public evidence")
			}
		})
	}
}

func TestDirectSourceCredentialInterruptedPublicationV2(t *testing.T) {
	for _, point := range []int{1, 2} {
		t.Run(string(rune('0'+point)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			syncFile := keys.sync
			count := 0
			keys.sync = func(f *os.File) error {
				count++
				if count == point {
					return errors.New("interrupted")
				}
				return syncFile(f)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("missing interruption")
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_v2_credentials`).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("attempt not committed", err)
			}
			keys.sync = syncFile
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
				t.Fatal("exact recovery failed", err)
			}
		})
	}
}

func TestDirectSourceCredentialRevalidatesAfterContentionAndBeforeACKV2(t *testing.T) {
	for _, revokeCall := range []int{2, 3, 4} {
		t.Run(string(rune('0'+revokeCall)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			calls := 0
			verify := func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
				calls++
				if calls >= revokeCall {
					return errors.New("revoked")
				}
				return nil
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("revoked authority returned ACK")
			}
		})
	}
}

func TestDirectSourceCredentialAuthorityRevokedDuringLockV2(t *testing.T) {
	for _, blockCall := range []int{1, 3} {
		t.Run(string(rune('0'+blockCall)), func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			blocked := make(chan struct{})
			done := make(chan error, 1)
			var revoked atomic.Bool
			calls := 0
			check := func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
				if revoked.Load() {
					return errors.New("revoked")
				}
				return nil
			}
			verify := func(issue transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) error {
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
				_, err := keys.InstallCredential(p, "https://example.test", session, verify, func(_ *sql.Conn, issue transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) (func(), error) {
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
			for _, path := range []string{directSourceCredentialPathV2(keys, p), strings.TrimSuffix(directSourceCredentialPathV2(keys, p), ".json") + ".pending"} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("secret published after authority revoked", err)
				}
			}
			var installed int
			if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_credentials WHERE state='installed'`).Scan(&installed); err != nil || installed != 0 {
				t.Fatal("revocation committed installed state", err)
			}
		})
	}
}

func TestDirectSourceCredentialRequiresPublicationFenceV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, nil); err == nil {
		t.Fatal("accepted missing publication fence")
	}
	if _, err := os.Lstat(directSourceCredentialPathV2(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published without fence", err)
	}
}

func TestDirectSourceCredentialInterruptedLinkedPublicationV2(t *testing.T) {
	for _, kind := range []string{"exact", "different-inode", "extra-link", "corrupt", "mode"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			path := directSourceCredentialPathV2(keys, p)
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
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("missing interruption")
			}
			keys.sync = syncFile
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_v2_credentials`).Scan(&state); err != nil || state != "attempted" {
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
			_, err = keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
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
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2); err != nil {
				t.Fatal("recovered evidence unavailable", err)
			}
		})
	}
}

func TestDirectSourceCredentialInstallationMetadataFenceV2(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing", false: "mismatch"}[missing], func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
				t.Fatal(err)
			}
			query := `UPDATE native_direct_managed_source_v2_credentials SET installation_id='wrong'`
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

func TestDirectSourceCredentialAttemptBeforeSecretAndExpiryV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	calls := 0
	verify := func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
		calls++
		if calls == 2 {
			return errors.New("interrupted after attempt")
		}
		return nil
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOKV2); err == nil {
		t.Fatal("missing interruption")
	}
	if _, err := os.Lstat(directSourceCredentialPathV2(keys, p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret before attempt recovery", err)
	}
	var state string
	if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_v2_credentials`).Scan(&state); err != nil || state != "attempted" {
		t.Fatal("missing durable attempt", err)
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
		t.Fatal("validated attempt failed recovery", err)
	}
	keys.now = func() time.Time { return p.CredentialExpiresAt }
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
		t.Fatal("expired replay")
	}
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2); err == nil {
		t.Fatal("expired evidence")
	}
}

func TestDirectSourceCredentialPublicationFenceThroughTransactionV2(t *testing.T) {
	for _, failure := range []string{"none", "publication", "update", "panic"} {
		t.Run(failure, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			if failure == "update" {
				if _, err := keys.registry.db.Exec(`CREATE TRIGGER reject_credential_install BEFORE UPDATE ON native_direct_managed_source_v2_credentials BEGIN SELECT RAISE(ABORT, 'interrupted update'); END`); err != nil {
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
			fence := func(conn *sql.Conn, issue transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) (func(), error) {
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
						releaseErr = conn.QueryRowContext(context.Background(), `SELECT state FROM native_direct_managed_source_v2_credentials WHERE credential_id=?`, p.CredentialID).Scan(&state)
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
				_, err = keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, fence)
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

func TestDirectSourceCredentialPublicationFenceAcquisitionFailsClosedV2(t *testing.T) {
	for _, kind := range []string{"error", "error-with-release", "nil-release"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			releases := 0
			fence := func(*sql.Conn, transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) (func(), error) {
				if kind == "nil-release" {
					return nil, nil
				}
				if kind == "error-with-release" {
					return func() { releases++ }, errors.New("revoked")
				}
				return nil, errors.New("revoked")
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, fence); err == nil {
				t.Fatal("accepted failed fence acquisition")
			}
			want := 0
			if kind == "error-with-release" {
				want = 1
			}
			if releases != want {
				t.Fatalf("releases=%d, want %d", releases, want)
			}
			for _, path := range []string{directSourceCredentialPathV2(keys, p), strings.TrimSuffix(directSourceCredentialPathV2(keys, p), ".json") + ".pending"} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("published after failed acquisition", err)
				}
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_v2_credentials WHERE credential_id=?`, p.CredentialID).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("failed acquisition installed credential", err)
			}
		})
	}
}

func TestDirectSourceCredentialPublicationFenceRollbackErrorClosesBeforeReleaseV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	releases := 0
	var releaseErr error
	fence := func(conn *sql.Conn, _ transport.DirectManagedSourceCredentialIssueV2, _ string, _ transport.HostSessionPayload) (func(), error) {
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
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, fence); err == nil {
		t.Fatal("accepted interrupted acquisition")
	}
	if releases != 1 || releaseErr != nil {
		t.Fatalf("releases=%d transaction=%v", releases, releaseErr)
	}
}

func directSourceCredentialFixtureV2(t *testing.T) (*DirectManagedSourceKeyStoreV2, transport.DirectManagedSourceCredentialIssueV2, transport.HostSessionPayload) {
	t.Helper()
	keys, pop, session, private := directSourcePoPFixtureV2(t)
	clear(private)
	raw, err := keys.ConfirmPoP(pop, "https://example.test", session, directSourcePoPScopeOKV2)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := transport.DecodeDirectManagedSourcePoPProofV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := transport.NewDirectManagedSourceCredentialIssueV2(transport.DirectManagedSourceCredentialIssueV2{CredentialID: domain.NewID(), ChannelGeneration: "1", Nonce: strings.Repeat("cd", 32), ServerEphemeralX25519: hex.EncodeToString(key.PublicKey().Bytes()), IssuedAt: time.Now().UTC(), InstallExpiresAt: pop.Prepare.Subject.EnrollmentExpiresAt, CredentialExpiresAt: pop.Prepare.Subject.AuthorizationExpiresAt, BudgetExpiresAt: pop.Prepare.Subject.AuthorizationExpiresAt}, pop, proof)
	if err != nil {
		t.Fatal(err)
	}
	return keys, issue, session
}
func directSourceCredentialPathV2(keys *DirectManagedSourceKeyStoreV2, p transport.DirectManagedSourceCredentialIssueV2) string {
	return filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespaceV2, directManagedSourceKeyScopeV2(keys.installation, "https://example.test", p.PoP.Prepare.Subject)+".credential.json")
}

func TestDirectSourceCredentialHistoricalPoPReplayAndIsolationV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	sentinel := []byte("retained V1 evidence")
	if _, err := keys.registry.db.Exec(`INSERT INTO native_direct_managed_source_credentials(credential_id,binding_id,installation_id,issue,issue_digest,state) VALUES(?,?,?,?,?,'attempted')`, p.CredentialID, p.PoP.Prepare.Subject.ID, keys.installation, sentinel, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	keys.now = func() time.Time { return p.PoP.ExpiresAt.Add(time.Second) }
	first, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
	if err != nil {
		t.Fatal("historical PoP must permit installation", err)
	}
	if _, _, err := transport.DecodeDirectManagedSourceCredentialACKVerifier(first); err == nil {
		t.Fatal("V2 ACK accepted in V1 domain")
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
	reopened.now = keys.now
	second, err := reopened.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("restart changed ACK", err)
	}
	reopened.now = func() time.Time { return p.InstallExpiresAt.Add(time.Second) }
	evidence, err := reopened.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2)
	if err != nil || evidence.State != "installed" || !bytes.Equal(evidence.ACK, first) {
		t.Fatal("use evidence lost after installation deadline", err)
	}
	if _, err := reopened.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
		t.Fatal("late installation replay accepted")
	}
	var retained []byte
	if err := registry.db.QueryRow(`SELECT issue FROM native_direct_managed_source_credentials WHERE credential_id=?`, p.CredentialID).Scan(&retained); err != nil || !bytes.Equal(retained, sentinel) {
		t.Fatal("V1 evidence changed", err)
	}
	if _, err := os.Lstat(filepath.Join(keys.registry.root, nativeDirectManagedSourceKeyNamespace)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("V1 namespace touched", err)
	}
}

func TestDirectSourceCredentialInstallDeadlineV2(t *testing.T) {
	for _, point := range []string{"before-attempt", "before-publication", "after-publication"} {
		t.Run(point, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			clock := p.IssuedAt
			keys.now = func() time.Time { return clock }
			verify := DirectManagedSourceCredentialScopeCheckV2(directSourceCredentialScopeOKV2)
			calls := 0
			if point == "before-attempt" {
				clock = p.InstallExpiresAt
			}
			if point == "before-publication" {
				verify = func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
					calls++
					if calls == 3 {
						clock = p.InstallExpiresAt
					}
					return nil
				}
			}
			if point == "after-publication" {
				syncFile := keys.sync
				keys.sync = func(f *os.File) error { err := syncFile(f); clock = p.InstallExpiresAt; return err }
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("installation crossed deadline")
			}
			var installed int
			if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_credentials WHERE state='installed'`).Scan(&installed); err != nil || installed != 0 {
				t.Fatal("expired installation committed", err)
			}
		})
	}
}

func TestDirectSourceCredentialAdditionalEvidenceFailuresV2(t *testing.T) {
	for _, kind := range []string{"intent", "generation", "predecessor", "challenge", "command", "proof-digest", "prepare-deadline", "issued-after-pop", "current-installation"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			var err error
			switch kind {
			case "intent":
				p.PoP.Prepare.Subject.DirectIntentID = domain.NewID()
			case "generation":
				p.ChannelGeneration = "2"
				p.PoP.Prepare.Subject.BindingGeneration = "2"
			case "predecessor":
				p.PoP.Prepare.Subject.PreviousCredentialID = domain.NewID()
			case "challenge":
				p.PoP.ChallengeID = domain.NewID()
			case "command":
				p.PoP.Prepare.CommandID = domain.NewID()
			case "proof-digest":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof_digest=?`, strings.Repeat("ab", 32))
			case "prepare-deadline":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_prepare_commands SET expires_at=?`, p.PoP.ExpiresAt.Format(time.RFC3339Nano))
			case "current-installation":
				_, err = keys.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID())
			case "issued-after-pop":
				p.IssuedAt = p.PoP.ExpiresAt
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}

func TestDirectSourceCredentialSecretAndACKIntegrityV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	ack, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(directSourceCredentialPathV2(keys, p))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var record directManagedSourceCredentialFileV2
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	defer clear(record.Secret)
	var issue, storedACK []byte
	var hash string
	if err := keys.registry.db.QueryRow(`SELECT issue,ack,credential_hash FROM native_direct_managed_source_v2_credentials WHERE credential_id=?`, p.CredentialID).Scan(&issue, &storedACK, &hash); err != nil {
		t.Fatal(err)
	}
	if len(record.Secret) != 32 || bytes.Contains(issue, record.Secret) || bytes.Contains(storedACK, record.Secret) || !bytes.Equal(ack, record.ACK) {
		t.Fatal("invalid secret separation")
	}
	decoded, err := transport.DecodeDirectManagedSourceCredentialACKV2(ack)
	if err != nil {
		t.Fatal(err)
	}
	v1hash, err := transport.DirectManagedSourceCredentialHash(decoded.TranscriptHash, record.Secret)
	if err != nil || v1hash == hash {
		t.Fatal("credential reused V1 hash domain", err)
	}
	decoded.HostConfirmation = strings.Repeat("ab", 32)
	changed, err := decoded.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_credentials SET ack=? WHERE credential_id=?`, changed, p.CredentialID); err != nil {
		t.Fatal(err)
	}
	keys.now = func() time.Time { return p.InstallExpiresAt.Add(time.Second) }
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2); err == nil {
		t.Fatal("changed retained ACK accepted")
	}
}

func TestDirectSourceCredentialAttemptedRecoveryAfterRestartV2(t *testing.T) {
	for _, window := range []string{"attempt-only", "pending", "two-links", "published"} {
		t.Run(window, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			verify := DirectManagedSourceCredentialScopeCheckV2(directSourceCredentialScopeOKV2)
			path := directSourceCredentialPathV2(keys, p)
			pending := strings.TrimSuffix(path, ".json") + ".pending"
			if window == "attempt-only" {
				calls := 0
				verify = func(transport.DirectManagedSourceCredentialIssueV2, string, transport.HostSessionPayload) error {
					calls++
					if calls == 2 {
						return errors.New("crash after attempt")
					}
					return nil
				}
			} else {
				syncFile := keys.sync
				calls := 0
				keys.sync = func(file *os.File) error {
					calls++
					if err := syncFile(file); err != nil {
						return err
					}
					if window == "two-links" && calls == 1 {
						if err := os.Link(pending, path); err != nil {
							return err
						}
					}
					if (window != "published" && calls == 1) || calls == 2 {
						return errors.New("crash during publication")
					}
					return nil
				}
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, verify, directSourceCredentialFenceOKV2); err == nil {
				t.Fatal("missing interruption")
			}
			var state string
			if err := keys.registry.db.QueryRow(`SELECT state FROM native_direct_managed_source_v2_credentials WHERE credential_id=?`, p.CredentialID).Scan(&state); err != nil || state != "attempted" {
				t.Fatal("attempt not committed", err)
			}
			// Check the modeled crash window before discarding the original store.
			for name, want := range map[string]bool{path: window == "published" || window == "two-links", pending: window == "pending" || window == "two-links"} {
				_, err := os.Lstat(name)
				if (err == nil) != want || (err != nil && !errors.Is(err, os.ErrNotExist)) {
					t.Fatal("unexpected publication window", err)
				}
			}
			root := filepath.Dir(keys.registry.root)
			if err := keys.registry.Close(); err != nil {
				t.Fatal(err)
			}
			registry, err := OpenNativeWorkerRegistry(root)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			reopened, err := NewDirectManagedSourceKeyStoreV2(registry)
			if err != nil {
				t.Fatal(err)
			}
			reopened.now = func() time.Time { return p.PoP.ExpiresAt.Add(time.Second) }
			ack, err := reopened.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2)
			if err != nil {
				t.Fatal("restart failed exact attempted recovery", err)
			}
			evidence, err := reopened.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2)
			if err != nil || evidence.State != "installed" || !bytes.Equal(ack, evidence.ACK) {
				t.Fatal("restart recovery lost completed evidence", err)
			}
			if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("restart recovery retained pending publication", err)
			}
		})
	}
}

func TestDirectSourceCredentialUseClockBoundariesV2(t *testing.T) {
	keys, p, _ := directSourceCredentialFixtureV2(t)
	deadline := p.IssuedAt.Add(time.Hour)
	for _, bound := range []string{"credential", "authorization", "budget"} {
		t.Run(bound, func(t *testing.T) {
			// Canonical issues require credential expiry <= both other deadlines.
			// Isolate each clock guard here so one guard cannot mask another.
			issue := p
			issue.CredentialExpiresAt = deadline.Add(time.Hour)
			issue.PoP.Prepare.Subject.AuthorizationExpiresAt = deadline.Add(time.Hour)
			issue.BudgetExpiresAt = deadline.Add(time.Hour)
			switch bound {
			case "credential":
				issue.CredentialExpiresAt = deadline
			case "authorization":
				issue.PoP.Prepare.Subject.AuthorizationExpiresAt = deadline
			case "budget":
				issue.BudgetExpiresAt = deadline
			}
			for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
				keys.now = func() time.Time { return deadline.Add(offset) }
				if got, want := keys.credentialUseValid(issue), offset < 0; got != want {
					t.Fatalf("offset %v: usable=%v, want %v", offset, got, want)
				}
			}
		})
	}
}

func TestDirectSourceCredentialPublicUseExpiryBoundariesV2(t *testing.T) {
	for _, bound := range []string{"credential", "authorization", "budget"} {
		t.Run(bound, func(t *testing.T) {
			keys, p, session := directSourceCredentialFixtureV2(t)
			deadline := p.CredentialExpiresAt
			switch bound {
			case "credential":
				deadline = p.InstallExpiresAt.Add(time.Minute)
				p.CredentialExpiresAt = deadline
			case "authorization":
				p.BudgetExpiresAt = deadline.Add(time.Hour)
			case "budget":
				deadline = p.InstallExpiresAt.Add(time.Minute)
				p.BudgetExpiresAt, p.CredentialExpiresAt = deadline, deadline
			}
			keys.now = func() time.Time { return p.IssuedAt }
			if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
				t.Fatal(err)
			}
			for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
				keys.now = func() time.Time { return deadline.Add(offset) }
				_, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2)
				if (err == nil) != (offset < 0) {
					t.Fatalf("offset %v: unexpected evidence result: %v", offset, err)
				}
			}
		})
	}
}

func TestDirectSourceCredentialRejectsPreIssueClockV2(t *testing.T) {
	keys, p, session := directSourceCredentialFixtureV2(t)
	keys.now = func() time.Time { return p.IssuedAt.Add(-time.Nanosecond) }
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err == nil {
		t.Fatal("installed before issue time")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_managed_source_v2_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("pre-issue clock committed an attempt", err)
	}
	keys.now = func() time.Time { return p.IssuedAt }
	if _, err := keys.InstallCredential(p, "https://example.test", session, directSourceCredentialScopeOKV2, directSourceCredentialFenceOKV2); err != nil {
		t.Fatal("issue-time installation failed", err)
	}
	keys.now = func() time.Time { return p.IssuedAt.Add(-time.Nanosecond) }
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, directSourceCredentialScopeOKV2); err == nil {
		t.Fatal("returned evidence before issue time")
	}
}
