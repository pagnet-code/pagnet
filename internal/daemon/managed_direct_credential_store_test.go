//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func managedCredentialStoreFixture(t *testing.T) (*ManagedEndpointKeyStore, transport.ManagedDirectCredentialIssue, transport.HostSessionPayload, []byte) {
	t.Helper()
	keys, pop, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	return managedCredentialStoreIssue(t, keys, pop, session)
}

func managedCredentialStoreIssue(t *testing.T, keys *ManagedEndpointKeyStore, pop transport.ManagedEndpointPoPChallenge, session transport.HostSessionPayload) (*ManagedEndpointKeyStore, transport.ManagedDirectCredentialIssue, transport.HostSessionPayload, []byte) {
	t.Helper()
	raw, err := keys.confirmPoP(pop, "https://example.test", session, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := transport.DecodeManagedEndpointPoPProofVerifier(raw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := transport.NewManagedDirectCredentialIssue(transport.ManagedDirectCredentialIssue{
		CredentialID: domain.NewID(), ChannelGeneration: 1,
		Nonce:                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32)),
		ServerEphemeralX25519: hex.EncodeToString(server.PublicKey().Bytes()),
		IssuedAt:              pop.IssuedAt, InstallExpiresAt: pop.ExpiresAt,
		CredentialExpiresAt: pop.IssuedAt.Add(2 * time.Minute),
		Budget:              transport.ManagedDirectCredentialBudgetReference{AgreementID: domain.NewID(), AcceptedRevision: 2, TermsDigest: strings.Repeat("ef", 32), ExpiresAt: pop.IssuedAt.Add(3 * time.Minute)},
	}, pop, proof)
	if err != nil {
		t.Fatal(err)
	}
	keys.now = func() time.Time { return issue.IssuedAt }
	private := server.Bytes()
	t.Cleanup(func() { clear(private) })
	return keys, issue, session, private
}

func managedCredentialScopeOK(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
	return nil
}
func managedCredentialFenceOK(*sql.Conn, transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
	return func() {}, nil
}
func managedCredentialPath(keys *ManagedEndpointKeyStore, p transport.ManagedDirectCredentialIssue) string {
	return filepath.Join(keys.registry.root, nativeManagedEndpointKeyNamespace, managedDirectCredentialName(keys.installation, "https://example.test", p)+".json")
}
func installManagedCredential(t *testing.T, keys *ManagedEndpointKeyStore, p transport.ManagedDirectCredentialIssue, session transport.HostSessionPayload) []byte {
	t.Helper()
	ack, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestManagedDirectCredentialStoreInstallAndReplay(t *testing.T) {
	keys, p, session, server := managedCredentialStoreFixture(t)
	endpoint := managedEndpointPath(t, keys)
	before, err := os.ReadFile(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	ack := installManagedCredential(t, keys, p, session)
	transcript, hash, verifier, err := transport.DeriveManagedDirectCredentialVerifier(p, server, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, digest, err := transport.DecodeManagedDirectCredentialACKVerifier(ack)
	if err != nil || digest != verifier || decoded.TranscriptHash != transcript {
		t.Fatal("ACK verifier mismatch", err)
	}
	reopened, err := NewManagedEndpointKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = keys.now
	for _, store := range []*ManagedEndpointKeyStore{keys, reopened} {
		got := installManagedCredential(t, store, p, session)
		evidence, err := store.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK)
		raw, _ := p.CanonicalBytes()
		sum := sha256.Sum256(raw)
		if err != nil || !bytes.Equal(got, ack) || evidence.State != "installed" || evidence.CredentialHash != hash || evidence.IssueDigest != hex.EncodeToString(sum[:]) || !bytes.Equal(evidence.ACK, ack) {
			t.Fatal("replay evidence mismatch", err)
		}
	}
	after, err := os.ReadFile(endpoint)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("endpoint key changed", err)
	}
	info, err := os.Stat(managedCredentialPath(keys, p))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential mode", err)
	}
	for _, namespace := range []string{nativeDirectManagedSourceKeyNamespace, nativeDirectManagedSourceKeyNamespaceV2, nativeShareSourceHolderNamespace} {
		if _, err := os.Lstat(filepath.Join(keys.registry.root, namespace)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("source namespace touched", namespace, err)
		}
	}
	for _, change := range []string{"same-id", "same-binding"} {
		t.Run(change, func(t *testing.T) {
			other := p
			other.Nonce = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x65}, 32))
			if change == "same-binding" {
				other.CredentialID = domain.NewID()
			}
			if _, err := keys.InstallCredential(other, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err == nil {
				t.Fatal("alternate issue accepted")
			}
		})
	}
}

func TestManagedDirectCredentialStoreAuthority(t *testing.T) {
	for _, stage := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			calls := 0
			stale := errors.New("stale authority")
			_, err := keys.InstallCredential(p, "https://example.test", session, func(transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) error {
				keys.registry.mu.Lock()
				keys.registry.mu.Unlock()
				calls++
				if calls == stage {
					return stale
				}
				return nil
			}, managedCredentialFenceOK)
			if !errors.Is(err, stale) || calls != stage {
				t.Fatal("authority check missing", calls, err)
			}
		})
	}
	for _, kind := range []string{"origin", "session", "nil-check", "nil-fence", "fence-error", "fence-no-release"} {
		t.Run(kind, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			origin := "https://example.test"
			verify := ManagedDirectCredentialScopeCheck(managedCredentialScopeOK)
			fence := ManagedDirectCredentialPublicationFence(managedCredentialFenceOK)
			released := 0
			switch kind {
			case "origin":
				origin = "https://other.test"
			case "session":
				session.HostID = domain.NewID().String()
			case "nil-check":
				verify = nil
			case "nil-fence":
				fence = nil
			case "fence-error":
				fence = func(*sql.Conn, transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
					return func() { released++ }, errors.New("stale fence")
				}
			case "fence-no-release":
				fence = func(*sql.Conn, transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
					return nil, nil
				}
			}
			if _, err := keys.InstallCredential(p, origin, session, verify, fence); err == nil {
				t.Fatal("invalid authority accepted")
			}
			if kind == "fence-error" && released != 1 {
				t.Fatal("fence release missing", released)
			}
		})
	}
}

func TestManagedDirectCredentialStoreRetainedEvidence(t *testing.T) {
	for name, query := range map[string]string{
		"installation":      `UPDATE native_registry_metadata SET value='wrong' WHERE name='installation_id'`,
		"slot-installation": `UPDATE native_managed_endpoint_key_slots SET installation_id='wrong'`,
		"slot-identity":     `UPDATE native_managed_endpoint_key_slots SET identity=x'00'`,
		"slot-missing":      `DELETE FROM native_managed_endpoint_key_slots`,
		"prepare-missing":   `DELETE FROM native_managed_endpoint_prepare_commands`,
		"prepare-request":   `UPDATE native_managed_endpoint_prepare_commands SET request=x'00'`,
		"prepare-digest":    `UPDATE native_managed_endpoint_prepare_commands SET request_digest=zeroblob(32)`,
		"prepare-ack":       `UPDATE native_managed_endpoint_prepare_commands SET ack=x'00'`,
		"prepare-state":     `UPDATE native_managed_endpoint_prepare_commands SET state='reserved',ack=NULL`,
		"pop-missing":       `DELETE FROM native_managed_endpoint_pop_challenges`,
		"pop-request":       `UPDATE native_managed_endpoint_pop_challenges SET request=x'00'`,
		"pop-digest":        `UPDATE native_managed_endpoint_pop_challenges SET request_digest=zeroblob(32)`,
		"pop-proof":         `UPDATE native_managed_endpoint_pop_challenges SET proof=x'00'`,
		"pop-proof-missing": `UPDATE native_managed_endpoint_pop_challenges SET proof=NULL`,
	} {
		t.Run(name, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			if _, err := keys.registry.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err == nil {
				t.Fatal("damaged retained evidence accepted")
			}
		})
	}
}

func TestManagedDirectCredentialStoreExpiry(t *testing.T) {
	for _, point := range []string{"before-issued", "issued", "before-install", "install", "credential", "budget", "authorization"} {
		t.Run(point, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			now := p.IssuedAt
			switch point {
			case "before-issued":
				now = now.Add(-time.Nanosecond)
			case "before-install":
				now = p.InstallExpiresAt.Add(-time.Nanosecond)
			case "install":
				now = p.InstallExpiresAt
			case "credential":
				now = p.CredentialExpiresAt
			case "budget":
				now = p.Budget.ExpiresAt
			case "authorization":
				now = p.PoP.Authorization.ExpiresAt
			}
			keys.now = func() time.Time { return now }
			_, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK)
			wantOK := point == "issued" || point == "before-install"
			if (err == nil) != wantOK {
				t.Fatal("install boundary", point, err)
			}
		})
	}
	keys, p, session, _ := managedCredentialStoreFixture(t)
	installManagedCredential(t, keys, p, session)
	keys.now = func() time.Time { return p.InstallExpiresAt }
	if _, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err == nil {
		t.Fatal("installed replay accepted at installation deadline")
	}
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK); err != nil {
		t.Fatal("installation deadline invalidated installed evidence", err)
	}
	keys.now = func() time.Time { return p.CredentialExpiresAt }
	if _, err := keys.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK); err == nil {
		t.Fatal("expired credential evidence accepted")
	}
}

func TestManagedDirectCredentialStoreCrashRetry(t *testing.T) {
	for _, stage := range []string{"file", "directory"} {
		t.Run(stage, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			original := keys.sync
			crashed := false
			keys.sync = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				if !crashed && ((stage == "file" && strings.HasSuffix(f.Name(), ".pending")) || (stage == "directory" && info.IsDir())) {
					crashed = true
					return errors.New("interrupted sync")
				}
				return original(f)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err == nil || !crashed {
				t.Fatal("sync fault not reached", err)
			}
			var state string
			var hash sql.NullString
			var ack []byte
			if err := keys.registry.db.QueryRow(`SELECT state,credential_hash,ack FROM native_managed_direct_v1_credentials`).Scan(&state, &hash, &ack); err != nil || state != "attempted" || hash.Valid || ack != nil {
				t.Fatal("attempt not retained", state, err)
			}
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK); err == nil {
				t.Fatal("attempted evidence accepted")
			}
			keys.sync = original
			installManagedCredential(t, keys, p, session)
		})
	}
}

func TestManagedDirectCredentialStoreRejectsUnsafeFiles(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt", "mode", "symlink", "pending", "partial-pending"} {
		t.Run(damage, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			path := managedCredentialPath(keys, p)
			if damage != "partial-pending" {
				installManagedCredential(t, keys, p, session)
			}
			var err error
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("{}"), 0600)
			case "mode":
				err = os.Chmod(path, 0644)
			case "symlink":
				target := filepath.Join(t.TempDir(), "outside")
				if err = os.Rename(path, target); err == nil {
					err = os.Symlink(target, path)
				}
			case "pending", "partial-pending":
				err = os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("partial"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, managedCredentialFenceOK); err == nil {
				t.Fatal("unsafe file accepted")
			}
			if _, err := keys.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK); err == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}

func TestManagedDirectCredentialStoreSharedEndpointIsolation(t *testing.T) {
	keys, p, session, _ := managedCredentialStoreFixture(t)
	endpoint := managedEndpointPath(t, keys)
	ack := installManagedCredential(t, keys, p, session)
	before, err := os.ReadFile(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	pop := p.PoP
	pop.ChallengeID = domain.NewID()
	pop.Prepare.CommandID = domain.NewID()
	pop.Prepare.Subject.ID = domain.NewID()
	pop.Prepare.Subject.DirectIntentID = domain.NewID()
	pop.Authorization.DirectIntentID = pop.Prepare.Subject.DirectIntentID
	pop.AuthorizationDigest, err = pop.Authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewManagedEndpointPrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&localManagedEndpointPrepare{keys: keys, journal: journal}).execute(session, "https://example.test", pop.Prepare, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	pop.ACK, err = transport.DecodeManagedEndpointPrepareACK(raw, pop.Prepare)
	if err != nil {
		t.Fatal(err)
	}
	pop.Receipt, err = transport.NewManagedEndpointPrepareReceiptReference(pop.ACK)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _, _ := managedCredentialStoreIssue(t, keys, pop, session)
	otherACK := installManagedCredential(t, keys, other, session)
	if managedCredentialPath(keys, p) == managedCredentialPath(keys, other) || bytes.Equal(ack, otherACK) {
		t.Fatal("independent credential scopes collided")
	}
	after, err := os.ReadFile(endpoint)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("shared endpoint key replaced", err)
	}
	for table, want := range map[string]int{"native_managed_endpoint_key_slots": 1, "native_managed_endpoint_keys": 2, "native_managed_endpoint_pop_challenges": 2, "native_managed_direct_v1_credentials": 2} {
		var count int
		if err := keys.registry.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != want {
			t.Fatal(table, count, err)
		}
	}
	if err := os.Remove(managedCredentialPath(keys, other)); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.CredentialEvidence(other, "https://example.test", session, managedCredentialScopeOK); err == nil {
		t.Fatal("missing independent credential accepted")
	}
	evidence, err := keys.CredentialEvidence(p, "https://example.test", session, managedCredentialScopeOK)
	if err != nil || !bytes.Equal(evidence.ACK, ack) {
		t.Fatal("other enrollment damaged original evidence", err)
	}
}

func TestManagedDirectCredentialStorePublicationRollback(t *testing.T) {
	keys, p, session, _ := managedCredentialStoreFixture(t)
	if _, err := keys.registry.db.Exec(`CREATE TRIGGER fail_credential_install BEFORE UPDATE ON native_managed_direct_v1_credentials BEGIN SELECT RAISE(ABORT,'interrupted commit'); END`); err != nil {
		t.Fatal(err)
	}
	released := 0
	fence := func(*sql.Conn, transport.ManagedDirectCredentialIssue, string, transport.HostSessionPayload) (func(), error) {
		return func() { released++ }, nil
	}
	if _, err := keys.InstallCredential(p, "https://example.test", session, managedCredentialScopeOK, fence); err == nil {
		t.Fatal("SQL failure ignored")
	}
	if released != 1 {
		t.Fatal("rollback did not release publication fence", released)
	}
	if _, err := os.Stat(managedCredentialPath(keys, p)); err != nil {
		t.Fatal("publication window not reached", err)
	}
	var state string
	if err := keys.registry.db.QueryRow(`SELECT state FROM native_managed_direct_v1_credentials`).Scan(&state); err != nil || state != "attempted" {
		t.Fatal("publication rollback lost attempt", state, err)
	}
	if err := os.Link(managedCredentialPath(keys, p), strings.TrimSuffix(managedCredentialPath(keys, p), ".json")+".pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`DROP TRIGGER fail_credential_install`); err != nil {
		t.Fatal(err)
	}
	installManagedCredential(t, keys, p, session)
	if _, err := os.Lstat(strings.TrimSuffix(managedCredentialPath(keys, p), ".json") + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery retained pending name", err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(managedCredentialPath(keys, p), &stat); err != nil || stat.Nlink != 1 {
		t.Fatal("recovery retained extra links", err)
	}
}

func TestManagedDirectCredentialStoreInstallationGuard(t *testing.T) {
	for _, damage := range []string{"metadata-missing", "credential-installation"} {
		t.Run(damage, func(t *testing.T) {
			keys, p, session, _ := managedCredentialStoreFixture(t)
			installManagedCredential(t, keys, p, session)
			for _, table := range []string{"native_managed_endpoint_prepare_commands", "native_managed_endpoint_pop_challenges", "native_managed_endpoint_keys", "native_managed_endpoint_key_slots"} {
				if _, err := keys.registry.db.Exec("DELETE FROM " + table); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.RemoveAll(filepath.Join(keys.registry.root, nativeManagedEndpointKeyNamespace)); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(keys.registry.root, managedEndpointPrepareJournalNamespace)); err != nil {
				t.Fatal(err)
			}
			query := `DELETE FROM native_registry_metadata WHERE name='installation_id'`
			if damage == "credential-installation" {
				query = `UPDATE native_managed_direct_v1_credentials SET installation_id='wrong'`
			}
			if _, err := keys.registry.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if err := keys.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("orphaned credential permitted installation reset")
			}
		})
	}
}
