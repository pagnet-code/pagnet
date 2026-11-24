//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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

func managedPoPStoreFixture(t *testing.T, legacy bool) (*ManagedEndpointKeyStore, transport.ManagedEndpointPoPChallenge, transport.HostSessionPayload, []byte) {
	t.Helper()
	keys, subject, session := managedEndpointFixture(t)
	if legacy {
		keys, subject, session, _, _ = legacyManagedEndpointFixture(t, false)
		if err := keys.registry.initSourceHolderInstallation(); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := NewManagedEndpointPrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	command := transport.ManagedEndpointPrepareCommand{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: domain.NewID(), Subject: subject}
	ackRaw, err := (&localManagedEndpointPrepare{keys: keys, journal: journal}).execute(session, "https://example.test", command, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := transport.DecodeManagedEndpointPrepareACK(ackRaw, command)
	if err != nil {
		t.Fatal(err)
	}
	var authorization transport.DirectAuthorizationSnapshotV1
	raw, err := os.ReadFile("../../transport/testdata/managed_endpoint_pop_v1/authorization.json")
	if err != nil || json.Unmarshal(raw, &authorization) != nil {
		t.Fatal("authorization fixture", err)
	}
	issued := time.Now().UTC()
	authorization.DirectIntentID = subject.DirectIntentID
	authorization.InviteeTenantID = subject.TenantID
	authorization.InviteeAccountID = subject.AccountID
	authorization.Target.PrincipalID = subject.PrincipalID
	authorization.CreatedAt = subject.CreatedAt
	authorization.ExpiresAt = subject.ExpiresAt
	authorization.GrantExpiresAt = subject.ExpiresAt.Add(time.Hour)
	digest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := transport.NewManagedEndpointPrepareReceiptReference(ack)
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := transport.ManagedEndpointPoPChallenge{ProtocolVersion: transport.ManagedEndpointPoPProtocol, Suite: transport.ManagedEndpointPoPSuite, ChallengeID: domain.NewID(), Nonce: strings.Repeat("ab", 32), ServerEphemeralX25519: hex.EncodeToString(server.PublicKey().Bytes()), IssuedAt: issued, ExpiresAt: issued.Add(time.Minute), Prepare: command, ACK: ack, Receipt: receipt, Authorization: authorization, AuthorizationDigest: digest}
	if _, err := p.CanonicalBytes(); err != nil {
		t.Fatal(err)
	}
	return keys, p, session, server.Bytes()
}

func TestManagedPoPStoreProofAndRestart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "slot-v2", true: "legacy-v1"}[legacy], func(t *testing.T) {
			keys, p, session, private := managedPoPStoreFixture(t, legacy)
			defer clear(private)
			before, err := os.ReadFile(managedEndpointPath(t, keys))
			if err != nil {
				t.Fatal(err)
			}
			proof, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK)
			if err != nil {
				t.Fatal(err)
			}
			_, got, err := transport.DecodeManagedEndpointPoPProofVerifier(proof)
			_, want, deriveErr := transport.DeriveManagedEndpointPoPVerifier(p, private, time.Now())
			if err != nil || deriveErr != nil || got != want {
				t.Fatal("proof mismatch", err, deriveErr)
			}
			r, err := OpenNativeWorkerRegistry(filepath.Dir(keys.registry.root))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			reopened, err := NewManagedEndpointKeyStore(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, store := range []*ManagedEndpointKeyStore{keys, reopened} {
				replay, err := store.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK)
				if err != nil || !bytes.Equal(proof, replay) {
					t.Fatal("changed retry", err)
				}
			}
			after, err := os.ReadFile(managedEndpointPath(t, keys))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("key changed", err)
			}
			for _, table := range []string{"native_managed_endpoint_keys", "native_managed_endpoint_key_slots", "native_managed_endpoint_pop_challenges"} {
				var count int
				if err := r.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
					t.Fatal(table, count, err)
				}
			}
		})
	}
}

func TestManagedPoPStoreRejectsRetainedDamage(t *testing.T) {
	for name, query := range map[string]string{
		"installation":      `UPDATE native_registry_metadata SET value='wrong' WHERE name='installation_id'`,
		"slot-installation": `UPDATE native_managed_endpoint_key_slots SET installation_id='wrong'`,
		"slot-identity":     `UPDATE native_managed_endpoint_key_slots SET identity=x'00'`,
		"slot-key":          `UPDATE native_managed_endpoint_key_slots SET x25519='wrong'`,
		"missing-slot":      `DELETE FROM native_managed_endpoint_key_slots`,
		"missing-ref":       `DELETE FROM native_managed_endpoint_keys`,
		"interrupted-ref":   `UPDATE native_managed_endpoint_keys SET reservation=NULL`,
		"missing-prepare":   `DELETE FROM native_managed_endpoint_prepare_commands`,
		"prepare-request":   `UPDATE native_managed_endpoint_prepare_commands SET request=x'00'`,
		"prepare-digest":    `UPDATE native_managed_endpoint_prepare_commands SET request_digest=zeroblob(32)`,
		"prepare-ack":       `UPDATE native_managed_endpoint_prepare_commands SET ack=x'00'`,
		"prepare-reserved":  `UPDATE native_managed_endpoint_prepare_commands SET state='reserved',ack=NULL`,
	} {
		t.Run(name, func(t *testing.T) {
			keys, p, session, private := managedPoPStoreFixture(t, false)
			clear(private)
			if _, err := keys.registry.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK); err == nil {
				t.Fatal("damaged evidence accepted")
			}
		})
	}
	for _, damage := range []string{"missing", "corrupt", "pending"} {
		t.Run(damage, func(t *testing.T) {
			keys, p, session, private := managedPoPStoreFixture(t, false)
			clear(private)
			path := managedEndpointPath(t, keys)
			var err error
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("{}"), 0600)
			case "pending":
				err = os.WriteFile(strings.TrimSuffix(path, ".json")+".pending", []byte("uncertain"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK); err == nil {
				t.Fatal("damaged file accepted")
			}
		})
	}
}

func TestManagedPoPStoreChallengeAssociation(t *testing.T) {
	keys, p, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	proof, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"nonce", "challenge-id", "digest", "request", "proof"} {
		t.Run(change, func(t *testing.T) {
			changed := p
			switch change {
			case "nonce":
				changed.Nonce = strings.Repeat("cd", 32)
			case "challenge-id":
				changed.ChallengeID = domain.NewID()
			case "digest":
				_, err = keys.registry.db.Exec(`UPDATE native_managed_endpoint_pop_challenges SET request_digest=zeroblob(32)`)
			case "request":
				_, err = keys.registry.db.Exec(`UPDATE native_managed_endpoint_pop_challenges SET request=x'00'`)
			case "proof":
				_, err = keys.registry.db.Exec(`UPDATE native_managed_endpoint_pop_challenges SET proof=x'00'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.confirmPoP(changed, "https://example.test", session, managedPrepareScopeOK); err == nil {
				t.Fatal("changed association accepted")
			}
			raw, _ := p.CanonicalBytes()
			hash := sha256.Sum256(raw)
			if _, err = keys.registry.db.Exec(`UPDATE native_managed_endpoint_pop_challenges SET request=?,request_digest=?,proof=?`, raw, hash[:], proof); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err = keys.registry.db.Exec(`UPDATE native_managed_endpoint_pop_challenges SET proof=NULL`); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewManagedEndpointKeyStore(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK)
	if err != nil || !bytes.Equal(proof, retry) {
		t.Fatal("interrupted association failed recovery", err)
	}
}

func TestManagedPoPStoreAuthorityChecks(t *testing.T) {
	keys, p, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	for _, stage := range []int{1, 2, 3} {
		calls := 0
		_, err := keys.confirmPoP(p, "https://example.test", session, func(transport.ManagedEndpointPrepareCommand, string) error {
			// Acquiring the registry here also proves verification runs unlocked.
			keys.registry.mu.Lock()
			keys.registry.mu.Unlock()
			calls++
			if calls == stage {
				return errors.New("stale worker or session")
			}
			return nil
		})
		if err == nil || calls != stage {
			t.Fatal("missing authority check", stage, calls, err)
		}
	}
	wrong := session
	wrong.HostID = domain.NewID().String()
	if _, err := keys.confirmPoP(p, "https://example.test", wrong, managedPrepareScopeOK); err == nil {
		t.Fatal("wrong session accepted")
	}
	if _, err := keys.confirmPoP(p, "https://other.test", session, managedPrepareScopeOK); err == nil {
		t.Fatal("wrong origin accepted")
	}
	if _, err := keys.ConfirmPoP(context.Background(), &Daemon{Config: Config{ServerURL: "https://other.test"}, nativeRegistry: keys.registry}, ManagedEndpointPrepareScope{Session: session}, "https://example.test", p); err == nil {
		t.Fatal("spoofed configured origin accepted")
	}
	keys.now = func() time.Time { return p.ExpiresAt }
	if _, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestManagedPoPStoreConcurrentRetry(t *testing.T) {
	keys, p, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	var wg sync.WaitGroup
	proofs := make([][]byte, 8)
	errs := make([]error, 8)
	for i := range proofs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			proofs[i], errs[i] = keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK)
		}(i)
	}
	wg.Wait()
	for i := range proofs {
		if errs[i] != nil || !bytes.Equal(proofs[0], proofs[i]) {
			t.Fatal("concurrent retry", errs[i])
		}
	}
}

func TestManagedPoPStoreDirectIntentFence(t *testing.T) {
	keys, p, session, private := managedPoPStoreFixture(t, false)
	clear(private)
	if _, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	// A second enrollment may share this endpoint key, but cannot replace the
	// challenge already retained for its direct intent.
	p.ChallengeID = domain.NewID()
	p.Prepare.CommandID = domain.NewID()
	p.Prepare.Subject.ID = domain.NewID()
	j, err := NewManagedEndpointPrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&localManagedEndpointPrepare{keys: keys, journal: j}).execute(session, "https://example.test", p.Prepare, managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	p.ACK, err = transport.DecodeManagedEndpointPrepareACK(raw, p.Prepare)
	if err != nil {
		t.Fatal(err)
	}
	p.Receipt, err = transport.NewManagedEndpointPrepareReceiptReference(p.ACK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.confirmPoP(p, "https://example.test", session, managedPrepareScopeOK); err == nil {
		t.Fatal("second challenge for direct intent accepted")
	}
	var count int
	if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_managed_endpoint_pop_challenges`).Scan(&count); err != nil || count != 1 {
		t.Fatal("changed direct intent association", count, err)
	}
}
