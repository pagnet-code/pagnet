//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func directSourcePoPScopeOKV2(transport.DirectManagedSourcePoPChallengeV2, string, transport.HostSessionPayload) error {
	return nil
}

func directSourcePoPKeyDigestV2(t *testing.T, keys *DirectManagedSourceKeyStoreV2) []byte {
	t.Helper()
	file, err := os.Open(directSourceKeyPathV2(t, keys))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	return hash.Sum(nil)
}

func directSourcePoPFixtureV2(t *testing.T) (*DirectManagedSourceKeyStoreV2, transport.DirectManagedSourcePoPChallengeV2, transport.HostSessionPayload, []byte) {
	t.Helper()
	keys, journal, command, session := directSourceStoreFixtureV2(t)
	grant := directSourceGrantV2(t, journal, command, session)
	reservation, err := keys.Reserve(command, "https://example.test", session, directSourceScopeOKV2, grant)
	if err != nil {
		t.Fatal(err)
	}
	ack := transport.DirectManagedSourcePrepareACKV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: command.CommandID, Reservation: reservation}
	raw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.Succeed(command, "https://example.test", session, directSourceScopeOKV2, raw); err != nil {
		t.Fatal(err)
	}
	receipt, err := transport.NewDirectManagedSourcePrepareReceiptReferenceV2(ack)
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
	p := transport.DirectManagedSourcePoPChallengeV2{ProtocolVersion: transport.DirectManagedSourcePoPProtocolV2, Suite: transport.DirectManagedSourcePoPSuiteV2, ChallengeID: domain.NewID(), Nonce: strings.Repeat("ab", 32), ServerEphemeralX25519: hex.EncodeToString(server.PublicKey().Bytes()), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Prepare: command, ACK: ack, Receipt: receipt, SourceBindingDigest: digest}
	return keys, p, session, server.Bytes()
}

func TestDirectSourceV2PoPProofReplayRestartAndInterruptedRecovery(t *testing.T) {
	keys, p, session, private := directSourcePoPFixtureV2(t)
	defer clear(private)
	// The same identities in V1 remain untouched by V2 custody.
	sentinel := []byte("v1 retained proof")
	if _, err := keys.registry.db.Exec(`INSERT INTO native_direct_managed_source_pop_challenges(challenge_id,binding_id,direct_intent_id,installation_id,request,request_digest,proof) VALUES(?,?,?,?,?,?,?)`, p.ChallengeID, p.Prepare.Subject.ID, p.Prepare.Subject.DirectIntentID, keys.installation, []byte("v1 request"), make([]byte, 32), sentinel); err != nil {
		t.Fatal(err)
	}
	proof, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2)
	if err != nil {
		t.Fatal(err)
	}
	decoded, got, err := transport.DecodeDirectManagedSourcePoPProofVerifierV2(proof)
	transcript, want, deriveErr := transport.DeriveDirectManagedSourcePoPVerifierV2(p, private, p.IssuedAt)
	if err != nil || deriveErr != nil || got != want || decoded.TranscriptHash != transcript || decoded.ProtocolVersion != transport.DirectManagedSourcePoPProtocolV2 || decoded.ChallengeID != p.ChallengeID {
		t.Fatal("invalid V2 custody proof", err, deriveErr)
	}
	if _, _, err := transport.DecodeDirectManagedSourcePoPProofVerifier(proof); err == nil {
		t.Fatal("V2 proof accepted in V1 domain")
	}
	for _, interrupted := range []bool{false, true} {
		if interrupted {
			if _, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof=NULL,proof_digest=NULL WHERE challenge_id=?`, p.ChallengeID); err != nil {
				t.Fatal(err)
			}
		}
		registry, err := OpenNativeWorkerRegistry(filepath.Dir(keys.registry.root))
		if err != nil {
			t.Fatal(err)
		}
		reopened, err := NewDirectManagedSourceKeyStoreV2(registry)
		if err != nil {
			registry.Close()
			t.Fatal(err)
		}
		replay, err := reopened.ConfirmPoP(p, "https://EXAMPLE.TEST///", session, directSourcePoPScopeOKV2)
		registry.Close()
		if err != nil || !bytes.Equal(replay, proof) {
			t.Fatal("restart or interrupted recovery changed proof", interrupted, err)
		}
	}
	var retained, request, digest, legacy []byte
	var proofDigest string
	if err := keys.registry.db.QueryRow(`SELECT request,request_digest,proof,proof_digest FROM native_direct_managed_source_v2_pop_challenges WHERE challenge_id=?`, p.ChallengeID).Scan(&request, &digest, &retained, &proofDigest); err != nil {
		t.Fatal(err)
	}
	raw, _ := p.CanonicalBytes()
	hash := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v2/"), raw...))
	receipt, err := transport.NewDirectManagedSourceCredentialPoPReceiptV2(decoded)
	if err != nil || proofDigest != receipt.ProofDigest {
		t.Fatal("retained proof digest lost V2 domain", err)
	}
	if !bytes.Equal(request, raw) || !bytes.Equal(digest, hash[:]) || !bytes.Equal(retained, proof) {
		t.Fatal("retained V2 association changed")
	}
	if err := keys.registry.db.QueryRow(`SELECT proof FROM native_direct_managed_source_pop_challenges WHERE challenge_id=?`, p.ChallengeID).Scan(&legacy); err != nil || !bytes.Equal(legacy, sentinel) {
		t.Fatal("V2 changed V1 proof", err)
	}
}

func TestDirectSourceV2PoPRejectsMismatchedEvidence(t *testing.T) {
	for _, failure := range []string{"protocol", "subject", "origin", "ack", "session", "installation", "prepare", "proof", "proof-digest", "request-digest", "scope", "nil-scope", "challenge-reuse", "generation", "predecessor", "previous-credential"} {
		t.Run(failure, func(t *testing.T) {
			keys, p, session, private := directSourcePoPFixtureV2(t)
			clear(private)
			server := "https://example.test"
			verify := DirectManagedSourcePoPScopeCheckV2(directSourcePoPScopeOKV2)
			var err error
			switch failure {
			case "protocol":
				p.ProtocolVersion = transport.DirectManagedSourcePoPProtocol
			case "subject":
				p.Prepare.Subject.InstanceID = domain.NewID()
			case "generation":
				p.Prepare.Subject.BindingGeneration = "2"
				p.Prepare.Subject.PredecessorBindingID = domain.NewID()
				p.Prepare.Subject.PreviousCredentialID = domain.NewID()
				p.ACK.Reservation.Subject = p.Prepare.Subject
				p.ACK.Reservation.EnrollmentDigest, err = p.ACK.Reservation.Digest()
				if err != nil {
					t.Fatal(err)
				}
				p.Receipt, err = transport.NewDirectManagedSourcePrepareReceiptReferenceV2(p.ACK)
				if err != nil {
					t.Fatal(err)
				}
				p.SourceBindingDigest, err = p.Prepare.Subject.Digest()
				if _, canonicalErr := p.CanonicalBytes(); canonicalErr != nil {
					t.Fatal("generation-2 challenge must be valid transport evidence", canonicalErr)
				}
			case "predecessor":
				p.Prepare.Subject.PredecessorBindingID = domain.NewID()
			case "previous-credential":
				p.Prepare.Subject.PreviousCredentialID = domain.NewID()
			case "origin":
				server = "https://other.test"
			case "ack":
				p.ACK.CommandID = domain.NewID()
			case "session":
				session.HostCredentialID = domain.NewID().String()
			case "installation":
				_, err = keys.registry.db.Exec(`UPDATE native_registry_metadata SET value=? WHERE name='installation_id'`, domain.NewID())
			case "prepare":
				_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_prepare_commands SET ack=x'00'`)
			case "proof", "proof-digest", "request-digest", "challenge-reuse":
				if _, err = keys.ConfirmPoP(p, server, session, verify); err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "proof":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof=x'00'`)
				case "proof-digest":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof_digest=?`, strings.Repeat("00", 32))
				case "request-digest":
					_, err = keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET request_digest=zeroblob(32)`)
				case "challenge-reuse":
					p.Nonce = strings.Repeat("cd", 32)
				}
			case "scope":
				verify = func(transport.DirectManagedSourcePoPChallengeV2, string, transport.HostSessionPayload) error {
					return errors.New("stale authority")
				}
			case "nil-scope":
				verify = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.ConfirmPoP(p, server, session, verify); err == nil {
				t.Fatal("mismatched evidence accepted")
			}
		})
	}
}

func TestDirectSourceV2PoPInterruptedBeforeDerivation(t *testing.T) {
	keys, p, session, private := directSourcePoPFixtureV2(t)
	clear(private)
	before := directSourcePoPKeyDigestV2(t, keys)
	interrupted := errors.New("interrupted after association")
	checks := 0
	verify := func(transport.DirectManagedSourcePoPChallengeV2, string, transport.HostSessionPayload) error {
		checks++
		if checks == 2 {
			return interrupted
		}
		return nil
	}
	if _, err := keys.ConfirmPoP(p, "https://example.test", session, verify); !errors.Is(err, interrupted) {
		t.Fatal("interruption was not returned", err)
	}
	var pending bool
	if err := keys.registry.db.QueryRow(`SELECT proof IS NULL AND proof_digest IS NULL FROM native_direct_managed_source_v2_pop_challenges WHERE challenge_id=?`, p.ChallengeID).Scan(&pending); err != nil || !pending {
		t.Fatal("interruption did not retain an unfinished association", err)
	}
	if _, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2); err != nil {
		t.Fatal("unfinished association did not recover", err)
	}
	if !bytes.Equal(before, directSourcePoPKeyDigestV2(t, keys)) {
		t.Fatal("interrupted proof replaced retained key")
	}
}

func TestDirectSourceV2PoPMissingOrChangedKeyNeverRegenerates(t *testing.T) {
	for _, failure := range []string{"missing", "changed"} {
		for _, interrupted := range []bool{false, true} {
			t.Run(failure+"/"+map[bool]string{false: "new", true: "interrupted"}[interrupted], func(t *testing.T) {
				keys, p, session, private := directSourcePoPFixtureV2(t)
				clear(private)
				if interrupted {
					if _, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2); err != nil {
						t.Fatal(err)
					}
					if _, err := keys.registry.db.Exec(`UPDATE native_direct_managed_source_v2_pop_challenges SET proof=NULL,proof_digest=NULL`); err != nil {
						t.Fatal(err)
					}
				}
				path := directSourceKeyPathV2(t, keys)
				var err error
				if failure == "missing" {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, []byte("{}"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				random := &managedEndpointRecoveryRandomReader{}
				original := rand.Reader
				rand.Reader = random
				defer func() { rand.Reader = original }()
				if _, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2); err == nil {
					t.Fatal("lost custody accepted")
				}
				if random.reads != 0 {
					t.Fatal("proof recovery generated randomness")
				}
				if failure == "missing" {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("missing key regenerated", err)
					}
				} else if raw, err := os.ReadFile(path); err != nil || string(raw) != "{}" {
					t.Fatal("changed key replaced", err)
				}
			})
		}
	}
}

func TestDirectSourceV2PoPTimeBoundsAndRetainedProof(t *testing.T) {
	for _, boundary := range []string{"before-issued", "issued", "before-expiry", "expiry"} {
		t.Run(boundary, func(t *testing.T) {
			keys, p, session, private := directSourcePoPFixtureV2(t)
			clear(private)
			now := p.IssuedAt
			switch boundary {
			case "before-issued":
				now = now.Add(-time.Nanosecond)
			case "before-expiry":
				now = p.ExpiresAt.Add(-time.Nanosecond)
			case "expiry":
				now = p.ExpiresAt
			}
			keys.now = func() time.Time { return now }
			_, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2)
			wantSuccess := boundary == "issued" || boundary == "before-expiry"
			if (err == nil) != wantSuccess {
				t.Fatal("incorrect challenge time boundary", err)
			}
		})
	}
	keys, p, session, private := directSourcePoPFixtureV2(t)
	clear(private)
	keyDigest := directSourcePoPKeyDigestV2(t, keys)
	proof, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2)
	if err != nil {
		t.Fatal(err)
	}
	keys.now = func() time.Time { return p.ExpiresAt }
	if _, err := keys.ConfirmPoP(p, "https://example.test", session, directSourcePoPScopeOKV2); err == nil {
		t.Fatal("expired successful challenge replayed")
	}
	var retained []byte
	if err := keys.registry.db.QueryRow(`SELECT proof FROM native_direct_managed_source_v2_pop_challenges WHERE challenge_id=?`, p.ChallengeID).Scan(&retained); err != nil || !bytes.Equal(proof, retained) {
		t.Fatal("expiry discarded credential installation evidence", err)
	}
	if !bytes.Equal(keyDigest, directSourcePoPKeyDigestV2(t, keys)) {
		t.Fatal("expiry changed retained key")
	}
}
