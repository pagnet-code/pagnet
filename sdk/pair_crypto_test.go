package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

func pairCryptoFixture(t *testing.T) (pairDescriptor, []byte, []byte, []byte, time.Time) {
	t.Helper()
	issuer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	d := pairDescriptor{Version: 1, Suite: pairSuite, GrantID: "grant", Generation: 1, InvitationID: "invitation", NetworkID: "network", OwningTenantID: "issuer-tenant", IssuerTenantID: "issuer-tenant", IssuerPrincipalID: "issuer", RecipientTenantID: "recipient-tenant", RecipientPrincipalID: "recipient", IssuerPublicKey: base64.RawURLEncoding.EncodeToString(issuer.PublicKey().Bytes()), RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipient.PublicKey().Bytes()), EpochID: epoch.String(), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Permissions: []string{"communicate"}, Limits: pairLimits{1024, 1, 10, 10240, 1, 8}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, raw, issuer.Bytes(), recipient.Bytes(), now
}

func pairChallenge(t *testing.T, d pairDescriptor, raw []byte, actor pairProofActor, now time.Time) pairProofChallenge {
	t.Helper()
	hash := sha256.Sum256(raw)
	transcript := pairProofTranscript{Domain: "pagnet/sdk-pair/proof/v1", ChallengeID: "challenge", Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), GrantID: d.GrantID, Generation: d.Generation, DescriptorHash: base64.RawURLEncoding.EncodeToString(hash[:]), EpochID: d.EpochID, PrincipalID: actor.PrincipalID, EndpointID: actor.EndpointID, CredentialID: actor.CredentialID}
	b, err := json.Marshal(transcript)
	if err != nil {
		t.Fatal(err)
	}
	return pairProofChallenge{"challenge", b, now.Add(time.Minute)}
}

func TestPairCryptoRestartRetryAndReadiness(t *testing.T) {
	d, raw, issuerPrivate, recipientPrivate, now := pairCryptoFixture(t)
	issuerDir, recipientDir := t.TempDir(), t.TempDir()
	issuer, err := newKeyring(issuerDir)
	if err != nil {
		t.Fatal(err)
	}
	epochKey := bytes.Repeat([]byte{4}, 32)
	first, err := issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, epochKey, now)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := issuer.loadPendingPairEpoch(d.GrantID, uint64(d.Generation))
	if err != nil {
		t.Fatal(err)
	}
	publication, _ := json.Marshal(first.Package)
	if !bytes.Equal(pending.Publication, publication) || !bytes.Equal(pending.EpochKey, epochKey) {
		t.Fatal("returned material differs from durable record")
	}
	issuer, err = newKeyring(issuerDir)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, bytes.Repeat([]byte{9}, 32), now)
	if err != nil || !reflect.DeepEqual(first, retry) {
		t.Fatalf("retry changed package: %v", err)
	}
	recipient, err := newKeyring(recipientDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipient.prepareRecipientPairEpoch(raw, d, recipientPrivate, first.Package.Enc, first.Package.Ciphertext, now); err != nil {
		t.Fatal(err)
	}
	recipient, err = newKeyring(recipientDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipient.prepareRecipientPairEpoch(raw, d, recipientPrivate, first.Package.Enc, first.Package.Ciphertext, now); err != nil {
		t.Fatal("recipient retry:", err)
	}
	for _, k := range []*keyring{issuer, recipient} {
		if _, _, err := k.ActiveEpoch(d.NetworkID); err == nil {
			t.Fatal("pending key became active")
		}
	}
	for _, test := range []struct {
		k         *keyring
		principal string
	}{{issuer, d.IssuerPrincipalID}, {recipient, d.RecipientPrincipalID}} {
		actor := pairProofActor{test.principal, "endpoint", "credential"}
		challenge := pairChallenge(t, d, raw, actor, now)
		proof, err := test.k.pendingPairReadinessProof(d, challenge, actor, now)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, first.ReadinessVerifier)
		mac.Write(challenge.Transcript)
		if !hmac.Equal(proof, mac.Sum(nil)) {
			t.Fatal("proof does not MAC exact transcript")
		}
	}
}

func TestPairDescriptorValidation(t *testing.T) {
	d, raw, _, _, now := pairCryptoFixture(t)
	mutations := map[string]func(*pairDescriptor){
		"version": func(p *pairDescriptor) { p.Version++ }, "suite": func(p *pairDescriptor) { p.Suite = "other" }, "grant": func(p *pairDescriptor) { p.GrantID = "other" }, "generation": func(p *pairDescriptor) { p.Generation++ }, "invitation": func(p *pairDescriptor) { p.InvitationID = "other" }, "network": func(p *pairDescriptor) { p.NetworkID = "other" }, "owner": func(p *pairDescriptor) { p.OwningTenantID = "other" }, "issuer tenant": func(p *pairDescriptor) { p.IssuerTenantID = "other" }, "issuer": func(p *pairDescriptor) { p.IssuerPrincipalID = "other" }, "recipient tenant": func(p *pairDescriptor) { p.RecipientTenantID = "other" }, "recipient": func(p *pairDescriptor) { p.RecipientPrincipalID = "other" }, "issuer key": func(p *pairDescriptor) { p.IssuerPublicKey = p.RecipientPublicKey }, "recipient key": func(p *pairDescriptor) { p.RecipientPublicKey = p.IssuerPublicKey }, "epoch": func(p *pairDescriptor) { p.EpochID = uuid.NewString() }, "expiry": func(p *pairDescriptor) { p.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339Nano) }, "permissions": func(p *pairDescriptor) { p.Permissions = []string{"read"} }, "wire bytes": func(p *pairDescriptor) { p.Limits.MaxMessageWireBytes++ }, "minute": func(p *pairDescriptor) { p.Limits.MaxMessagesPerMinute++ }, "day": func(p *pairDescriptor) { p.Limits.MaxMessagesPerDay++ }, "bytes day": func(p *pairDescriptor) { p.Limits.MaxWireBytesPerDay++ }, "inflight": func(p *pairDescriptor) { p.Limits.MaxInFlight++ }, "turns": func(p *pairDescriptor) { p.Limits.MaxTurnsPerThread++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := d
			mutate(&changed)
			b, _ := json.Marshal(changed)
			if _, _, _, err := validatePairDescriptor(b, d, now); err == nil {
				t.Fatal("accepted changed binding")
			}
		})
	}
	for name, b := range map[string][]byte{"whitespace": append([]byte(" "), raw...), "unknown field": []byte(strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`), "duplicate field": []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)), "reordered": []byte(strings.Replace(string(raw), `{"version":1,"suite":"`+pairSuite+`"`, `{"suite":"`+pairSuite+`","version":1`, 1))} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := validatePairDescriptor(b, d, now); err == nil {
				t.Fatal("accepted noncanonical descriptor")
			}
		})
	}
	// Even a matching snapshot cannot authorize unsupported protocol values.
	for name, mutate := range map[string]func(*pairDescriptor){"version": mutations["version"], "suite": mutations["suite"], "expiry": mutations["expiry"], "epoch": mutations["epoch"], "zero generation": func(p *pairDescriptor) { p.Generation = 0 }, "short key": func(p *pairDescriptor) { p.IssuerPublicKey = "AA" }, "limit": func(p *pairDescriptor) { p.Limits.MaxInFlight = 3 }} {
		t.Run("intrinsic "+name, func(t *testing.T) {
			changed := d
			mutate(&changed)
			b, _ := json.Marshal(changed)
			if _, _, _, err := validatePairDescriptor(b, changed, now); err == nil {
				t.Fatal("accepted invalid protocol value")
			}
		})
	}
}

func TestPairCryptoRejectsWrongKeysAndTampering(t *testing.T) {
	d, raw, issuerPrivate, recipientPrivate, now := pairCryptoFixture(t)
	issuer := newTestKeyring(t)
	epochKey := bytes.Repeat([]byte{4}, 32)
	if _, err := issuer.prepareIssuerPairEpoch(raw, d, recipientPrivate, epochKey, now); err == nil {
		t.Fatal("accepted wrong issuer private key")
	}
	if _, err := issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, epochKey[:31], now); err == nil {
		t.Fatal("accepted short epoch key")
	}
	material, err := issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, epochKey, now)
	if err != nil {
		t.Fatal(err)
	}
	recipient := newTestKeyring(t)
	if err := recipient.prepareRecipientPairEpoch(raw, d, issuerPrivate, material.Package.Enc, material.Package.Ciphertext, now); err == nil {
		t.Fatal("accepted wrong recipient private key")
	}
	tampered := append([]byte(nil), material.Package.Ciphertext...)
	tampered[0] ^= 1
	if err := recipient.prepareRecipientPairEpoch(raw, d, recipientPrivate, material.Package.Enc, tampered, now); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	recipientPub, _ := pairKey(d.RecipientPublicKey)
	hash := sha256.Sum256(raw)
	enc, ct, err := e2ee.HPKEWrapAuth(recipientPub, recipientPrivate, []byte("pagnet/sdk-pair/epoch-wrap/v1"), hash[:], epochKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipient.prepareRecipientPairEpoch(raw, d, recipientPrivate, enc, ct, now); err == nil {
		t.Fatal("accepted package authenticated by wrong issuer")
	}
	if _, err := recipient.loadPendingPairEpoch(d.GrantID, uint64(d.Generation)); err == nil {
		t.Fatal("failed unwrap persisted key")
	}
}

func TestPairProofRejectsChangedChallenge(t *testing.T) {
	d, raw, issuerPrivate, _, now := pairCryptoFixture(t)
	k := newTestKeyring(t)
	if _, err := k.prepareIssuerPairEpoch(raw, d, issuerPrivate, bytes.Repeat([]byte{4}, 32), now); err != nil {
		t.Fatal(err)
	}
	actor := pairProofActor{d.IssuerPrincipalID, "endpoint", "credential"}
	challenge := pairChallenge(t, d, raw, actor, now)
	for name, mutate := range map[string]func(*pairProofTranscript){"domain": func(p *pairProofTranscript) { p.Domain = "other" }, "challenge": func(p *pairProofTranscript) { p.ChallengeID = "other" }, "nonce": func(p *pairProofTranscript) { p.Nonce = "AA" }, "grant": func(p *pairProofTranscript) { p.GrantID = "other" }, "generation": func(p *pairProofTranscript) { p.Generation++ }, "hash": func(p *pairProofTranscript) { p.DescriptorHash = "other" }, "epoch": func(p *pairProofTranscript) { p.EpochID = "other" }, "principal": func(p *pairProofTranscript) { p.PrincipalID = "other" }, "endpoint": func(p *pairProofTranscript) { p.EndpointID = "other" }, "credential": func(p *pairProofTranscript) { p.CredentialID = "other" }} {
		t.Run(name, func(t *testing.T) {
			var transcript pairProofTranscript
			json.Unmarshal(challenge.Transcript, &transcript)
			mutate(&transcript)
			changed := challenge
			changed.Transcript, _ = json.Marshal(transcript)
			if _, err := k.pendingPairReadinessProof(d, changed, actor, now); err == nil {
				t.Fatal("accepted changed transcript")
			}
		})
	}
	expired := challenge
	expired.ExpiresAt = now
	if _, err := k.pendingPairReadinessProof(d, expired, actor, now); err == nil {
		t.Fatal("accepted expired challenge")
	}
	noncanonical := challenge
	noncanonical.Transcript = append([]byte(" "), challenge.Transcript...)
	if _, err := k.pendingPairReadinessProof(d, noncanonical, actor, now); err == nil {
		t.Fatal("accepted noncanonical transcript")
	}
}

func TestPairCryptoStorageFailureReturnsNoMaterial(t *testing.T) {
	d, raw, issuerPrivate, recipientPrivate, now := pairCryptoFixture(t)
	issuer := newTestKeyring(t)
	issuer.pendingPairSyncDir = func(string) error { return errorsForPairTest{} }
	material, err := issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, bytes.Repeat([]byte{4}, 32), now)
	if err == nil || !reflect.DeepEqual(material, pairIssuerMaterial{}) {
		t.Fatal("returned upload material before durable storage")
	}
	issuer = newTestKeyring(t)
	material, err = issuer.prepareIssuerPairEpoch(raw, d, issuerPrivate, bytes.Repeat([]byte{4}, 32), now)
	if err != nil {
		t.Fatal(err)
	}
	recipient := newTestKeyring(t)
	recipient.pendingPairSyncDir = func(string) error { return errorsForPairTest{} }
	if err := recipient.prepareRecipientPairEpoch(raw, d, recipientPrivate, material.Package.Enc, material.Package.Ciphertext, now); err == nil {
		t.Fatal("recipient reported readiness before durable storage")
	}
}

type errorsForPairTest struct{}

func (errorsForPairTest) Error() string { return "injected storage failure" }
