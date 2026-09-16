package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// testKeyID is a keyId distinct from the pinned KeyID, used to exercise the
// key-parameterized verification core with a throwaway keypair.
const testKeyID = "test-key"

// signTestManifest builds a manifest, signs it with a fresh throwaway
// Ed25519 key, and returns the manifest + the public key (so the test can
// verify with the matching key via verifyManifestWithKey).
func signTestManifest(t *testing.T) (*Manifest, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Version: "v1.2.3",
		Created: "2026-09-16T00:00:00Z",
		Assets:  []Asset{{Name: "pagnet-v1.2.3-linux-amd64.tar.gz", SHA256: "deadbeef"}},
	}
	// Sign with the test key: replicate SignManifest but stamp the test
	// keyId (SignManifest stamps the pinned KeyID).
	canon, err := CanonicalJSON(*m)
	if err != nil {
		t.Fatal(err)
	}
	m.KeyID = testKeyID
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	return m, pub
}

// A correctly-signed manifest verifies under its own key.
func TestVerifyManifest_Valid(t *testing.T) {
	m, pub := signTestManifest(t)
	if err := verifyManifestWithKey(m, pub, testKeyID); err != nil {
		t.Fatalf("a correctly-signed manifest must verify: %v", err)
	}
}

// A tampered signature (or a signature over different bytes) must fail.
func TestVerifyManifest_BadSignature(t *testing.T) {
	m, pub := signTestManifest(t)
	// Flip a byte in the signature.
	sig, _ := base64.StdEncoding.DecodeString(m.Signature)
	sig[0] ^= 0xff
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	if err := verifyManifestWithKey(m, pub, testKeyID); err == nil {
		t.Fatal("a tampered signature must not verify")
	}

	// A signature over different content (the asset hash changed after
	// signing) must also fail.
	m2, pub2 := signTestManifest(t)
	m2.Assets[0].SHA256 = "cafebabe"
	if err := verifyManifestWithKey(m2, pub2, testKeyID); err == nil {
		t.Fatal("a signature over different content must not verify")
	}
}

// A manifest whose keyId does not match the expected key is refused even
// if the signature would otherwise verify.
func TestVerifyManifest_WrongKeyID(t *testing.T) {
	m, pub := signTestManifest(t)
	// Verify against a DIFFERENT expected keyId: the keyId check must fail
	// before the signature is even considered.
	if err := verifyManifestWithKey(m, pub, "some-other-key"); err == nil {
		t.Fatal("a mismatched keyId must be refused")
	}
}

// VerifyAsset: a matching sha256 passes; a mismatch or a missing asset
// fails.
func TestManifestVerifyAsset(t *testing.T) {
	m := &Manifest{Assets: []Asset{{Name: "x.tar.gz", SHA256: "cf2c48145dcaa488ca59ee1ec43a08ce66d56b48bd007fc7ece0d8a6049091d9"}}}
	// The fixture content hashes to the listed sha256.
	if err := m.VerifyAsset("x.tar.gz", []byte("pagnet-test-tarball-bytes")); err != nil {
		t.Fatalf("matching sha256 must pass: %v", err)
	}
	if err := m.VerifyAsset("x.tar.gz", []byte("tampered")); err == nil {
		t.Fatal("a sha256 mismatch must fail")
	}
	if err := m.VerifyAsset("missing.tar.gz", []byte("whatever")); err == nil {
		t.Fatal("an asset not listed in the manifest must fail")
	}
}

// CanonicalJSON is stable across formatting: the same data marshaled with
// different key order / whitespace canonicalizes to the same bytes. This
// is what lets a pretty-printed manifest file verify against a signature
// made over compact bytes.
func TestCanonicalJSON_StableAcrossFormatting(t *testing.T) {
	a := Manifest{Version: "v1.2.3", Created: "2026-09-16T00:00:00Z",
		Assets: []Asset{{Name: "n", SHA256: "s"}}, KeyID: KeyID, Signature: "sig"}
	b := a
	// Re-parse a pretty-printed, differently-key-ordered form.
	pretty := `{"signature":"sig","assets":[{"sha256":"s","name":"n"}],"keyId":"` + KeyID + `","version":"v1.2.3","created":"2026-09-16T00:00:00Z"}`
	var reparsed Manifest
	if err := json.Unmarshal([]byte(pretty), &reparsed); err != nil {
		t.Fatal(err)
	}
	b = reparsed
	ca, err := CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("canonical bytes differ across formatting:\n%s\n%s", ca, cb)
	}
	// The signature/keyId fields must be absent from the canonical form.
	if strings.Contains(string(ca), "signature") || strings.Contains(string(ca), "keyId") {
		t.Fatalf("canonical form must omit signature/keyId: %s", ca)
	}
}

// The PINNED public key must verify a manifest signed by the matching
// release private key. The fixture below was signed (out of band, with the
// private key) over the canonical bytes of this exact manifest; the test
// proves the pinned key is the correct counterpart. If the key is ever
// rotated, this fixture must be regenerated.
func TestVerifyManifest_PinnedKeyAcceptsSignedFixture(t *testing.T) {
	const fixture = `{"assets":[{"name":"pagnet-v9.9.9-test-linux-amd64.tar.gz","sha256":"cf2c48145dcaa488ca59ee1ec43a08ce66d56b48bd007fc7ece0d8a6049091d9"}],"created":"2026-09-16T00:00:00Z","keyId":"pagnet-2026-09","signature":"TTbOp9YWdriTjk6Lg0QVlQzdNVT4cnekzbVO4oW47WVHYWCmzt8IXFFr3fb8BAywwLV/EuDfXNGMm4ue2GqyBA==","version":"v9.9.9-test"}`
	var m Manifest
	if err := json.Unmarshal([]byte(fixture), &m); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(&m); err != nil {
		t.Fatalf("the pinned key must verify the signed fixture: %v", err)
	}
	// And the fixture's asset hash matches its content.
	if err := m.VerifyAsset("pagnet-v9.9.9-test-linux-amd64.tar.gz", []byte("pagnet-test-tarball-bytes")); err != nil {
		t.Fatalf("fixture asset hash must match: %v", err)
	}
}

// A manifest signed by a FOREIGN key must be refused by the pinned
// VerifyManifest (the whole point of pinning: only the release key is
// trusted).
func TestVerifyManifest_PinnedKeyRejectsForeignSignature(t *testing.T) {
	m, _ := signTestManifest(t)
	// Re-stamp the pinned keyId but keep the foreign signature: the
	// signature was made under the test key, so it must not verify under
	// the pinned key.
	m.KeyID = KeyID
	err := VerifyManifest(m)
	if err == nil {
		t.Fatal("a foreign signature must not verify under the pinned key")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected a signature failure, got: %v", err)
	}
}
