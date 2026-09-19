package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// enrollmentVectorsFile is the shape of testdata/enrollment_vectors_v1.json
// — the committed cross-implementation reference for endpoint crypto
// enrollment (plan D6). The SDK (sdk/crypto.go) and the daemon
// (host.crypto_share_endpoint) must agree on the suite, the mode, the info
// context, the AAD, and the wrap/unwrap construction; this file is the
// single pinned input both sides are tested against.
type enrollmentVectorsFile struct {
	Version int `json:"version"`
	Suite   struct {
		KEM  string `json:"kem"`
		KDF  string `json:"kdf"`
		AEAD string `json:"aead"`
	} `json:"suite"`
	Mode    string `json:"mode"`
	Info    string `json:"info"`
	AAD     any    `json:"aad"`
	Example struct {
		EndpointPublic  string `json:"endpoint_public"`
		EndpointPrivate string `json:"endpoint_private"`
		EpochKey        string `json:"epoch_key"`
	} `json:"example"`
}

// TestEnrollmentCrossImplVectors loads testdata/enrollment_vectors_v1.json
// and verifies the Go protocol constants agree with the committed
// reference, then runs the full wrap/unwrap round-trip with the file's
// fixed endpoint keypair: the daemon-side WrapEpochKeyForEndpoint and the
// EXACT SDK unwrap construction (HPKEUnwrap with the enrollment info, no
// AAD — the call sdk/crypto.go handleCryptoKeyPackage makes).
func TestEnrollmentCrossImplVectors(t *testing.T) {
	path := filepath.Join("testdata", "enrollment_vectors_v1.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f enrollmentVectorsFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if f.Version != 1 {
		t.Fatalf("vector version = %d, want 1", f.Version)
	}
	// The Go info constant must match the committed reference (the
	// binding cross-wave constant).
	if f.Info != EnrollmentInfo {
		t.Fatalf("file info = %q, want %q", f.Info, EnrollmentInfo)
	}
	// Enrollment uses no AAD (the endpoint identity + epoch binding is
	// enforced by the server flow, not by HPKE AAD).
	if f.AAD != nil {
		t.Fatalf("file aad = %v, want null (enrollment wraps carry no AAD)", f.AAD)
	}
	pub, err := hex.DecodeString(f.Example.EndpointPublic)
	if err != nil {
		t.Fatalf("decode endpoint public: %v", err)
	}
	priv, err := hex.DecodeString(f.Example.EndpointPrivate)
	if err != nil {
		t.Fatalf("decode endpoint private: %v", err)
	}
	epochKey, err := hex.DecodeString(f.Example.EpochKey)
	if err != nil {
		t.Fatalf("decode epoch key: %v", err)
	}
	if len(epochKey) != epochKeyBytes {
		t.Fatalf("vector epoch key is %d bytes, want %d", len(epochKey), epochKeyBytes)
	}

	// Daemon side (host.crypto_share_endpoint): wrap the epoch key under
	// the endpoint public key.
	enc, ct, err := WrapEpochKeyForEndpoint(pub, epochKey)
	if err != nil {
		t.Fatalf("WrapEpochKeyForEndpoint: %v", err)
	}
	if len(enc) != 32 {
		t.Fatalf("enc is %d bytes, want 32 (X25519 encapsulated key)", len(enc))
	}

	// SDK side (endpoint.crypto_key_package unwrap) — the EXACT
	// construction sdk/crypto.go uses: HPKEUnwrap(priv, enc, info, nil,
	// ciphertext). The base64 round-trip mirrors the wire
	// (transport.CryptoHPKEWrap carries []byte fields, base64 in JSON).
	encB64 := base64.StdEncoding.EncodeToString(enc)
	ctB64 := base64.StdEncoding.EncodeToString(ct)
	encBack, _ := base64.StdEncoding.DecodeString(encB64)
	ctBack, _ := base64.StdEncoding.DecodeString(ctB64)
	plain, err := HPKEUnwrap(priv, encBack, []byte(f.Info), nil, ctBack)
	if err != nil {
		t.Fatalf("SDK unwrap: %v", err)
	}
	if !bytes.Equal(plain, epochKey) {
		t.Fatal("SDK unwrap did not recover the committed epoch key")
	}

	// A DIFFERENT endpoint key cannot unwrap (the wrap is bound to the
	// announced public key).
	_, otherPriv := newTestX25519KeyPair(t)
	if _, err := HPKEUnwrap(otherPriv, enc, []byte(EnrollmentInfo), nil, ct); err == nil {
		t.Fatal("a different endpoint private key must not unwrap the wrap")
	}
	// A mismatched info context fails authentication (the browser-session
	// infos must never open an enrollment wrap, and vice versa).
	if _, err := HPKEUnwrap(priv, enc, []byte(HPKEInfoCekWrap), nil, ct); err == nil {
		t.Fatal("a mismatched info context must not unwrap the wrap")
	}
}

// TestWrapEpochKeyForEndpointRejectsBadKey enforces the 32-byte epoch-key
// contract: a truncated or over-long key is refused before any HPKE work.
func TestWrapEpochKeyForEndpointRejectsBadKey(t *testing.T) {
	pub, _ := newTestX25519KeyPair(t)
	if _, _, err := WrapEpochKeyForEndpoint(pub, make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte epoch key must be refused")
	}
	if _, _, err := WrapEpochKeyForEndpoint(pub, make([]byte, 33)); err == nil {
		t.Fatal("a 33-byte epoch key must be refused")
	}
	if _, _, err := WrapEpochKeyForEndpoint(nil, make([]byte, 32)); err == nil {
		t.Fatal("an empty endpoint public key must be refused")
	}
}
