package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

// newTestX25519KeyPair generates a fresh X25519 keypair (pub, priv) for HPKE
// tests, using the fixed suite's KEM scheme. The static key is per-session in
// production; tests draw a fresh one.
func newTestX25519KeyPair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pkR, skR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub, err = pkR.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	priv, err = skR.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	return pub, priv
}

// TestHPKERoundTrip verifies HPKEWrap/HPKEUnwrap round-trip with the fixed
// suite and a fresh recipient static key.
func TestHPKERoundTrip(t *testing.T) {
	pub, priv := newTestX25519KeyPair(t)
	info := []byte(HPKEInfoCekUnwrap)
	aad := BrowserSessionAAD("net-1", "sess-1", "obj-1")
	plaintext := []byte("secret-cek-bytes-0123456789abcdef")
	enc, ct, err := HPKEWrap(pub, info, aad, plaintext)
	if err != nil {
		t.Fatalf("HPKEWrap: %v", err)
	}
	got, err := HPKEUnwrap(priv, enc, info, aad, ct)
	if err != nil {
		t.Fatalf("HPKEUnwrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("HPKE round-trip mismatch")
	}
}

// TestHPKEWrongKeyFails verifies a different recipient private key cannot
// open the seal.
func TestHPKEWrongKeyFails(t *testing.T) {
	pub, _ := newTestX25519KeyPair(t)
	_, otherPriv := newTestX25519KeyPair(t)
	info := []byte(HPKEInfoCekWrap)
	aad := BrowserSessionAAD("net-1", "sess-1", "obj-1")
	enc, ct, err := HPKEWrap(pub, info, aad, []byte("cek"))
	if err != nil {
		t.Fatalf("HPKEWrap: %v", err)
	}
	if _, err := HPKEUnwrap(otherPriv, enc, info, aad, ct); err == nil {
		t.Fatal("HPKEUnwrap with the wrong private key succeeded, want failure")
	}
}

// TestHPKEWrongInfoFails verifies a mismatched info context fails
// authentication (the two directions use different info on purpose).
func TestHPKEWrongInfoFails(t *testing.T) {
	pub, priv := newTestX25519KeyPair(t)
	aad := BrowserSessionAAD("net-1", "sess-1", "obj-1")
	enc, ct, err := HPKEWrap(pub, []byte(HPKEInfoCekUnwrap), aad, []byte("cek"))
	if err != nil {
		t.Fatalf("HPKEWrap: %v", err)
	}
	// Open with the OTHER direction's info: must fail.
	if _, err := HPKEUnwrap(priv, enc, []byte(HPKEInfoCekWrap), aad, ct); err == nil {
		t.Fatal("HPKEUnwrap with a mismatched info succeeded, want failure")
	}
}

// TestHPKEWrongAADFails verifies a mismatched AAD (different object binding)
// fails authentication.
func TestHPKEWrongAADFails(t *testing.T) {
	pub, priv := newTestX25519KeyPair(t)
	info := []byte(HPKEInfoCekUnwrap)
	enc, ct, err := HPKEWrap(pub, info, BrowserSessionAAD("net-1", "sess-1", "obj-1"), []byte("cek"))
	if err != nil {
		t.Fatalf("HPKEWrap: %v", err)
	}
	// Open with a different object binding: must fail.
	if _, err := HPKEUnwrap(priv, enc, info, BrowserSessionAAD("net-1", "sess-1", "obj-2"), ct); err == nil {
		t.Fatal("HPKEUnwrap with a mismatched AAD succeeded, want failure")
	}
}

// TestHPKEFreshEphemeral verifies each HPKEWrap draws a distinct sender
// ephemeral (two seals of the same plaintext differ).
func TestHPKEFreshEphemeral(t *testing.T) {
	pub, _ := newTestX25519KeyPair(t)
	info := []byte(HPKEInfoCekUnwrap)
	aad := BrowserSessionAAD("net-1", "sess-1", "obj-1")
	enc1, ct1, err := HPKEWrap(pub, info, aad, []byte("cek"))
	if err != nil {
		t.Fatalf("HPKEWrap 1: %v", err)
	}
	enc2, ct2, err := HPKEWrap(pub, info, aad, []byte("cek"))
	if err != nil {
		t.Fatalf("HPKEWrap 2: %v", err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Fatal("two HPKEWrap calls produced the same ephemeral enc; ephemerals must be fresh")
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two HPKEWrap calls produced the same ciphertext; ephemerals must be fresh")
	}
}

// hpkeVectorsFile is the shape of testdata/hpke_vectors_v1.json — the
// cross-implementation reference the black-box browser double (p10b) reads.
type hpkeVectorsFile struct {
	Version int `json:"version"`
	Suite   struct {
		KEM  string `json:"kem"`
		KDF  string `json:"kdf"`
		AEAD string `json:"aead"`
	} `json:"suite"`
	Info struct {
		CekUnwrap string `json:"cek_unwrap"`
		CekWrap   string `json:"cek_wrap"`
	} `json:"info"`
	AAD struct {
		Separator string   `json:"separator"`
		Fields    []string `json:"fields"`
	} `json:"aad"`
	Example struct {
		NetworkID string `json:"network_id"`
		SessionID string `json:"session_id"`
		ObjectID  string `json:"object_id"`
		AAD       string `json:"aad"`
		CEKHex    string `json:"cek_hex"`
	} `json:"example"`
}

// TestHPKECrossImplVectors loads testdata/hpke_vectors_v1.json and verifies
// the Go protocol constants agree with the committed cross-implementation
// reference (the same file the black-box browser double, p10b, reads). A
// drift between the Go constants and the file fails here, so the two
// implementations cannot silently diverge on the HPKE context.
func TestHPKECrossImplVectors(t *testing.T) {
	path := filepath.Join("testdata", "hpke_vectors_v1.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f hpkeVectorsFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if f.Version != 1 {
		t.Fatalf("vector version = %d, want 1", f.Version)
	}
	// The Go info constants must match the committed reference.
	if f.Info.CekUnwrap != HPKEInfoCekUnwrap {
		t.Fatalf("file info.cek_unwrap = %q, want %q", f.Info.CekUnwrap, HPKEInfoCekUnwrap)
	}
	if f.Info.CekWrap != HPKEInfoCekWrap {
		t.Fatalf("file info.cek_wrap = %q, want %q", f.Info.CekWrap, HPKEInfoCekWrap)
	}
	// The AAD construction must match the committed reference.
	wantAAD, err := base64.StdEncoding.DecodeString(f.Example.AAD)
	if err != nil {
		t.Fatalf("decode example aad: %v", err)
	}
	gotAAD := BrowserSessionAAD(f.Example.NetworkID, f.Example.SessionID, f.Example.ObjectID)
	if !bytes.Equal(gotAAD, wantAAD) {
		t.Fatalf("BrowserSessionAAD = %x, want %x", gotAAD, wantAAD)
	}
	// The example CEK must be the committed v1 vector's CEK (ties the HPKE
	// path to VectorsV1).
	if f.Example.CEKHex != VectorsV1[0].CEKHex {
		t.Fatalf("example cek = %s, want VectorsV1[0] %s", f.Example.CEKHex, VectorsV1[0].CEKHex)
	}
	cek, err := hex.DecodeString(f.Example.CEKHex)
	if err != nil {
		t.Fatalf("decode example cek: %v", err)
	}
	// Full round-trip using the file's context and a fresh recipient key.
	pub, priv := newTestX25519KeyPair(t)
	enc, ct, err := HPKEWrap(pub, []byte(f.Info.CekUnwrap), wantAAD, cek)
	if err != nil {
		t.Fatalf("HPKEWrap: %v", err)
	}
	got, err := HPKEUnwrap(priv, enc, []byte(f.Info.CekUnwrap), wantAAD, ct)
	if err != nil {
		t.Fatalf("HPKEUnwrap: %v", err)
	}
	if !bytes.Equal(got, cek) {
		t.Fatal("HPKE cross-impl vector round-trip mismatch")
	}
}
