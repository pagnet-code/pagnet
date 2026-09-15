package crypto

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

// TestHostIdentitySaveLoad verifies the host identity round-trips through the
// 0600 file and the keys remain usable.
func TestHostIdentitySaveLoad(t *testing.T) {
	stateDir := t.TempDir()
	hi, err := NewHostIdentity()
	if err != nil {
		t.Fatalf("NewHostIdentity: %v", err)
	}
	if err := hi.Save(stateDir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Permission must be 0600 (the file holds private keys).
	fi, err := os.Stat(HostPath(stateDir))
	if err != nil {
		t.Fatalf("stat host: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("host file permission = %o, want 0600", perm)
	}

	loaded, err := LoadHostIdentity(stateDir)
	if err != nil {
		t.Fatalf("LoadHostIdentity: %v", err)
	}
	if !bytes.Equal(loaded.X25519Pub, hi.X25519Pub) || !bytes.Equal(loaded.X25519Priv, hi.X25519Priv) {
		t.Fatal("x25519 keys changed on round-trip")
	}
	if !bytes.Equal(loaded.Ed25519Pub, hi.Ed25519Pub) || !bytes.Equal(loaded.Ed25519Priv, hi.Ed25519Priv) {
		t.Fatal("ed25519 keys changed on round-trip")
	}
}

// TestEnsureHostIdentity verifies EnsureHostIdentity creates the identity on
// first call and returns the SAME identity on subsequent calls (idempotent,
// stable across daemon restarts).
func TestEnsureHostIdentity(t *testing.T) {
	stateDir := t.TempDir()
	h1, err := EnsureHostIdentity(stateDir)
	if err != nil {
		t.Fatalf("EnsureHostIdentity (1st): %v", err)
	}
	h2, err := EnsureHostIdentity(stateDir)
	if err != nil {
		t.Fatalf("EnsureHostIdentity (2nd): %v", err)
	}
	if !bytes.Equal(h1.X25519Pub, h2.X25519Pub) || !bytes.Equal(h1.Ed25519Pub, h2.Ed25519Pub) {
		t.Fatal("EnsureHostIdentity did not return a stable identity across calls")
	}
}

// TestHostIdentityDistinct verifies two generated identities are distinct.
func TestHostIdentityDistinct(t *testing.T) {
	a, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.X25519Pub, b.X25519Pub) {
		t.Fatal("two host identities share the same x25519 public key")
	}
	if bytes.Equal(a.Ed25519Pub, b.Ed25519Pub) {
		t.Fatal("two host identities share the same ed25519 public key")
	}
}

// TestHostIdentityEd25519SignVerify verifies the Ed25519 signing key works.
func TestHostIdentityEd25519SignVerify(t *testing.T) {
	hi, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("crypto metadata")
	sig := ed25519.Sign(hi.Ed25519Signer(), msg)
	if !ed25519.Verify(hi.Ed25519Verifier(), msg, sig) {
		t.Fatal("ed25519 signature did not verify")
	}
	// A tampered message must not verify.
	if ed25519.Verify(hi.Ed25519Verifier(), append(msg, 'x'), sig) {
		t.Fatal("ed25519 signature verified a tampered message")
	}
}

// TestHostIdentityHPKEKeysUsable verifies the X25519 keys convert to usable
// circl KEM keys.
func TestHostIdentityHPKEKeysUsable(t *testing.T) {
	hi, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hi.HPKEPublicKey(); err != nil {
		t.Fatalf("HPKEPublicKey: %v", err)
	}
	if _, err := hi.HPKEPrivateKey(); err != nil {
		t.Fatalf("HPKEPrivateKey: %v", err)
	}
}
