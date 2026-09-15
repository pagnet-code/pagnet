package crypto

import (
	"bytes"
	"testing"
)

// TestHPKERoundTrip verifies WrapKey/OpenKey round-trip to a host's X25519
// keypair, and that the wrong private key fails.
func TestHPKERoundTrip(t *testing.T) {
	hi, err := NewHostIdentity()
	if err != nil {
		t.Fatalf("NewHostIdentity: %v", err)
	}
	other, err := NewHostIdentity()
	if err != nil {
		t.Fatalf("NewHostIdentity (other): %v", err)
	}
	plaintext := []byte("secret keyring bytes")
	info := []byte("pagnet/e2ee/keypackage/v1/test-network")

	enc, ct, err := WrapKey(hi.X25519Pub, info, nil, plaintext)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := OpenKey(hi.X25519Priv, enc, info, nil, ct)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("HPKE round-trip mismatch")
	}
	// The wrong private key must fail.
	if _, err := OpenKey(other.X25519Priv, enc, info, nil, ct); err == nil {
		t.Fatal("OpenKey with the wrong private key succeeded, want failure")
	}
	// A wrong info context must fail (it is bound to the exchange).
	if _, err := OpenKey(hi.X25519Priv, enc, []byte("other-info"), nil, ct); err == nil {
		t.Fatal("OpenKey with a wrong info context succeeded, want failure")
	}
}

// TestHPKEAAD verifies the HPKE AAD is authenticated (tampering fails).
func TestHPKEAAD(t *testing.T) {
	hi, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("bound to aad")
	info := []byte("info")
	aad := []byte("aad-1")
	enc, ct, err := WrapKey(hi.X25519Pub, info, aad, plaintext)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if _, err := OpenKey(hi.X25519Priv, enc, info, []byte("aad-2"), ct); err == nil {
		t.Fatal("OpenKey with a tampered AAD succeeded, want failure")
	}
}
