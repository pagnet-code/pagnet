package e2ee

import (
	"bytes"
	"testing"
)

// TestCommittedVectors pins the cross-implementation contract: encryptCore
// with the committed inputs must reproduce the committed envelope byte-for-
// byte, and Decrypt must round-trip it.
func TestCommittedVectors(t *testing.T) {
	for i, v := range VectorsV1 {
		epochKey, cek, nonce, nonceWrap, plaintext, err := v.inputs()
		if err != nil {
			t.Fatalf("vector %d: bad inputs: %v", i, err)
		}

		// The canonical AAD must match the committed reference.
		if got := string(v.AAD.CanonicalBytes()); got != v.AADCanonical {
			t.Fatalf("vector %d: AAD canonical = %s, want %s", i, got, v.AADCanonical)
		}

		env, err := encryptCore(plaintext, epochKey, cek, v.AAD, nonce, nonceWrap)
		if err != nil {
			t.Fatalf("vector %d: encryptCore: %v", i, err)
		}
		canon, err := env.CanonicalJSON()
		if err != nil {
			t.Fatalf("vector %d: canonical: %v", i, err)
		}
		if string(canon) != v.EnvelopeCanonicalJSON {
			t.Fatalf("vector %d: envelope canonical mismatch.\n got: %s\nwant: %s", i, canon, v.EnvelopeCanonicalJSON)
		}

		// Decrypt must recover the plaintext.
		got, err := Decrypt(env, epochKey, v.AAD)
		if err != nil {
			t.Fatalf("vector %d: decrypt: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("vector %d: decrypt round-trip mismatch", i)
		}
	}
}
