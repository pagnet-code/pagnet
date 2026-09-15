package e2ee

import (
	"bytes"
	"testing"
)

func testAAD() AAD {
	return AAD{
		ProtocolVersion: 1,
		TenantID:        "tenant-1",
		NetworkID:       "network-1",
		ObjectType:      "message",
		ObjectID:        "object-1",
		Sender:          "sender-1",
		Recipient:       "recipient-1",
		CreatedAt:       "2026-09-14T00:00:00Z",
		KeyEpochID:      "epoch-1",
	}
}

// TestWrongEpochKeyFails verifies decryption fails with a different epoch
// key (the CEK unwrap is authenticated under the epoch key).
func TestWrongEpochKeyFails(t *testing.T) {
	var key1, key2 [32]byte
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 100)
	}
	aad := testAAD()
	env, err := Encrypt([]byte("secret"), key1, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(env, key2, aad); err == nil {
		t.Fatal("Decrypt with the wrong epoch key succeeded, want failure")
	}
}

// TestWrongEpochIDFails verifies a mismatch between the envelope's
// key_epoch_id and the AAD's key_epoch_id is rejected.
func TestWrongEpochIDFails(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	aad := testAAD()
	env, err := Encrypt([]byte("secret"), key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Same key, but the AAD claims a different epoch id.
	wrong := aad
	wrong.KeyEpochID = "epoch-2"
	if _, err := Decrypt(env, key, wrong); err == nil {
		t.Fatal("Decrypt with a mismatched AAD key_epoch_id succeeded, want failure")
	}
}

// TestCEKWrapUnwrap verifies the CEK wrap/unwrap helpers round-trip and that
// a wrong key fails.
func TestCEKWrapUnwrap(t *testing.T) {
	var epochKey, otherKey, cek [32]byte
	for i := range epochKey {
		epochKey[i] = byte(i)
		otherKey[i] = byte(i + 50)
		cek[i] = byte(i * 3)
	}
	var nonce [12]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	wrapped, err := wrapCEK(epochKey, cek, nonce)
	if err != nil {
		t.Fatalf("wrapCEK: %v", err)
	}
	got, err := unwrapCEK(epochKey, wrapped)
	if err != nil {
		t.Fatalf("unwrapCEK: %v", err)
	}
	if got != cek {
		t.Fatal("CEK wrap/unwrap round-trip mismatch")
	}
	if _, err := unwrapCEK(otherKey, wrapped); err == nil {
		t.Fatal("unwrapCEK with the wrong epoch key succeeded, want failure")
	}
}

// TestEncryptFresCEKPerObject verifies each Encrypt call uses a distinct CEK
// (two envelopes of the same plaintext differ, and each decrypts correctly).
func TestEncryptFreshCEKPerObject(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	aad := testAAD()
	pt := []byte("same plaintext")
	e1, err := Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	e2, err := Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	if e1.WrappedContentKey == e2.WrappedContentKey {
		t.Fatal("two Encrypt calls produced the same wrapped CEK; CEKs must be fresh per object")
	}
	if e1.Nonce == e2.Nonce {
		t.Fatal("two Encrypt calls produced the same payload nonce; nonces must be fresh")
	}
	for i, e := range []EncryptedPayloadV1{e1, e2} {
		got, err := Decrypt(e, key, aad)
		if err != nil {
			t.Fatalf("Decrypt %d: %v", i+1, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("Decrypt %d mismatch", i+1)
		}
	}
}

// TestEncryptEmptyPlaintext verifies the empty-payload edge case.
func TestEncryptEmptyPlaintext(t *testing.T) {
	var key [32]byte
	aad := testAAD()
	env, err := Encrypt([]byte{}, key, aad)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	got, err := Decrypt(env, key, aad)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty round-trip = %d bytes, want 0", len(got))
	}
}

// TestEncryptRequiresEpochID verifies Encrypt rejects an AAD without an
// epoch id (the envelope must bind to an epoch).
func TestEncryptRequiresEpochID(t *testing.T) {
	var key [32]byte
	aad := testAAD()
	aad.KeyEpochID = ""
	if _, err := Encrypt([]byte("x"), key, aad); err == nil {
		t.Fatal("Encrypt with empty AAD key_epoch_id succeeded, want failure")
	}
}
