package e2ee

import (
	"testing"
)

// TestAADTamperFails verifies that altering ANY bound AAD field makes
// decryption fail (the AAD is the GCM associated-data, plan §11.4).
func TestAADTamperFails(t *testing.T) {
	var epochKey [32]byte
	for i := range epochKey {
		epochKey[i] = byte(i * 7)
	}
	base := AAD{
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
	plaintext := []byte("bind me to the routing metadata")
	env, err := Encrypt(plaintext, epochKey, base)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Sanity: the unaltered AAD decrypts.
	if _, err := Decrypt(env, epochKey, base); err != nil {
		t.Fatalf("baseline Decrypt failed: %v", err)
	}

	mutations := map[string]func(AAD) AAD{
		"protocol_version": func(a AAD) AAD { a.ProtocolVersion = 2; return a },
		"tenant_id":        func(a AAD) AAD { a.TenantID = "tenant-2"; return a },
		"network_id":       func(a AAD) AAD { a.NetworkID = "network-2"; return a },
		"object_type":      func(a AAD) AAD { a.ObjectType = "task"; return a },
		"object_id":        func(a AAD) AAD { a.ObjectID = "object-2"; return a },
		"sender":           func(a AAD) AAD { a.Sender = "sender-2"; return a },
		"recipient":        func(a AAD) AAD { a.Recipient = "recipient-2"; return a },
		"created_at":       func(a AAD) AAD { a.CreatedAt = "2026-09-14T00:00:01Z"; return a },
		"key_epoch_id":     func(a AAD) AAD { a.KeyEpochID = "epoch-2"; return a },
	}
	for name, mutate := range mutations {
		tampered := mutate(base)
		if _, err := Decrypt(env, epochKey, tampered); err == nil {
			t.Errorf("tampering %q did not fail decryption", name)
		}
	}
}

// TestAADCanonicalBytesStable verifies the AAD canonical serialization is
// deterministic and in the fixed key order.
func TestAADCanonicalBytesStable(t *testing.T) {
	a := AAD{
		ProtocolVersion: 1,
		TenantID:        "t",
		NetworkID:       "n",
		ObjectType:      "message",
		ObjectID:        "o",
		Sender:          "s",
		Recipient:       "r",
		CreatedAt:       "2026-09-14T00:00:00Z",
		KeyEpochID:      "e",
	}
	b1 := a.CanonicalBytes()
	b2 := a.CanonicalBytes()
	if string(b1) != string(b2) {
		t.Fatalf("AAD canonical bytes not stable: %s vs %s", b1, b2)
	}
	want := `{"protocol_version":1,"tenant_id":"t","network_id":"n","object_type":"message","object_id":"o","sender":"s","recipient":"r","created_at":"2026-09-14T00:00:00Z","key_epoch_id":"e"}`
	if string(b1) != want {
		t.Fatalf("AAD canonical = %s, want %s", b1, want)
	}
}
