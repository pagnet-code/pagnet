package sessionworker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"
)

func TestCloudPrivateCaptureKeyDerivationHistoricalBytes(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	scope := Scope{ServerURL: "https://actual.example", TenantID: "tenant", AccountID: "account", HostID: "host", InstanceID: "instance", Generation: "generation"}
	// This is the original cloud HKDF profile, byte-exact, independent of the
	// new closed Local authority representation or capture helper implementation.
	info := `{"Domain":"pagnet-worker-private-source-key-v2","Scope":{"serverUrl":"https://actual.example","tenantId":"tenant","accountId":"account","hostId":"host","instanceId":"instance","generation":"generation"},"Directory":"/owned/private-worker"}`
	derived, e := hkdf.Key(sha256.New, key, nil, info, 32)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(derived)
	block, e := aes.NewCipher(derived)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := captureAEAD(key, scope, "/owned/private-worker")
	if e != nil {
		t.Fatal(e)
	}
	nonce := bytes.Repeat([]byte{3}, expected.NonceSize())
	plaintext := []byte("retained private original source")
	aad := []byte("historical exact aad")
	if !bytes.Equal(actual.Seal(nil, nonce, plaintext, aad), expected.Seal(nil, nonce, plaintext, aad)) {
		t.Fatal("historical Cloud private capture key changed")
	}
}
