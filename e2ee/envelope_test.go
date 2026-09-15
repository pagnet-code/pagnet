package e2ee

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCanonicalJSONStable verifies the canonical envelope encoding is
// deterministic: repeated encodings are byte-identical, and the key order is
// the fixed declaration order (the wire contract).
func TestCanonicalJSONStable(t *testing.T) {
	env := EncryptedPayloadV1{
		Version:           EnvelopeVersion,
		CipherSuite:       CipherSuiteAES256GCM,
		KeyEpochID:        "epoch-1",
		Nonce:             "AAAA",
		Ciphertext:        "BBBB",
		WrappedContentKey: "CCCC",
		AADVersion:        AADVersion,
	}
	a, err := env.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical JSON not stable:\n%s\n%s", a, b)
	}
	// The key order is part of the contract.
	want := `{"version":1,"cipher_suite":"AES-256-GCM","key_epoch_id":"epoch-1","nonce":"AAAA","ciphertext":"BBBB","wrapped_content_key":"CCCC","aad_version":1}`
	if string(a) != want {
		t.Fatalf("canonical JSON = %s, want %s", a, want)
	}
}

// TestCanonicalJSONNoHTMLEscaping ensures the canonical encoder does not
// HTML-escape (a browser JSON.stringify does not), so the bytes match a JS
// implementation.
func TestCanonicalJSONNoHTMLEscaping(t *testing.T) {
	env := EncryptedPayloadV1{
		Version:           EnvelopeVersion,
		CipherSuite:       CipherSuiteAES256GCM,
		KeyEpochID:        "a<b>&c",
		Nonce:             "AAAA",
		Ciphertext:        "BBBB",
		WrappedContentKey: "CCCC",
		AADVersion:        AADVersion,
	}
	got, err := env.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if want := `"key_epoch_id":"a<b>&c"`; !strings.Contains(string(got), want) {
		t.Fatalf("canonical JSON %s does not contain unescaped %s", got, want)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	var epochKey [32]byte
	for i := range epochKey {
		epochKey[i] = byte(i)
	}
	aad := AAD{
		ProtocolVersion: 1,
		TenantID:        "t1",
		NetworkID:       "n1",
		ObjectType:      "message",
		ObjectID:        "o1",
		Sender:          "s",
		Recipient:       "r",
		CreatedAt:       "2026-09-14T00:00:00Z",
		KeyEpochID:      "epoch-1",
	}
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	env, err := Encrypt(plaintext, epochKey, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got, err := Decrypt(env, epochKey, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip = %q, want %q", got, plaintext)
	}
}

// TestEnvelopeValidate catches malformed envelopes.
func TestEnvelopeValidate(t *testing.T) {
	valid := EncryptedPayloadV1{
		Version:           EnvelopeVersion,
		CipherSuite:       CipherSuiteAES256GCM,
		KeyEpochID:        "epoch-1",
		Nonce:             "AAECAwQFBgcICQoL", // 12 bytes
		Ciphertext:        "BBBB",
		WrappedContentKey: "Dw4NDAsKCQgHBgUExFHTPz+yycmDtts0VPfnbhkXbRO7LIcTLjDUhE53zlWWGDzxXuZOK4K/fkBK9gTy", // 60 bytes
		AADVersion:        AADVersion,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	const nonce12 = "AAECAwQFBgcICQoL" // 12 bytes
	// wrapOK is a 60-byte wrapped CEK (12-byte nonce + 48-byte GCM record).
	const wrapOK = "Dw4NDAsKCQgHBgUExFHTPz+yycmDtts0VPfnbhkXbRO7LIcTLjDUhE53zlWWGDzxXuZOK4K/fkBK9gTy"
	cases := map[string]EncryptedPayloadV1{
		"bad version":        {Version: 99, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: nonce12, Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: AADVersion},
		"bad cipher suite":   {Version: EnvelopeVersion, CipherSuite: "RSA", KeyEpochID: "e", Nonce: nonce12, Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: AADVersion},
		"bad aad version":    {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: nonce12, Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: 99},
		"empty epoch id":     {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "", Nonce: nonce12, Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: AADVersion},
		"bad nonce b64":      {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: "!!!", Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: AADVersion},
		"short nonce":        {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: "AAAA", Ciphertext: "B", WrappedContentKey: wrapOK, AADVersion: AADVersion},
		"short wrapped cek":  {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: nonce12, Ciphertext: "B", WrappedContentKey: "AAAA", AADVersion: AADVersion},
		"bad ciphertext b64": {Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e", Nonce: nonce12, Ciphertext: "!!!", WrappedContentKey: wrapOK, AADVersion: AADVersion},
	}
	for name, env := range cases {
		if err := env.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded, want error", name)
		}
	}
}

// TestEnvelopeCanonicalJSONIsCompactJSON ensures the canonical encoding is
// plain compact JSON (parseable, no whitespace).
func TestEnvelopeCanonicalJSONIsCompactJSON(t *testing.T) {
	env := EncryptedPayloadV1{
		Version: EnvelopeVersion, CipherSuite: CipherSuiteAES256GCM, KeyEpochID: "e",
		Nonce: "AAAA", Ciphertext: "BBBB", WrappedContentKey: "CCCC", AADVersion: AADVersion,
	}
	b, _ := env.CanonicalJSON()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("canonical JSON is not valid JSON: %v", err)
	}
	if len(m) != 7 {
		t.Fatalf("envelope has %d keys, want 7", len(m))
	}
}
