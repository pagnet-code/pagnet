package e2ee

import "encoding/hex"

// TestVectorV1 is one committed, cross-implementation test vector. Any
// implementation of the e2ee contract (the Go client, the Go server, the
// browser) must produce the exact EnvelopeCanonicalJSON from the given
// inputs, so independent implementations can be cross-checked byte-for-byte.
//
// The inputs include the CEK and both GCM nonces (fixed here for
// reproducibility; production Encrypt draws them randomly).
type TestVectorV1 struct {
	// EpochKeyHex is the 32-byte network key-epoch key.
	EpochKeyHex string `json:"epoch_key"`
	// CEKHex is the 32-byte per-object content encryption key.
	CEKHex string `json:"cek"`
	// NonceHex is the 12-byte payload GCM nonce.
	NonceHex string `json:"nonce"`
	// NonceWrapHex is the 12-byte CEK-wrap GCM nonce.
	NonceWrapHex string `json:"nonce_wrap"`
	// PlaintextHex is the plaintext payload.
	PlaintextHex string `json:"plaintext"`
	// AAD is the associated-data binding.
	AAD AAD `json:"aad"`
	// AADCanonical is the expected canonical AAD bytes (GCM associated-data),
	// for reference.
	AADCanonical string `json:"aad_canonical"`
	// EnvelopeCanonicalJSON is the expected canonical JSON of the envelope.
	EnvelopeCanonicalJSON string `json:"envelope"`
}

// VectorsV1 are the committed v1 test vectors. Do not edit the expected
// output by hand; regenerate with the crypto and re-verify by hand before
// committing (a changed vector silently breaks cross-implementation checks).
var VectorsV1 = []TestVectorV1{
	{
		EpochKeyHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		CEKHex:       "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
		NonceHex:     "000102030405060708090a0b",
		NonceWrapHex: "0f0e0d0c0b0a090807060504",
		PlaintextHex: "68656c6c6f207061676e65742065326565", // "hello pagnet e2ee"
		AAD: AAD{
			ProtocolVersion: 1,
			TenantID:        "01900000-0000-7000-8000-000000000001",
			NetworkID:       "01900000-0000-7000-8000-000000000002",
			ObjectType:      "message",
			ObjectID:        "01900000-0000-7000-8000-000000000003",
			Sender:          "agent-coder",
			Recipient:       "agent-reviewer",
			CreatedAt:       "2026-09-14T00:00:00Z",
			KeyEpochID:      "01900000-0000-7000-8000-000000000004",
		},
		AADCanonical:          `{"protocol_version":1,"tenant_id":"01900000-0000-7000-8000-000000000001","network_id":"01900000-0000-7000-8000-000000000002","object_type":"message","object_id":"01900000-0000-7000-8000-000000000003","sender":"agent-coder","recipient":"agent-reviewer","created_at":"2026-09-14T00:00:00Z","key_epoch_id":"01900000-0000-7000-8000-000000000004"}`,
		EnvelopeCanonicalJSON: `{"version":1,"cipher_suite":"AES-256-GCM","key_epoch_id":"01900000-0000-7000-8000-000000000004","nonce":"AAECAwQFBgcICQoL","ciphertext":"zNbAptx5NXFsP1vK6x6hstAQlk1+SZfVo3hbPsJfbjPT","wrapped_content_key":"Dw4NDAsKCQgHBgUExFHTPz+yycmDtts0VPfnbhkXbRO7LIcTLjDUhE53zlWWGDzxXuZOK4K/fkBK9gTy","aad_version":1}`,
	},
}

// Reconstruct encryptCore inputs from a committed vector.
func (v TestVectorV1) inputs() (epochKey, cek [32]byte, nonce, nonceWrap [12]byte, plaintext []byte, err error) {
	epochKeyBytes, e1 := hex.DecodeString(v.EpochKeyHex)
	cekBytes, e2 := hex.DecodeString(v.CEKHex)
	nonceBytes, e3 := hex.DecodeString(v.NonceHex)
	nonceWrapBytes, e4 := hex.DecodeString(v.NonceWrapHex)
	plaintext, e5 := hex.DecodeString(v.PlaintextHex)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		err = e1
		if err == nil {
			err = e2
		}
		if err == nil {
			err = e3
		}
		if err == nil {
			err = e4
		}
		if err == nil {
			err = e5
		}
		return
	}
	copy(epochKey[:], epochKeyBytes)
	copy(cek[:], cekBytes)
	copy(nonce[:], nonceBytes)
	copy(nonceWrap[:], nonceWrapBytes)
	return
}
