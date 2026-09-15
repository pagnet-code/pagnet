package e2ee

// This file holds the E2EE wire types that cross the daemon ↔ control-plane
// boundary during Private Network activation and host enrollment (plan
// §11.6/§11.7). They live in the public e2ee package — not internal/crypto —
// because they are the WIRE CONTRACT: the private server (a separate module)
// must import and relay them, and the public repo owns shared wire types
// (addendum §6). internal/crypto keeps the cryptography and uses these types.
//
// Opaque-relay rule: the control plane relays these values byte-for-byte and
// NEVER parses the ciphertext. The only envelope field the server may read is
// key_epoch_id (routing metadata). Key material (epoch keys, host private
// keys, the unwrapped keyring) never appears in any of these types — only
// public keys and ciphertext.

// KeyPackage is the HPKE-encrypted network keyring for a new host (plan
// §11.7 step 5–6). The Network Key Authority builds it sealed to the new
// host's X25519 public key; only that host can open it. The control plane
// stores/relays only these opaque bytes.
//
// JSON encoding: the byte fields are base64 (Go's default for []byte), which
// is the cross-implementation wire encoding.
type KeyPackage struct {
	// Enc is the HPKE encapsulated (ephemeral) key.
	Enc []byte `json:"enc"`
	// Ciphertext is the HPKE-sealed keyring.
	Ciphertext []byte `json:"ciphertext"`
	// Info is the HPKE info context (public).
	Info []byte `json:"info"`
}

// Challenge is a decryption challenge: a random value encrypted under the
// current key epoch, which the new host must decrypt and MAC to prove it
// holds the keys (plan §11.7 step 7). The Challenge is safe to relay: it
// carries no plaintext or key material.
type Challenge struct {
	// Envelope is the encrypted challenge (EncryptedPayloadV1).
	Envelope EncryptedPayloadV1 `json:"envelope"`
	// AAD is the AAD used to encrypt the challenge (public routing metadata).
	// The recipient decrypts with this AAD verbatim — the server relays it
	// without alteration (the AAD server obligation, PROTOCOL §3).
	AAD AAD `json:"aad"`
	// Nonce is a random nonce the host must include in its proof (replay
	// protection).
	Nonce []byte `json:"nonce"`
}

// Proof is the new host's response to a Challenge: an HMAC over the challenge
// nonce, keyed by the decrypted challenge plaintext. Only a host that
// decrypted the challenge (i.e. holds the epoch key) can produce a valid
// proof.
type Proof struct {
	// MAC is the challenge-proof MAC (base64 in JSON).
	MAC []byte `json:"mac"`
}
