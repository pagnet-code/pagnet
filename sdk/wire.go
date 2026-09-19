package sdk

import (
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// Crypto-enrollment wire types (plan D2/D6).
//
// NOTE: the W1 transport package defines the 12 endpoint.* message types
// and their payloads, but NOT the three crypto-enrollment types below
// (endpoint.crypto_key_package / endpoint.crypto_challenge /
// endpoint.crypto_prove). They are defined HERE (additive; the SDK is the
// first consumer) and are part of the binding D2 contract — W2 (server)
// and W5 (daemon) must use the same names and shapes. If they are later
// added to transport/, these definitions should be replaced by aliases.

const (
	// MsgEndpointCryptoKeyPackage is s→c: the relayed HPKE wrap of the
	// network epoch key under this endpoint's X25519 public key (info
	// enrollmentInfo, no AAD, plaintext = the raw 32-byte epoch key). The
	// server never sees key material.
	MsgEndpointCryptoKeyPackage = "endpoint.crypto_key_package"
	// MsgEndpointCryptoChallenge is s→c: the relayed decryption challenge
	// (issued by the crypto-authority host, encrypted under the epoch key)
	// plus the host-computed expected proof (the server compares the
	// endpoint's proof to it — it never sees the challenge plaintext).
	MsgEndpointCryptoChallenge = "endpoint.crypto_challenge"
	// MsgEndpointCryptoProve is c→s: the endpoint's proof of possession of
	// the epoch key (HMAC over the challenge nonce, keyed by the decrypted
	// challenge plaintext — the host NKA's construction).
	MsgEndpointCryptoProve = "endpoint.crypto_prove"
)

// EndpointCryptoKeyPackagePayload is the wire payload of
// endpoint.crypto_key_package.
type EndpointCryptoKeyPackagePayload struct {
	NetworkID string `json:"networkId"`
	// EpochID is the epoch the wrapped key belongs to (validated by the
	// SDK before storing).
	EpochID string `json:"epochId"`
	// WrappedKey is the HPKE base-mode wrap (X25519/HKDF-SHA256/AES-256-
	// GCM): Enc = encapsulated (ephemeral) key, Ciphertext = the sealed
	// 32-byte epoch key.
	WrappedKey transport.CryptoHPKEWrap `json:"wrappedKey"`
}

// EndpointCryptoChallengePayload is the wire payload of
// endpoint.crypto_challenge.
type EndpointCryptoChallengePayload struct {
	NetworkID string `json:"networkId"`
	// Challenge is the decryption challenge (encrypted under the current
	// epoch; AAD object type e2ee_challenge).
	Challenge e2ee.Challenge `json:"challenge"`
	// ExpectedProof is the host-computed proof the server will compare
	// the endpoint's proof against (opaque to the SDK — it is sent back
	// only in the sense that a matching MAC proves possession).
	ExpectedProof e2ee.Proof `json:"expectedProof"`
}

// EndpointCryptoProvePayload is the wire payload of endpoint.crypto_prove.
type EndpointCryptoProvePayload struct {
	NetworkID string `json:"networkId"`
	// Proof is the endpoint's challenge proof (MAC over nonce ||
	// proofContext, keyed by the decrypted challenge plaintext).
	Proof e2ee.Proof `json:"proof"`
}
