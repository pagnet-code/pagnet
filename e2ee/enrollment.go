package e2ee

import "fmt"

// EnrollmentInfo is the HPKE info context for endpoint crypto enrollment
// (plan D6): the crypto-authority host wraps the network's CURRENT epoch
// key under an SDK endpoint's X25519 public key with EXACTLY this info,
// no AAD, and a plaintext of exactly the raw 32-byte epoch key. It is a
// binding cross-wave constant — the SDK side unwraps with
// HPKEUnwrap(priv, enc, []byte(EnrollmentInfo), nil, ct)
// (sdk/crypto.go handleCryptoKeyPackage), and the daemon side wraps with
// WrapEpochKeyForEndpoint. A mismatched info string fails authentication
// (HPKE binds info into the HKDF expansion).
const EnrollmentInfo = "pagnet/endpoint-enrollment/epoch-wrap/v1"

// epochKeyBytes is the fixed length of a network key-epoch key (the
// plaintext of an enrollment wrap).
const epochKeyBytes = 32

// WrapEpochKeyForEndpoint seals the network's current epoch key (32
// bytes) to the enrolling endpoint's X25519 public key using HPKE base
// mode with the fixed suite, the EnrollmentInfo context, and NO AAD.
// It returns the encapsulated (ephemeral) key enc and the sealed
// ciphertext — the pair the control plane relays byte-for-byte to the
// endpoint as endpoint.crypto_key_package {wrappedKey: {enc,
// ciphertext}} (transport.CryptoHPKEWrap), and the endpoint opens with
// HPKEUnwrap using its X25519 private key, the SAME info, and a nil AAD.
// A fresh sender ephemeral is drawn per call (never reused); the epoch
// key itself is never logged.
func WrapEpochKeyForEndpoint(endpointPub, epochKey []byte) (enc, ct []byte, err error) {
	if len(epochKey) != epochKeyBytes {
		return nil, nil, fmt.Errorf("e2ee: enrollment epoch key is %d bytes, want %d", len(epochKey), epochKeyBytes)
	}
	if len(endpointPub) == 0 {
		return nil, nil, fmt.Errorf("e2ee: enrollment endpoint public key is empty")
	}
	return HPKEWrap(endpointPub, []byte(EnrollmentInfo), nil, epochKey)
}
