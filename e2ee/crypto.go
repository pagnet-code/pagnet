package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Fixed sizes for the v1 construction.
const (
	gcmNonceSize = 12
	gcmTagSize   = 16
	cekSize      = 32
)

// Encrypt encrypts plaintext under a fresh per-object CEK, wrapped under the
// network key-epoch key, producing a versioned envelope.
//
//   - A fresh random 256-bit CEK is generated for this object.
//   - The payload is encrypted with AES-256-GCM under the CEK, with the
//     canonical AAD as associated data.
//   - The CEK is wrapped with AES-256-GCM under the epoch key (NOT AES-KW —
//     WebCrypto has no AES-KW). The wrapped CEK is stored as
//     nonce(12) || ciphertext+tag.
//
// aad.KeyEpochID must be set: it becomes the envelope's key_epoch_id and
// binds the object to the epoch.
func Encrypt(plaintext []byte, epochKey [32]byte, aad AAD) (EncryptedPayloadV1, error) {
	var nonce, nonceWrap [gcmNonceSize]byte
	var cek [cekSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return EncryptedPayloadV1{}, fmt.Errorf("e2ee: read nonce: %w", err)
	}
	if _, err := rand.Read(nonceWrap[:]); err != nil {
		return EncryptedPayloadV1{}, fmt.Errorf("e2ee: read wrap nonce: %w", err)
	}
	if _, err := rand.Read(cek[:]); err != nil {
		return EncryptedPayloadV1{}, fmt.Errorf("e2ee: read CEK: %w", err)
	}
	return encryptCore(plaintext, epochKey, cek, aad, nonce, nonceWrap)
}

// encryptCore builds the envelope with explicit CEK and nonces. Encrypt uses
// random values; the committed test vectors (VectorsV1) use fixed values so
// the output is reproducible across implementations.
func encryptCore(plaintext []byte, epochKey, cek [32]byte, aad AAD, nonce, nonceWrap [gcmNonceSize]byte) (EncryptedPayloadV1, error) {
	if aad.KeyEpochID == "" {
		return EncryptedPayloadV1{}, errors.New("e2ee: AAD key_epoch_id is required")
	}
	// Wrap the CEK under the epoch key.
	wrapped, err := wrapCEK(epochKey, cek, nonceWrap)
	if err != nil {
		return EncryptedPayloadV1{}, err
	}
	// Encrypt the payload under the CEK, bound to the canonical AAD.
	ct, err := sealPayload(cek, nonce, plaintext, aad.CanonicalBytes())
	if err != nil {
		return EncryptedPayloadV1{}, err
	}
	return EncryptedPayloadV1{
		Version:           EnvelopeVersion,
		CipherSuite:       CipherSuiteAES256GCM,
		KeyEpochID:        aad.KeyEpochID,
		Nonce:             base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext:        base64.StdEncoding.EncodeToString(ct),
		WrappedContentKey: base64.StdEncoding.EncodeToString(wrapped),
		AADVersion:        AADVersion,
	}, nil
}

// Decrypt decrypts an envelope with the network key-epoch key, returning the
// plaintext.
//
// aad must be the AAD reconstructed from the object's routing metadata. If
// the server altered any bound field, the reconstructed AAD differs from the
// one used at encryption and GCM authentication fails. The envelope's
// key_epoch_id must also match aad.KeyEpochID.
func Decrypt(env EncryptedPayloadV1, epochKey [32]byte, aad AAD) ([]byte, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	if env.KeyEpochID != aad.KeyEpochID {
		return nil, fmt.Errorf("e2ee: key_epoch_id mismatch (envelope %q != aad %q)", env.KeyEpochID, aad.KeyEpochID)
	}
	// Unwrap the CEK under the epoch key.
	wrapped, err := base64.StdEncoding.DecodeString(env.WrappedContentKey)
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode wrapped CEK: %w", err)
	}
	cek, err := unwrapCEK(epochKey, wrapped)
	if err != nil {
		return nil, err
	}
	// Decrypt the payload under the CEK, bound to the canonical AAD.
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("e2ee: decode ciphertext: %w", err)
	}
	return openPayload(cek, nonce, ct, aad.CanonicalBytes())
}

// wrapCEK wraps a CEK under the epoch key: nonce(12) || GCM(cek). No
// associated data — the epoch key binds the wrap to the epoch.
func wrapCEK(epochKey, cek [32]byte, nonce [gcmNonceSize]byte) ([]byte, error) {
	aead, err := newGCM(epochKey)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce[:], cek[:], nil)
	out := make([]byte, 0, gcmNonceSize+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out, nil
}

// unwrapCEK unwraps a CEK wrapped by wrapCEK.
func unwrapCEK(epochKey [32]byte, wrapped []byte) ([32]byte, error) {
	if len(wrapped) < gcmNonceSize+gcmTagSize {
		return [32]byte{}, errors.New("e2ee: wrapped CEK too short")
	}
	nonce := wrapped[:gcmNonceSize]
	ct := wrapped[gcmNonceSize:]
	aead, err := newGCM(epochKey)
	if err != nil {
		return [32]byte{}, err
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("e2ee: unwrap CEK (wrong epoch key or tampered wrap): %w", err)
	}
	if len(plain) != cekSize {
		return [32]byte{}, fmt.Errorf("e2ee: unwrapped CEK is %d bytes, want %d", len(plain), cekSize)
	}
	var cek [32]byte
	copy(cek[:], plain)
	return cek, nil
}

func sealPayload(cek [32]byte, nonce [gcmNonceSize]byte, plaintext, aadBytes []byte) ([]byte, error) {
	aead, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, aadBytes), nil
}

func openPayload(cek [32]byte, nonce, ct, aadBytes []byte) ([]byte, error) {
	if len(nonce) != gcmNonceSize {
		return nil, fmt.Errorf("e2ee: nonce is %d bytes, want %d", len(nonce), gcmNonceSize)
	}
	aead, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, aadBytes)
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("e2ee: aes.NewCipher: %w", err)
	}
	return cipher.NewGCM(block)
}
