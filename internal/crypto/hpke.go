package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// suite is the HPKE suite used for all key transfer:
// HPKE-X25519 / HKDF-SHA256 / AES-256-GCM (RFC 9180). It is the audited
// github.com/cloudflare/circl implementation — no hand-rolled crypto.
var suite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

// WrapKey encrypts plaintext to the recipient's X25519 public key using
// HPKE. It returns the encapsulated key (enc, ephemeral) and the sealed
// ciphertext. info and aad are public context bound to the exchange.
func WrapKey(recipientPub, info, aad, plaintext []byte) (enc, ct []byte, err error) {
	pkR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hpke recipient public key: %w", err)
	}
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hpke sender: %w", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hpke setup: %w", err)
	}
	ct, err = sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hpke seal: %w", err)
	}
	return enc, ct, nil
}

// OpenKey decrypts an HPKE-wrapped plaintext using the recipient's X25519
// private key. info and aad must match what WrapKey used.
func OpenKey(recipientPriv, enc, info, aad, ct []byte) ([]byte, error) {
	skR, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke recipient private key: %w", err)
	}
	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke receiver: %w", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("crypto: hpke open setup: %w", err)
	}
	return opener.Open(ct, aad)
}
