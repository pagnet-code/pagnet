package durable

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// AESGCM owns a private copy of a caller-supplied AES-256 secret. Bootstrap and
// Open never generate or replace keys. Reference is opaque configuration metadata.
type AESGCM struct {
	aead      cipher.AEAD
	reference KeyReference
}

func NewAESGCM(reference KeyReference, secret []byte) (*AESGCM, error) {
	if !validText(reference.ID, 256) || !validText(reference.Version, 128) || len(secret) != 32 {
		return nil, invalid("Invalid event encryption key reference")
	}
	owned := append([]byte(nil), secret...)
	defer clear(owned)
	block, err := aes.NewCipher(owned)
	if err != nil {
		return nil, unavailable()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, unavailable()
	}
	return &AESGCM{aead: aead, reference: reference}, nil
}
func (p *AESGCM) Reference() KeyReference { return p.reference }
func (p *AESGCM) Seal(aad, plain []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return p.aead.Seal(nonce, nonce, plain, aad), nil
}
func (p *AESGCM) Open(aad, sealed []byte) ([]byte, error) {
	if len(sealed) < p.aead.NonceSize()+p.aead.Overhead() {
		return nil, errors.New("invalid event ciphertext")
	}
	return p.aead.Open(nil, sealed[:p.aead.NonceSize()], sealed[p.aead.NonceSize():], aad)
}
