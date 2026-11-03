package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

// SealNativeShareEpochWithSource consumes exactly one fresh epoch on every exit.
// Both envelopes contain that same single key, and are returned only if both
// seals succeed. A failed attempt must never be resealed under its operation ID.
// The caller must independently authorize recipient and source authority, holder
// keys and incarnation. No keyring, historical key or installation is involved.
func SealNativeShareEpochWithSource(fresh *FreshNativeShareEpoch, recipient transport.NativeShareEpochMetadata, sourceContext transport.NativeShareEpochSourceContext, source ed25519.PrivateKey, now time.Time) (transport.NativeShareEpochPackage, transport.NativeShareEpochSourceEnvelope, error) {
	var p transport.NativeShareEpochPackage
	var envelope transport.NativeShareEpochSourceEnvelope
	if fresh == nil || fresh.secret == nil {
		return p, envelope, errNativeShareEpoch
	}
	s := fresh.secret
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key
	s.key = nil
	defer clearNativeShareEpoch(key)
	if _, err := sourceContext.CanonicalBytes(); err != nil {
		return p, envelope, err
	}
	if len(source) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(source.Seed()), source) || hex.EncodeToString(source.Public().(ed25519.PublicKey)) != sourceContext.SigningKey {
		return p, envelope, errNativeShareEpoch
	}
	selected, err := sealNativeShareEpochKey(key, s.id, recipient, source, now)
	if err != nil {
		return p, envelope, err
	}
	digest, err := transport.NativeShareEpochPackageDigest(selected)
	if err != nil {
		return p, envelope, err
	}
	metadata := transport.NativeShareEpochSourceMetadata{Recipient: recipient, Source: sourceContext, RecipientPackageDigest: digest}
	aad, err := metadata.AAD()
	if err != nil {
		return p, envelope, err
	}
	holder, _ := hex.DecodeString(sourceContext.HolderX25519)
	enc, ct, err := e2ee.HPKEWrap(holder, []byte(transport.NativeShareEpochSourceInfo), aad, key)
	if err != nil {
		return p, envelope, err
	}
	result := transport.NativeShareEpochSourceEnvelope{Metadata: metadata, Wrapped: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}}
	signed, err := result.SignatureBytes()
	if err != nil {
		return p, envelope, err
	}
	result.Signature = ed25519.Sign(source, signed)
	return selected, result, nil
}

// OpenNativeShareEpochSource verifies independently pinned context before opening
// exactly one prospective key. It cannot persist or install that key.
func OpenNativeShareEpochSource(p transport.NativeShareEpochSourceEnvelope, expected transport.NativeShareEpochSourceMetadata, trustedSource ed25519.PublicKey, holderPrivate []byte, now time.Time) (*NativeShareEpochKey, error) {
	if err := p.Verify(expected, trustedSource, now); err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(holderPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != expected.Source.HolderX25519 {
		return nil, errNativeShareEpoch
	}
	aad, err := expected.AAD()
	if err != nil {
		return nil, err
	}
	key, err := e2ee.HPKEUnwrap(holderPrivate, p.Wrapped.Enc, []byte(transport.NativeShareEpochSourceInfo), aad, p.Wrapped.Ciphertext)
	if err != nil {
		clearNativeShareEpoch(key)
		return nil, err
	}
	if len(key) != 32 {
		clearNativeShareEpoch(key)
		return nil, errNativeShareEpoch
	}
	verifier, err := nativeShareEpochPossessionVerifier(key, expected.Recipient.NetworkID, expected.Recipient.EpochID)
	if err != nil || hex.EncodeToString(verifier) != expected.Recipient.EpochPossessionVerifier {
		clearNativeShareEpoch(key)
		return nil, errNativeShareEpoch
	}
	return &NativeShareEpochKey{EpochID: expected.Recipient.EpochID, Key: key}, nil
}
