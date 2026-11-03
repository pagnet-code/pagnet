package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

var errNativeShareEpoch = errors.New("crypto: invalid native share epoch")

// FreshNativeShareEpoch can only be created with NewFreshNativeShareEpoch.
// CSPRNG construction and one-shot consumption guarantee fresh material without
// accepting an existing KeyEpoch or Keyring. Copies share consumption state.
// It has no key export/clone path and never inserts material into a keyring.
type FreshNativeShareEpoch struct{ secret *nativeShareEpochSecret }
type nativeShareEpochSecret struct {
	mu  sync.Mutex
	id  domain.ID
	key []byte
}

func NewFreshNativeShareEpoch() (*FreshNativeShareEpoch, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		clearNativeShareEpoch(key)
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		clearNativeShareEpoch(key)
		return nil, err
	}
	return &FreshNativeShareEpoch{secret: &nativeShareEpochSecret{id: domain.ID(id.String()), key: key}}, nil
}

func (f *FreshNativeShareEpoch) ID() domain.ID {
	if f == nil || f.secret == nil {
		return ""
	}
	return f.secret.id
}

// Destroy clears the owned buffer best-effort. Go and the HPKE implementation
// may retain internal copies; this is not a guaranteed memory erasure primitive.
func (f *FreshNativeShareEpoch) Destroy() {
	if f == nil || f.secret == nil {
		return
	}
	f.secret.mu.Lock()
	defer f.secret.mu.Unlock()
	clearNativeShareEpoch(f.secret.key)
	f.secret.key = nil
}

func clearNativeShareEpoch(key []byte) { clear(key); runtime.KeepAlive(key) }

// SealNativeShareEpoch consumes fresh even when validation or encryption fails.
// The caller must independently authorize metadata and source signing authority.
func SealNativeShareEpoch(fresh *FreshNativeShareEpoch, metadata transport.NativeShareEpochMetadata, source ed25519.PrivateKey, now time.Time) (transport.NativeShareEpochPackage, error) {
	var p transport.NativeShareEpochPackage
	if fresh == nil || fresh.secret == nil {
		return p, errNativeShareEpoch
	}
	s := fresh.secret
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key
	s.key = nil
	defer clearNativeShareEpoch(key)
	if len(key) != 32 || metadata.EpochID != s.id || len(source) != ed25519.PrivateKeySize {
		return p, errNativeShareEpoch
	}
	aad, err := metadata.AAD()
	if err != nil {
		return p, err
	}
	deadline, _ := time.Parse(time.RFC3339Nano, metadata.Deadline)
	if now.IsZero() || !now.Before(deadline) {
		return p, errNativeShareEpoch
	}
	holder, _ := hex.DecodeString(metadata.HolderX25519)
	enc, ct, err := e2ee.HPKEWrap(holder, []byte(transport.NativeShareEpochInfo), aad, key)
	if err != nil {
		return p, err
	}
	p = transport.NativeShareEpochPackage{Metadata: metadata, Wrapped: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ct}}
	signed, err := p.SignatureBytes()
	if err != nil {
		return transport.NativeShareEpochPackage{}, err
	}
	p.Signature = ed25519.Sign(source, signed)
	return p, nil
}

// NativeShareEpochKey is exactly one prospective epoch; it carries no lifecycle
// state, source key, or historical keys. The caller owns Key and should Destroy it.
type NativeShareEpochKey struct {
	EpochID domain.ID
	Key     []byte
}

// String omits key material from diagnostics.
func (k NativeShareEpochKey) String() string {
	return fmt.Sprintf("NativeShareEpochKey{epoch=%s}", k.EpochID)
}

func (k *NativeShareEpochKey) Destroy() {
	if k != nil {
		clearNativeShareEpoch(k.Key)
		k.Key = nil
	}
}

// OpenNativeShareEpoch verifies caller-pinned authority/context before HPKE open.
// It returns material only; it cannot stage, install, commit or activate an epoch.
func OpenNativeShareEpoch(p transport.NativeShareEpochPackage, expected transport.NativeShareEpochMetadata, trustedSource ed25519.PublicKey, holderPrivate []byte, now time.Time) (*NativeShareEpochKey, error) {
	if err := p.Verify(expected, trustedSource, now); err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(holderPrivate)
	if err != nil || hex.EncodeToString(private.PublicKey().Bytes()) != expected.HolderX25519 {
		return nil, errNativeShareEpoch
	}
	aad, err := expected.AAD()
	if err != nil {
		return nil, err
	}
	key, err := e2ee.HPKEUnwrap(holderPrivate, p.Wrapped.Enc, []byte(transport.NativeShareEpochInfo), aad, p.Wrapped.Ciphertext)
	if err != nil {
		clearNativeShareEpoch(key)
		return nil, err
	}
	if len(key) != 32 {
		clearNativeShareEpoch(key)
		return nil, errNativeShareEpoch
	}
	return &NativeShareEpochKey{EpochID: expected.EpochID, Key: key}, nil
}
