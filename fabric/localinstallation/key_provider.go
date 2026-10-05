package localinstallation

import (
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"sync"
)

// KeyProvider retains one operator-owned encryption secret. It exposes only
// bounded encryption operations and opaque reference metadata, never key bytes.
// Close clears raw storage and prevents new encryption/decryption. Go's AES
// implementation does not promise erasure of transient expanded cipher state.
type KeyProvider struct {
	mu        sync.RWMutex
	key       [32]byte
	reference durable.KeyReference
	closed    bool
}

func (*KeyProvider) MarshalJSON() ([]byte, error) { return nil, denied() }
func (*KeyProvider) UnmarshalJSON([]byte) error   { return denied() }

func (p *KeyProvider) Reference() durable.KeyReference { return p.reference }
func (p *KeyProvider) apply(aad, data []byte, seal bool) ([]byte, error) {
	limit := 32 << 20
	if !seal {
		limit += 28
	} // AES-GCM's original 12-byte nonce and 16-byte tag.
	if len(aad) > 64<<10 || len(data) > limit {
		return nil, denied()
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, denied()
	}
	cipher, e := durable.NewAESGCM(p.reference, p.key[:])
	if e != nil {
		return nil, e
	}
	if seal {
		return cipher.Seal(aad, data)
	}
	return cipher.Open(aad, data)
}
func (p *KeyProvider) Seal(aad, plaintext []byte) ([]byte, error) {
	return p.apply(aad, plaintext, true)
}
func (p *KeyProvider) Open(aad, ciphertext []byte) ([]byte, error) {
	return p.apply(aad, ciphertext, false)
}
func (p *KeyProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	clear(p.key[:])
	return nil
}

var _ durable.DataProtector = (*KeyProvider)(nil)
