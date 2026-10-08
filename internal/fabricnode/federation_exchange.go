// Package fabricnode (part of the installed federation product).
//
// FederationExchangeKeys retains the node's X25519 federation exchange keypair
// as a single sealed record in the native authority store. The seal AAD is the
// node's OWN namespace/store identity — not the operator principal — because
// the transport's federation.KeyProvider read is per-connection and carries only
// the local PeerBinding (no owner); the write path stays owner-guarded at the
// store/CAS level. The record holds only the independent exchange keypair, never
// a converted domain signing key.
package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const exchangeKeyVersion = "pagnet.fabric.federation.exchange-key.v1"
const exchangeKeyFormat = 1

// exchangeKeyRecord is the sealed plaintext: the independent X25519 keypair and
// its monotonically advancing revision. It is never stored unsealed.
type exchangeKeyRecord struct {
	Format      int      `json:"format"`
	KeyRevision uint64   `json:"keyRevision,string"`
	PublicKey   [32]byte `json:"publicKey"`
	PrivateKey  [32]byte `json:"privateKey"`
}

// exchangeKeyCipher is the retained authority-record value: a versioned,
// key-referenced seal of exchangeKeyRecord.
type exchangeKeyCipher struct {
	Version    string               `json:"version"`
	Key        durable.KeyReference `json:"key"`
	Ciphertext []byte               `json:"ciphertext"`
}

// FederationExchangeKeys is the retained, owner-guarded X25519 exchange-keypair
// store. It implements federation.KeyProvider: the transport resolves the local
// private key per-connection from the certified PeerBinding.
type FederationExchangeKeys struct {
	store     *registry.Store
	root      registry.AuthorityIdentity
	owner     func(context.Context) (fabric.ExecutionContext, error)
	operator  LocalOperator
	protector durable.DataProtector
}

func exchangeKeyKey() registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityFederationPeer, ID: "local.exchange"}
}
func exchangeScope() registry.AuthorityScope {
	return registry.AuthorityScope{MaxOperations: 4, Timeout: time.Second}
}

// NewFederationExchangeKeys composes the exchange-key store over the
// installation's actual store, operator and sealing key. A missing record is
// not an error: the first certify creates it.
func NewFederationExchangeKeys(installation *localinstallation.Installation) (*FederationExchangeKeys, error) {
	if installation == nil || installation.Store == nil || installation.Keys == nil {
		return nil, localDenied()
	}
	return &FederationExchangeKeys{
		store:     installation.Store,
		root:      installation.Store.AuthorityIdentity(),
		owner:     installation.Operator,
		operator:  installation,
		protector: installation.Keys,
	}, nil
}

// aad binds the seal to the node's own namespace/store identity (reproducible
// from a PeerBinding.Authority), never to the operator principal.
func (k *FederationExchangeKeys) aad(namespace, storeID string) []byte {
	raw, _ := json.Marshal(struct {
		Purpose, Domain, Store string
		Key                    durable.KeyReference
	}{exchangeKeyVersion, namespace, storeID, k.protector.Reference()})
	return raw
}

func (k *FederationExchangeKeys) current(ctx context.Context, c fabric.ExecutionContext, next func(context.Context) error) error {
	if k == nil || ctx == nil || c.VerifyAuthenticated(k.root.Namespace) != nil || c.PrincipalView() != k.root.Owner {
		return localDenied()
	}
	root, e := k.store.CurrentAuthorityIdentity(ctx)
	if e != nil || root.Namespace != k.root.Namespace || root.StoreID != k.root.StoreID || root.Owner != k.root.Owner || root.KeyRevision != k.root.KeyRevision || !bytes.Equal(root.PublicKey, k.root.PublicKey) {
		return localDenied()
	}
	return guardedBoundary(ctx, func(ctx context.Context, n func(context.Context) error) error {
		return k.operator.WithCurrentOperator(ctx, c, n)
	}, next)
}

// decodeRecord is the two-step open: verify the retained record, unwrap the
// versioned/key-referenced seal with the node-namespace AAD, and decode the
// keypair. A missing record is the caller's concern; any other failure denies.
func (k *FederationExchangeKeys) decodeRecord(row registry.AuthorityRecord, out *exchangeKeyRecord) error {
	if registry.VerifyAuthorityRecord(k.root, row) != nil || row.Retired {
		return localDenied()
	}
	var sealed exchangeKeyCipher
	if fabric.DecodeJSONWithLimits(row.Value, &sealed, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 512}) != nil || sealed.Version != exchangeKeyVersion || sealed.Key != k.protector.Reference() {
		return localDenied()
	}
	raw, e := k.protector.Open(k.aad(k.root.Namespace, k.root.StoreID), sealed.Ciphertext)
	if e != nil {
		return e
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxMembers: 512}) != nil || out.Format != exchangeKeyFormat {
		return localDenied()
	}
	return nil
}

// Current returns the retained exchange keypair and its ledger revision. A
// missing record is the not-configured state: zero values, found=false, no
// error. Any other read failure (corrupt record, owner fence) still denies.
func (k *FederationExchangeKeys) Current(ctx context.Context, owner fabric.ExecutionContext) ([32]byte, uint64, uint64, bool, error) {
	var pub [32]byte
	var keyRevision, ledgerRevision uint64
	var found bool
	if k == nil {
		return pub, 0, 0, false, localDenied()
	}
	e := k.current(ctx, owner, func(ctx context.Context) error {
		return k.store.WithNativeAuthority(ctx, owner, exchangeScope(), func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(exchangeKeyKey())
			if e != nil {
				var missing *fabric.Error
				if errors.As(e, &missing) && missing.Code == fabric.CodeNotFound {
					return nil
				}
				return e
			}
			var record exchangeKeyRecord
			if e := k.decodeRecord(row, &record); e != nil {
				return e
			}
			pub = record.PublicKey
			keyRevision = record.KeyRevision
			ledgerRevision = row.Revision
			found = true
			clear(record.PrivateKey[:])
			return nil
		})
	})
	return pub, keyRevision, ledgerRevision, found, e
}

// GenerateOrRotate generates a fresh X25519 keypair at the next revision and
// CAS-commits the sealed record. The base is the caller-supplied ledger
// revision (0 for the first record); a stale base conflicts. The returned
// public key is the one to certify.
func (k *FederationExchangeKeys) GenerateOrRotate(ctx context.Context, owner fabric.ExecutionContext, expectedLedgerRevision uint64) ([32]byte, uint64, uint64, error) {
	var pub [32]byte
	if k == nil {
		return pub, 0, 0, localDenied()
	}
	var keyRevision, ledgerRevision uint64
	e := k.current(ctx, owner, func(ctx context.Context) error {
		return k.store.WithNativeAuthority(ctx, owner, exchangeScope(), func(tx *registry.AuthorityTx) error {
			var prior uint64
			if row, e := tx.Get(exchangeKeyKey()); e == nil {
				if row.Retired {
					return localDenied()
				}
				var record exchangeKeyRecord
				if e := k.decodeRecord(row, &record); e != nil {
					return e
				}
				prior = record.KeyRevision
				clear(record.PrivateKey[:])
			} else {
				var missing *fabric.Error
				if !errors.As(e, &missing) || missing.Code != fabric.CodeNotFound {
					return e
				}
			}
			next := prior + 1
			pubKey, privKey, e := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
			if e != nil {
				return localDenied()
			}
			pubRaw, e := pubKey.MarshalBinary()
			if e != nil || len(pubRaw) != 32 {
				return localDenied()
			}
			privRaw, e := privKey.MarshalBinary()
			if e != nil || len(privRaw) != 32 {
				return localDenied()
			}
			record := exchangeKeyRecord{Format: exchangeKeyFormat, KeyRevision: next}
			copy(record.PublicKey[:], pubRaw)
			copy(record.PrivateKey[:], privRaw)
			plaintext, e := json.Marshal(record)
			if e != nil {
				return localDenied()
			}
			clear(record.PrivateKey[:])
			clear(privRaw)
			sealed, e := k.protector.Seal(k.aad(k.root.Namespace, k.root.StoreID), plaintext)
			clear(plaintext)
			if e != nil {
				return e
			}
			value, e := json.Marshal(exchangeKeyCipher{exchangeKeyVersion, k.protector.Reference(), sealed})
			clear(sealed)
			if e != nil {
				return localDenied()
			}
			committed, e := tx.CAS(exchangeKeyKey(), expectedLedgerRevision, value, false)
			clear(value)
			if e != nil {
				return e
			}
			copy(pub[:], pubRaw)
			keyRevision = next
			ledgerRevision = committed.Revision
			return nil
		})
	})
	return pub, keyRevision, ledgerRevision, e
}

// ExchangePrivateKey implements federation.KeyProvider. It resolves the local
// private exchange key for the certified PeerBinding, opening the seal with the
// node-namespace AAD (no owner). The returned bytes are a fresh copy owned by
// the transport, which clears them after setup.
func (k *FederationExchangeKeys) ExchangePrivateKey(ctx context.Context, binding federation.PeerBinding) ([]byte, error) {
	if k == nil || ctx == nil {
		return nil, fabric.NewError(fabric.CodeNotFound, "Federation exchange key not configured")
	}
	if binding.Authority.Namespace != k.root.Namespace || binding.Authority.StoreID != k.root.StoreID {
		return nil, fabric.NewError(fabric.CodeUnauthenticated, "Federation exchange binding is not this node")
	}
	owner, e := k.owner(ctx)
	if e != nil {
		return nil, e
	}
	var out []byte
	e = k.current(ctx, owner, func(ctx context.Context) error {
		return k.store.WithNativeAuthority(ctx, owner, exchangeScope(), func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(exchangeKeyKey())
			if e != nil {
				var missing *fabric.Error
				if errors.As(e, &missing) && missing.Code == fabric.CodeNotFound {
					return fabric.NewError(fabric.CodeNotFound, "Federation exchange key not configured")
				}
				return e
			}
			var record exchangeKeyRecord
			if e := k.decodeRecord(row, &record); e != nil {
				return e
			}
			if binding.ExchangePublicKey != record.PublicKey || binding.ExchangeKeyRevision != record.KeyRevision {
				return fabric.NewError(fabric.CodeUnauthenticated, "Federation exchange binding does not match the current key")
			}
			out = make([]byte, 32)
			copy(out, record.PrivateKey[:])
			clear(record.PrivateKey[:])
			return nil
		})
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
