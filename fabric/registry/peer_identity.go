package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// PeerOwnerValidator rechecks genuine current operator authentication, not an
// asserted or serialized principal. It must not call this handle recursively.
// MaxPeerPinBytes covers both canonical 4096-byte owner fields, including
// worst-case JSON escaping, plus finite certificate fields within one ledger record.
const MaxPeerPinBytes = 64 << 10

type PeerOwnerValidator func(context.Context, fabric.ExecutionContext, AuthorityIdentity) error
type PeerIdentity struct {
	root     *Store
	identity AuthorityIdentity
	owner    PeerOwnerValidator
}
type CertifiedPeer struct {
	Authority   AuthorityIdentity
	Certificate fabric.SignedPeerCertificate
	Digest      [32]byte
	Revision    uint64
}
type peerPin struct {
	Format      int                          `json:"format"`
	Authority   AuthorityIdentity            `json:"authority"`
	Certificate fabric.SignedPeerCertificate `json:"certificate"`
	Revoked     bool                         `json:"revoked"`
}

func NewPeerIdentity(ctx context.Context, root *Store, gate PeerOwnerValidator) (*PeerIdentity, error) {
	if ctx == nil || root == nil || gate == nil {
		return nil, invalid("Current peer owner authentication required")
	}
	identity, e := root.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	return &PeerIdentity{root, identity, gate}, nil
}
func (p *PeerIdentity) authorize(ctx context.Context, owner fabric.ExecutionContext) error {
	if p == nil || ctx == nil || owner.VerifyAuthenticated(p.identity.Namespace) != nil || owner.PrincipalView() != p.identity.Owner {
		return unauthPeer()
	}
	current, e := p.root.CurrentAuthorityIdentity(ctx)
	if e != nil || !peerSameRoot(current, p.identity) {
		return unauthPeer()
	}
	if e = p.owner(ctx, owner, current); e != nil {
		return unauthPeer()
	}
	return nil
}

// CheckOwner validates live operator authority before an independent forwarding
// policy callback. Never call it from inside this store's authority transaction.
func (p *PeerIdentity) CheckOwner(ctx context.Context, owner fabric.ExecutionContext) error {
	return p.authorize(ctx, owner)
}
func unauthPeer() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Certified current federation peer required")
}
func peerSameRoot(a, b AuthorityIdentity) bool {
	return a.Namespace == b.Namespace && a.StoreID == b.StoreID && a.Owner == b.Owner && a.KeyRevision == b.KeyRevision && bytes.Equal(a.PublicKey, b.PublicKey)
}
func peerKey(namespace, storeID string) AuthorityKey {
	digest := sha256.Sum256([]byte(namespace + "\x00" + storeID))
	return AuthorityKey{Kind: AuthorityFederationPeer, ID: "peer." + hex.EncodeToString(digest[:])}
}
func localPeerKey() AuthorityKey {
	return AuthorityKey{Kind: AuthorityFederationPeer, ID: "local.certificate"}
}
func peerScope() AuthorityScope { return AuthorityScope{MaxOperations: 8, Timeout: time.Second} }
func clonePeerPin(v peerPin) (peerPin, error) {
	if len(v.Authority.PublicKey) != 32 || !text(v.Authority.Owner.Ref, 4096, false) || !text(v.Authority.Owner.Issuer, 4096, false) || !fabric.ValidNamespacedName(v.Authority.Owner.Kind) {
		return peerPin{}, unauthPeer()
	}
	if _, e := v.Certificate.Digest(); e != nil {
		return peerPin{}, e
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > MaxPeerPinBytes {
		return peerPin{}, invalid("Peer certificate exceeds bounds")
	}
	var owned peerPin
	if fabric.DecodeJSONWithLimits(raw, &owned, fabric.WireLimits{MaxBytes: MaxPeerPinBytes, MaxDepth: 16, MaxMembers: 128}) != nil {
		return peerPin{}, invalid("Malformed peer certificate")
	}
	return owned, nil
}
func validatePeerPin(v peerPin, now time.Time) error {
	if v.Format != 1 || len(v.Authority.PublicKey) != ed25519.PublicKeySize || !text(v.Authority.Owner.Ref, 4096, false) || !text(v.Authority.Owner.Issuer, 4096, false) || !fabric.ValidNamespacedName(v.Authority.Owner.Kind) || v.Certificate.Certificate.Namespace != v.Authority.Namespace || v.Certificate.Certificate.StoreID != v.Authority.StoreID || v.Certificate.Certificate.RootKeyRevision != v.Authority.KeyRevision || !bytes.Equal(v.Certificate.Certificate.RootPublicKey[:], v.Authority.PublicKey) {
		return unauthPeer()
	}
	return fabric.VerifyPeerCertificate(v.Certificate, now)
}
func readPeer(tx *AuthorityTx, key AuthorityKey, now time.Time) (CertifiedPeer, error) {
	record, e := tx.Get(key)
	if e != nil {
		return CertifiedPeer{}, e
	}
	var v peerPin
	if record.Retired || fabric.DecodeJSONWithLimits(record.Value, &v, fabric.WireLimits{MaxBytes: MaxPeerPinBytes, MaxDepth: 16, MaxMembers: 128}) != nil || v.Revoked || validatePeerPin(v, now) != nil {
		return CertifiedPeer{}, unauthPeer()
	}
	if key != localPeerKey() && key != peerKey(v.Authority.Namespace, v.Authority.StoreID) {
		return CertifiedPeer{}, unauthPeer()
	}
	digest, e := v.Certificate.Digest()
	if e != nil {
		return CertifiedPeer{}, e
	}
	return CertifiedPeer{v.Authority, v.Certificate, digest, record.Revision}, nil
}
func currentRevision(tx *AuthorityTx, key AuthorityKey, expected uint64, next peerPin) error {
	old, e := tx.Get(key)
	if e != nil {
		var typed *fabric.Error
		if expected == 0 && errors.As(e, &typed) && typed.Code == fabric.CodeNotFound {
			return nil
		}
		return conflict("Peer pin revision conflict")
	}
	var prior peerPin
	if old.Retired || old.Revision != expected || fabric.DecodeJSON(old.Value, &prior) != nil || prior.Format != 1 || !peerSameRoot(prior.Authority, next.Authority) {
		return conflict("Peer pin revision conflict")
	}
	// Revocation does not erase the original proof or permit old-key resurrection.
	if _, e := prior.Certificate.Digest(); e != nil {
		return unauthPeer()
	}
	a, b := prior.Certificate.Certificate, next.Certificate.Certificate
	if b.ExchangeKeyRevision < a.ExchangeKeyRevision || (prior.Revoked || b.ExchangePublicKey != a.ExchangePublicKey) && b.ExchangeKeyRevision <= a.ExchangeKeyRevision {
		return conflict("Peer key rotation must advance revision")
	}
	return nil
}

// CertifyLocal signs ONLY the selected independent public exchange key using
// the actual retained root. No private key conversion/export exists here.
func (p *PeerIdentity) CertifyLocal(ctx context.Context, owner fabric.ExecutionContext, expected uint64, exchange [32]byte, keyRevision uint64, issued, expires time.Time) (CertifiedPeer, error) {
	if e := p.authorize(ctx, owner); e != nil {
		return CertifiedPeer{}, e
	}
	frame := fabric.PeerCertificate{Namespace: p.identity.Namespace, StoreID: p.identity.StoreID, RootKeyRevision: p.identity.KeyRevision, ExchangePublicKey: exchange, ExchangeKeyRevision: keyRevision, BindingProfile: fabric.ForwardBindingProfile, IssuedAt: issued.UTC().Format(time.RFC3339Nano), ExpiresAt: expires.UTC().Format(time.RFC3339Nano)}
	copy(frame.RootPublicKey[:], p.identity.PublicKey)
	raw, e := frame.SigningBytes()
	if e != nil {
		return CertifiedPeer{}, e
	}
	if time.Now().Before(issued) || !time.Now().Before(expires) {
		return CertifiedPeer{}, unauthPeer()
	}
	var result CertifiedPeer
	e = p.root.WithNativeAuthority(ctx, owner, peerScope(), func(tx *AuthorityTx) error {
		// This closed signing purpose remains inside the real owner transaction.
		signed := fabric.SignedPeerCertificate{Certificate: frame, Signature: ed25519.Sign(p.root.key, raw)}
		v := peerPin{1, p.identity, signed, false}
		if e := currentRevision(tx, localPeerKey(), expected, v); e != nil {
			return e
		}
		value, _ := json.Marshal(v)
		if _, e := tx.CAS(localPeerKey(), expected, value, false); e != nil {
			return e
		}
		var e error
		result, e = readPeer(tx, localPeerKey(), time.Now())
		return e
	})
	if e != nil {
		return CertifiedPeer{}, e
	}
	return result, nil
}

// PinRemote is explicit owner approval of a complete original authority and
// certificate, never DNS discovery or signature-only automatic trust.
func (p *PeerIdentity) PinRemote(ctx context.Context, owner fabric.ExecutionContext, expected uint64, authority AuthorityIdentity, certificate fabric.SignedPeerCertificate) (CertifiedPeer, error) {
	if e := p.authorize(ctx, owner); e != nil {
		return CertifiedPeer{}, e
	}
	v, e := clonePeerPin(peerPin{1, authority, certificate, false})
	if e != nil {
		return CertifiedPeer{}, e
	}
	if v.Authority.Namespace == p.identity.Namespace || validatePeerPin(v, time.Now()) != nil {
		return CertifiedPeer{}, unauthPeer()
	}
	key := peerKey(v.Authority.Namespace, v.Authority.StoreID)
	var result CertifiedPeer
	e = p.root.WithNativeAuthority(ctx, owner, peerScope(), func(tx *AuthorityTx) error {
		if e := currentRevision(tx, key, expected, v); e != nil {
			return e
		}
		value, _ := json.Marshal(v)
		if _, e := tx.CAS(key, expected, value, false); e != nil {
			return e
		}
		var e error
		result, e = readPeer(tx, key, time.Now())
		return e
	})
	if e != nil {
		return CertifiedPeer{}, e
	}
	return result, nil
}
func (p *PeerIdentity) Local(ctx context.Context, owner fabric.ExecutionContext) (CertifiedPeer, error) {
	return p.get(ctx, owner, localPeerKey())
}
func (p *PeerIdentity) Remote(ctx context.Context, owner fabric.ExecutionContext, namespace, storeID string) (CertifiedPeer, error) {
	if len(namespace) != 54 || len(storeID) != 64 {
		return CertifiedPeer{}, unauthPeer()
	}
	return p.get(ctx, owner, peerKey(namespace, storeID))
}
func (p *PeerIdentity) get(ctx context.Context, owner fabric.ExecutionContext, key AuthorityKey) (CertifiedPeer, error) {
	if e := p.authorize(ctx, owner); e != nil {
		return CertifiedPeer{}, e
	}
	var result CertifiedPeer
	e := p.root.WithNativeAuthority(ctx, owner, peerScope(), func(tx *AuthorityTx) error {
		var e error
		result, e = readPeer(tx, key, time.Now())
		if e == nil && key == localPeerKey() && !peerSameRoot(result.Authority, p.identity) {
			return unauthPeer()
		}
		return e
	})
	if e != nil {
		return CertifiedPeer{}, e
	}
	return result, nil
}
func (p *PeerIdentity) RevokeLocal(ctx context.Context, owner fabric.ExecutionContext, expected uint64) error {
	return p.revoke(ctx, owner, localPeerKey(), expected)
}
func (p *PeerIdentity) RevokeRemote(ctx context.Context, owner fabric.ExecutionContext, namespace, storeID string, expected uint64) error {
	if len(namespace) != 54 || len(storeID) != 64 {
		return unauthPeer()
	}
	return p.revoke(ctx, owner, peerKey(namespace, storeID), expected)
}
func (p *PeerIdentity) revoke(ctx context.Context, owner fabric.ExecutionContext, key AuthorityKey, expected uint64) error {
	if e := p.authorize(ctx, owner); e != nil {
		return e
	}
	return p.root.WithNativeAuthority(ctx, owner, peerScope(), func(tx *AuthorityTx) error {
		record, e := tx.Get(key)
		if e != nil {
			return e
		}
		var v peerPin
		if record.Retired || record.Revision != expected || fabric.DecodeJSON(record.Value, &v) != nil || v.Format != 1 {
			return conflict("Peer revocation revision conflict")
		}
		v.Revoked = true
		raw, _ := json.Marshal(v)
		_, e = tx.CAS(key, expected, raw, false)
		return e
	})
}

// CheckCurrentTx is the narrow same-transaction seam for closed forwarding or
// admission ports. The transaction must belong to this exact retained store.
// No nested Store call or provider IO is permitted while this fence is held.
func (p *PeerIdentity) CheckCurrentTx(tx *AuthorityTx, local, remote CertifiedPeer) error {
	if p == nil || tx == nil || tx.store != p.root || !peerSameRoot(local.Authority, p.identity) || remote.Authority.Namespace == p.identity.Namespace || len(remote.Authority.Namespace) != 54 || len(remote.Authority.StoreID) != 64 {
		return unauthPeer()
	}
	actualLocal, e := readPeer(tx, localPeerKey(), time.Now())
	if e != nil {
		return e
	}
	actualRemote, e := readPeer(tx, peerKey(remote.Authority.Namespace, remote.Authority.StoreID), time.Now())
	if e != nil {
		return e
	}
	if !sameCertified(actualLocal, local) || !sameCertified(actualRemote, remote) {
		return unauthPeer()
	}
	return nil
}
func sameCertified(a, b CertifiedPeer) bool {
	digest, e := b.Certificate.Digest()
	return e == nil && digest == b.Digest && a.Revision == b.Revision && a.Digest == b.Digest && peerSameRoot(a.Authority, b.Authority)
}

// WithCurrent fences bounded synchronous cryptography against rotation and
// revocation. Callback is trusted infrastructure, not application/provider code;
// it may not start nested registry transactions. No execution is authorized.
func (p *PeerIdentity) WithCurrent(ctx context.Context, owner fabric.ExecutionContext, local, remote CertifiedPeer, callback func(context.Context) error) error {
	if callback == nil {
		return invalid("Peer fence callback required")
	}
	if e := p.authorize(ctx, owner); e != nil {
		return e
	}
	localExpiry, e := time.Parse(time.RFC3339Nano, local.Certificate.Certificate.ExpiresAt)
	if e != nil {
		return unauthPeer()
	}
	remoteExpiry, e := time.Parse(time.RFC3339Nano, remote.Certificate.Certificate.ExpiresAt)
	if e != nil {
		return unauthPeer()
	}
	if remoteExpiry.Before(localExpiry) {
		localExpiry = remoteExpiry
	}
	bounded, cancel := context.WithDeadline(ctx, localExpiry)
	defer cancel()
	return p.root.WithNativeAuthority(bounded, owner, peerScope(), func(tx *AuthorityTx) error {
		if e := p.CheckCurrentTx(tx, local, remote); e != nil {
			return e
		}
		if e := callback(tx.ctx); e != nil {
			return e
		}
		if e := tx.ctx.Err(); e != nil {
			return e
		}
		return p.CheckCurrentTx(tx, local, remote)
	})
}
