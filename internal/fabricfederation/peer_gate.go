// Package fabricfederation composes current retained peer identity with the
// public federation crypto/forward/admission ports. Peer trust is not caller policy.
package fabricfederation

import (
	"bytes"
	"context"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type Config struct {
	Peers         *registry.PeerIdentity
	Owner         func(context.Context) (fabric.ExecutionContext, error)
	Local, Remote registry.CertifiedPeer
}
type PeerGate struct {
	config        Config
	local, remote federation.PeerBinding
}

func denied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current certified federation pair required")
}
func cloneCertified(c registry.CertifiedPeer) registry.CertifiedPeer {
	c.Authority.PublicKey = bytes.Clone(c.Authority.PublicKey)
	c.Certificate.Signature = bytes.Clone(c.Certificate.Signature)
	return c
}

// Binding verifies certificate metadata but does not grant trust. Only the
// actual signed pin's current transaction check may authorize this binding.
func Binding(c registry.CertifiedPeer) (federation.PeerBinding, error) {
	digest, e := c.Certificate.Digest()
	f := c.Certificate.Certificate
	if e != nil || c.Revision == 0 || digest != c.Digest || fabric.VerifyPeerCertificate(c.Certificate, time.Now()) != nil || c.Authority.Namespace != f.Namespace || c.Authority.StoreID != f.StoreID || c.Authority.KeyRevision != f.RootKeyRevision || !bytes.Equal(c.Authority.PublicKey, f.RootPublicKey[:]) {
		return federation.PeerBinding{}, denied()
	}
	expires, e := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	if e != nil {
		return federation.PeerBinding{}, denied()
	}
	c = cloneCertified(c)
	return federation.PeerBinding{Authority: c.Authority, ExchangePublicKey: f.ExchangePublicKey, ExchangeKeyRevision: f.ExchangeKeyRevision, BindingDigest: digest, ExpiresAt: expires}, nil
}
func New(ctx context.Context, c Config) (*PeerGate, error) {
	if ctx == nil || c.Peers == nil || c.Owner == nil {
		return nil, denied()
	}
	c.Local = cloneCertified(c.Local)
	c.Remote = cloneCertified(c.Remote)
	local, e := Binding(c.Local)
	if e != nil {
		return nil, e
	}
	remote, e := Binding(c.Remote)
	if e != nil {
		return nil, e
	}
	g := &PeerGate{c, local, remote}
	owner, e := c.Owner(ctx)
	if e != nil {
		return nil, denied()
	}
	if e = c.Peers.WithCurrent(ctx, owner, c.Local, c.Remote, func(context.Context) error { return nil }); e != nil {
		return nil, e
	}
	return g, nil
}
func sameBinding(a, b federation.PeerBinding) bool {
	return a.Authority.Namespace == b.Authority.Namespace && a.Authority.StoreID == b.Authority.StoreID && a.Authority.Owner == b.Authority.Owner && a.Authority.KeyRevision == b.Authority.KeyRevision && bytes.Equal(a.Authority.PublicKey, b.Authority.PublicKey) && a.ExchangePublicKey == b.ExchangePublicKey && a.ExchangeKeyRevision == b.ExchangeKeyRevision && a.BindingDigest == b.BindingDigest && a.ExpiresAt.Equal(b.ExpiresAt)
}
func (g *PeerGate) pair(local, remote federation.PeerBinding) bool {
	return g != nil && sameBinding(local, g.local) && sameBinding(remote, g.remote)
}
func (g *PeerGate) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := g.local.ExpiresAt
	if g.remote.ExpiresAt.Before(deadline) {
		deadline = g.remote.ExpiresAt
	}
	return context.WithDeadline(ctx, deadline)
}
func (g *PeerGate) WithCurrent(ctx context.Context, local, remote federation.PeerBinding, step func(context.Context) error) error {
	if ctx == nil || step == nil || !g.pair(local, remote) {
		return denied()
	}
	owner, e := g.config.Owner(ctx)
	if e != nil {
		return denied()
	}
	return g.config.Peers.WithCurrent(ctx, owner, g.config.Local, g.config.Remote, step)
}

// WithCurrentTx is admission-only. No provider IO, owner-session lookup or
// nested registry call occurs while the caller holds the actual SQL transaction.
func (g *PeerGate) WithCurrentTx(ctx context.Context, tx *registry.AuthorityTx, local, remote federation.PeerBinding, step func(context.Context) error) error {
	if ctx == nil || step == nil || !g.pair(local, remote) {
		return denied()
	}
	bounded, cancel := g.deadline(ctx)
	defer cancel()
	if bounded.Err() != nil {
		return bounded.Err()
	}
	if e := g.config.Peers.CheckCurrentTx(tx, g.config.Local, g.config.Remote); e != nil {
		return e
	}
	if e := step(bounded); e != nil {
		return e
	}
	if e := bounded.Err(); e != nil {
		return e
	}
	return g.config.Peers.CheckCurrentTx(tx, g.config.Local, g.config.Remote)
}
func (g *PeerGate) forward(f registry.ForwardFacts) bool {
	c := f.Frame
	return g != nil && c.SourceDomain == g.local.Authority.Namespace && c.SourceStoreID == g.local.Authority.StoreID && c.SourceKeyRevision == g.local.Authority.KeyRevision && c.DestinationDomain == g.remote.Authority.Namespace && c.DestinationStoreID == g.remote.Authority.StoreID && c.SourcePeerBindingDigest == g.local.BindingDigest && c.DestinationPeerBindingDigest == g.remote.BindingDigest && c.BindingProfile == federation.Profile
}

// WithForward checks live operator policy BEFORE SignForwardExact opens its
// same-store transaction. It does not hold that transaction recursively.
func (g *PeerGate) WithForward(ctx context.Context, f registry.ForwardFacts, step func(context.Context) error) error {
	if ctx == nil || step == nil || !g.forward(f) {
		return denied()
	}
	owner, e := g.config.Owner(ctx)
	if e != nil {
		return denied()
	}
	if e = g.config.Peers.CheckOwner(ctx, owner); e != nil {
		return e
	}
	bounded, cancel := g.deadline(ctx)
	defer cancel()
	if e = bounded.Err(); e != nil {
		return e
	}
	if e = step(bounded); e != nil {
		return e
	}
	return bounded.Err()
}
func (g *PeerGate) CheckForwardTx(ctx context.Context, tx *registry.AuthorityTx, f registry.ForwardFacts) error {
	if ctx == nil || ctx.Err() != nil || !g.forward(f) {
		return denied()
	}
	return g.config.Peers.CheckCurrentTx(tx, g.config.Local, g.config.Remote)
}

var _ federation.TrustGate = (*PeerGate)(nil)
var _ federation.PeerTxGate = (*PeerGate)(nil)
var _ registry.ForwardGate = (*PeerGate)(nil)
var _ registry.ForwardTransactionGate = (*PeerGate)(nil)
