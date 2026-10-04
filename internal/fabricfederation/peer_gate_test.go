package fabricfederation

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/federation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type keyPort struct {
	keys  map[[32]byte][]byte
	roots map[string]*registry.Store
}

func (k keyPort) ExchangePrivateKey(ctx context.Context, p federation.PeerBinding) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// A selected key provider may query its retained root. It must be called
	// outside the same-root SQL fence, otherwise this bounded fixture fails.
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	root := k.roots[p.Authority.Namespace]
	if root == nil {
		return nil, denied()
	}
	result := make(chan error, 1)
	go func() {
		identity, e := root.CurrentAuthorityIdentity(bounded)
		if e == nil && (identity.StoreID != p.Authority.StoreID || identity.Namespace != p.Authority.Namespace) {
			e = denied()
		}
		result <- e
	}()
	select {
	case e := <-result:
		if e != nil {
			return nil, e
		}
	case <-bounded.Done():
		return nil, bounded.Err()
	}
	raw := k.keys[p.BindingDigest]
	if len(raw) != 32 {
		return nil, denied()
	}
	return bytes.Clone(raw), nil
}

type fixturePeer struct {
	root  *registry.Store
	peers *registry.PeerIdentity
	owner fabric.ExecutionContext
	cert  registry.CertifiedPeer
	key   []byte
}

func rootPeer(t *testing.T, ownerName string, issuerOverride ...string) fixturePeer {
	t.Helper()
	dir, e := os.MkdirTemp("", "pgn-peer-gate-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	issuer := strings.Repeat("i", 4096)
	if len(issuerOverride) > 0 {
		issuer = issuerOverride[0]
	}
	principal := fabric.Principal{Ref: ownerName, Issuer: issuer, Kind: "owner.test"}
	root, e := registry.Bootstrap(t.Context(), filepath.Join(dir, "domain"), principal)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	owner, e := fabric.NewAuthenticatedContext(principal, root.Namespace(), []byte("trusted infrastructure owner fixture"))
	if e != nil {
		t.Fatal(e)
	}
	gate := func(ctx context.Context, c fabric.ExecutionContext, r registry.AuthorityIdentity) error {
		if c.VerifyAuthenticated(r.Namespace) != nil || c.PrincipalView() != r.Owner {
			return denied()
		}
		return ctx.Err()
	}
	peers, e := registry.NewPeerIdentity(t.Context(), root, gate)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var pub [32]byte
	copy(pub[:], key.PublicKey().Bytes())
	now := time.Now()
	cert, e := peers.CertifyLocal(t.Context(), owner, 0, pub, 1, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	return fixturePeer{root, peers, owner, cert, key.Bytes()}
}
func pairFixture(t *testing.T) (fixturePeer, fixturePeer, *PeerGate, *PeerGate) {
	t.Helper()
	a := rootPeer(t, strings.Repeat("a", 4096))
	b := rootPeer(t, "remote-owner")
	remoteB, e := a.peers.PinRemote(t.Context(), a.owner, 0, b.cert.Authority, b.cert.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	remoteA, e := b.peers.PinRemote(t.Context(), b.owner, 0, a.cert.Authority, a.cert.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	ownerA := func(context.Context) (fabric.ExecutionContext, error) { return a.owner, nil }
	ownerB := func(context.Context) (fabric.ExecutionContext, error) { return b.owner, nil }
	ga, e := New(t.Context(), Config{a.peers, ownerA, a.cert, remoteB})
	if e != nil {
		t.Fatal(e)
	}
	gb, e := New(t.Context(), Config{b.peers, ownerB, b.cert, remoteA})
	if e != nil {
		t.Fatal(e)
	}
	return a, b, ga, gb
}
func forwardFixture(t *testing.T, a, b fixturePeer, g *PeerGate) (fabric.ExecutionContext, []byte, []byte, fabric.ForwardFrame) {
	t.Helper()
	now := time.Now().UTC()
	principal := fabric.Principal{Ref: "actual-caller", Kind: "actor.test", Issuer: a.root.Namespace()}
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "forward-exact", Operation: fabric.OperationDiscover, Principal: principal, Source: principal.Ref, CreatedAt: now, Payload: json.RawMessage(`{"query":"private","n":9007199254740993123456789}`), Context: fabric.EnvelopeContext{Origin: principal.Ref, IdempotencyKey: "forward-exact"}}
	original, _ := json.Marshal(env)
	env.Context.Hops = 1
	forwarded, _ := json.Marshal(env)
	caller, e := fabric.NewAuthenticatedContext(principal, a.root.Namespace(), original)
	if e != nil {
		t.Fatal(e)
	}
	frame := fabric.ForwardFrame{SourceDomain: a.cert.Authority.Namespace, SourceStoreID: a.cert.Authority.StoreID, SourceKeyRevision: a.cert.Authority.KeyRevision, DestinationDomain: b.cert.Authority.Namespace, DestinationStoreID: b.cert.Authority.StoreID, SourcePeerBindingDigest: g.local.BindingDigest, DestinationPeerBindingDigest: g.remote.BindingDigest, Principal: principal, Operation: fabric.OperationDiscover, InvocationID: env.ID, ReplayID: env.Context.IdempotencyKey, OriginalEnvelopeDigest: sha256.Sum256(original), ForwardedEnvelopeDigest: sha256.Sum256(forwarded), OriginalProvenance: fabric.Provenance{Origin: principal.Ref}, ForwardedProvenance: fabric.Provenance{Origin: principal.Ref, Hops: 1}, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), BindingProfile: federation.Profile}
	return caller, original, forwarded, frame
}
func TestActualCertifiedPairRootForwardSigningAndAuthenticatedHPKE(t *testing.T) {
	a, b, ga, gb := pairFixture(t)
	caller, original, forwarded, frame := forwardFixture(t, a, b, ga)
	proof, e := a.root.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, frame, ga)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := proof.Frame.SigningBytes()
	if e != nil || !ed25519.Verify(a.cert.Authority.PublicKey, raw, proof.Signature) {
		t.Fatal("actual root forward signature missing", e)
	}
	channel := federation.ChannelBinding{}
	rand.Read(channel.ID[:])
	rand.Read(channel.SourceRoute[:])
	rand.Read(channel.DestinationRoute[:])
	keys := keyPort{map[[32]byte][]byte{a.cert.Digest: a.key, b.cert.Digest: b.key}, map[string]*registry.Store{a.root.Namespace(): a.root, b.root.Namespace(): b.root}}
	source := federation.Config{Local: ga.local, Remote: ga.remote, Keys: keys, Trust: ga, Channel: channel, SourceRole: true, MaxRecords: 8}
	destination := federation.Config{Local: gb.local, Remote: gb.remote, Keys: keys, Trust: gb, Channel: channel, SourceRole: false, MaxRecords: 8}
	sender, e := federation.NewSender(t.Context(), source)
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := federation.NewReceiver(destination)
	if e != nil {
		t.Fatal(e)
	}
	packet, e := sender.Seal(t.Context(), forwarded)
	if e != nil {
		t.Fatal(e)
	}
	clear, e := receiver.Open(t.Context(), packet)
	if e != nil || !bytes.Equal(clear, forwarded) {
		t.Fatal("real HPKE changed original bytes", e)
	}
	// Destination admission check uses its existing real root transaction only.
	e = b.root.WithNativeAuthority(t.Context(), b.owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
		return gb.WithCurrentTx(t.Context(), tx, gb.local, gb.remote, func(context.Context) error { return nil })
	})
	if e != nil {
		t.Fatal("same TX destination fence", e)
	}
	if e = a.peers.RevokeRemote(t.Context(), a.owner, b.cert.Authority.Namespace, b.cert.Authority.StoreID, ga.config.Remote.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e = sender.Seal(t.Context(), forwarded); e == nil {
		t.Fatal("existing HPKE sender ignored revoked pin")
	}
	if _, e = a.root.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, frame, ga); e == nil {
		t.Fatal("source root signed revoked peer")
	}
}
func TestExactCertifiedPairCannotSubstituteProfileKeyPrincipalOrRevision(t *testing.T) {
	a, b, ga, _ := pairFixture(t)
	for _, change := range []func(*federation.PeerBinding){func(p *federation.PeerBinding) { p.ExchangePublicKey[0] ^= 1 }, func(p *federation.PeerBinding) { p.ExchangeKeyRevision++ }, func(p *federation.PeerBinding) { p.Authority.Owner.Issuer = "foreign-owner" }, func(p *federation.PeerBinding) { p.Authority.StoreID = strings.Repeat("b", 64) }, func(p *federation.PeerBinding) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) }, func(p *federation.PeerBinding) { p.BindingDigest[0] ^= 1 }} {
		bad := ga.remote
		bad.Authority.PublicKey = bytes.Clone(bad.Authority.PublicKey)
		change(&bad)
		called := false
		if e := ga.WithCurrent(t.Context(), ga.local, bad, func(context.Context) error { called = true; return nil }); e == nil || called {
			t.Fatal("substituted peer escaped exact pin fence")
		}
	}
	caller, original, forwarded, frame := forwardFixture(t, a, b, ga)
	wrong := frame
	wrong.Principal.Ref = "different-caller"
	if _, e := a.root.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, wrong, ga); e == nil {
		t.Fatal("peer key authority replaced caller authorization")
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var pub [32]byte
	copy(pub[:], key.PublicKey().Bytes())
	now := time.Now()
	newRemote, e := b.peers.CertifyLocal(t.Context(), b.owner, b.cert.Revision, pub, 2, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.peers.PinRemote(t.Context(), a.owner, ga.config.Remote.Revision, newRemote.Authority, newRemote.Certificate); e != nil {
		t.Fatal(e)
	}
	if e = ga.WithCurrent(t.Context(), ga.local, ga.remote, func(context.Context) error { return nil }); e == nil {
		t.Fatal("rotated certificate still treated current")
	}
	if _, e = a.root.SignForwardExact(t.Context(), a.owner, caller, original, forwarded, frame, ga); e == nil {
		t.Fatal("forward gate ignored certificate rotation")
	}
}

func TestPeerPinsAcceptCanonicalOwnerEscapingWithinFiniteRecordBudget(t *testing.T) {
	// Both authenticated owner fields are4096bytes; escaping their quotation
	// marks exceeds16KiB before certificate metadata, without using control text.
	a := rootPeer(t, strings.Repeat("\"", 4096), strings.Repeat("\"", 4096))
	b := rootPeer(t, "explicit-owner")
	pinned, e := b.peers.PinRemote(t.Context(), b.owner, 0, a.cert.Authority, a.cert.Certificate)
	if e != nil {
		t.Fatal("canonical root rejected by narrower peer pin format", e)
	}
	retained, e := b.peers.Remote(t.Context(), b.owner, a.cert.Authority.Namespace, a.cert.Authority.StoreID)
	if e != nil || retained.Digest != pinned.Digest || retained.Authority.Owner.Ref != a.cert.Authority.Owner.Ref {
		t.Fatal("bounded peer readback changed original owner", e)
	}
}
