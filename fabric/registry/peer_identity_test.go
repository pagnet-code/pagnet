package registry

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func peerGate(ctx context.Context, c fabric.ExecutionContext, r AuthorityIdentity) error {
	if c.VerifyAuthenticated(r.Namespace) != nil || c.PrincipalView() != r.Owner {
		return unauthPeer()
	}
	return ctx.Err()
}
func peerExchange(t *testing.T) [32]byte {
	t.Helper()
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var pub [32]byte
	copy(pub[:], key.PublicKey().Bytes())
	return pub
}
func certLocal(t *testing.T, p *PeerIdentity, owner fabric.ExecutionContext, expected, keyRevision uint64) CertifiedPeer {
	t.Helper()
	now := time.Now()
	cert, e := p.CertifyLocal(t.Context(), owner, expected, peerExchange(t), keyRevision, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	return cert
}
func TestActualRetainedPeerPinsRotationRevocationAndCertificateIsolation(t *testing.T) {
	a, ownerA, dir := fixture(t)
	b, ownerB, _ := fixture(t)
	pa, e := NewPeerIdentity(t.Context(), a, peerGate)
	if e != nil {
		t.Fatal(e)
	}
	pb, e := NewPeerIdentity(t.Context(), b, peerGate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := pa.CertifyLocal(t.Context(), ownerA, 0, peerExchange(t), 1, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)); e == nil {
		t.Fatal("expired local certificate installed")
	}
	local := certLocal(t, pa, ownerA, 0, 1)
	remoteLocal := certLocal(t, pb, ownerB, 0, 1)
	remote, e := pa.PinRemote(t.Context(), ownerA, 0, b.AuthorityIdentity(), remoteLocal.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	if e = pa.WithCurrent(t.Context(), ownerA, local, remote, func(context.Context) error { calls++; return nil }); e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
	substituted := remote
	substituted.Certificate.Certificate.ExchangePublicKey = peerExchange(t)
	if e = pa.WithCurrent(t.Context(), ownerA, local, substituted, func(context.Context) error { calls++; return nil }); e == nil || calls != 1 {
		t.Fatal("digest label accepted substituted public key")
	}
	identity := a.AuthorityIdentity()
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(t.Context(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(identity, reopened.AuthorityIdentity()) {
		t.Fatal("restart replaced original root")
	}
	pa, e = NewPeerIdentity(t.Context(), reopened, peerGate)
	if e != nil {
		t.Fatal(e)
	}
	retained, e := pa.Remote(t.Context(), ownerA, remote.Authority.Namespace, remote.Authority.StoreID)
	if e != nil || !sameCertified(retained, remote) {
		t.Fatal("restart lost exact peer pin", e)
	}
	newRemote := certLocal(t, pb, ownerB, 1, 2)
	if _, e = pa.PinRemote(t.Context(), ownerA, 0, b.AuthorityIdentity(), newRemote.Certificate); e == nil {
		t.Fatal("stale pin CAS accepted")
	}
	rotated, e := pa.PinRemote(t.Context(), ownerA, remote.Revision, b.AuthorityIdentity(), newRemote.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	if e = pa.WithCurrent(t.Context(), ownerA, local, remote, func(context.Context) error { calls++; return nil }); e == nil {
		t.Fatal("old peer still current after rotation")
	}
	if e = pa.RevokeRemote(t.Context(), ownerA, rotated.Authority.Namespace, rotated.Authority.StoreID, rotated.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e = pa.Remote(t.Context(), ownerA, rotated.Authority.Namespace, rotated.Authority.StoreID); e == nil {
		t.Fatal("revoked peer available")
	}
	if _, e = pa.PinRemote(t.Context(), ownerA, rotated.Revision+1, b.AuthorityIdentity(), newRemote.Certificate); e == nil {
		t.Fatal("revoked key resurrected")
	}
	renewed := certLocal(t, pb, ownerB, newRemote.Revision, 3)
	recovered, e := pa.PinRemote(t.Context(), ownerA, rotated.Revision+1, b.AuthorityIdentity(), renewed.Certificate)
	if e != nil {
		t.Fatal("explicit higher-key revision could not restore approved peer", e)
	}
	if e = pa.WithCurrent(t.Context(), ownerA, local, recovered, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = pa.RevokeLocal(t.Context(), ownerA, local.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e = pa.Local(t.Context(), ownerA); e == nil {
		t.Fatal("revoked local certificate available")
	}
}
func TestPeerOwnerGateForeignCertificateAndClosedRootDeny(t *testing.T) {
	a, ownerA, _ := fixture(t)
	b, ownerB, _ := fixture(t)
	open := true
	gate := func(ctx context.Context, c fabric.ExecutionContext, r AuthorityIdentity) error {
		if !open {
			return unauthPeer()
		}
		return peerGate(ctx, c, r)
	}
	pa, _ := NewPeerIdentity(t.Context(), a, gate)
	pb, _ := NewPeerIdentity(t.Context(), b, peerGate)
	remote := certLocal(t, pb, ownerB, 0, 1)
	wrong := b.AuthorityIdentity()
	wrong.StoreID = a.AuthorityIdentity().StoreID
	if _, e := pa.PinRemote(t.Context(), ownerA, 0, wrong, remote.Certificate); e == nil {
		t.Fatal("foreign store certificate mismatch accepted")
	}
	if _, e := pa.CertifyLocal(t.Context(), ownerB, 0, peerExchange(t), 1, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)); e == nil {
		t.Fatal("foreign owner granted signing")
	}
	if _, e := pa.CertifyLocal(t.Context(), ownerA, 0, peerExchange(t), 1, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)); e == nil {
		t.Fatal("expired local certificate installed")
	}
	local := certLocal(t, pa, ownerA, 0, 1)
	remote, e := pa.PinRemote(t.Context(), ownerA, 0, b.AuthorityIdentity(), remote.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	open = false
	if _, e = pa.Local(t.Context(), ownerA); e == nil {
		t.Fatal("expired actual control gate ignored")
	}
	open = true
	otherTx := b.WithNativeAuthority(t.Context(), ownerB, AuthorityScope{}, func(tx *AuthorityTx) error { return pa.CheckCurrentTx(tx, local, remote) })
	if otherTx == nil {
		t.Fatal("foreign root transaction accepted")
	}
	a.Close()
	if _, e = pa.Local(t.Context(), ownerA); e == nil {
		t.Fatal("closed original root accepted")
	}
}
