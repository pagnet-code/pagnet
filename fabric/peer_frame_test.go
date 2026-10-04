package fabric

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func peerFixture(t *testing.T) (SignedPeerCertificate, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	exchange, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	namespace, _ := DomainNamespace(pub)
	c := PeerCertificate{Namespace: namespace, StoreID: strings.Repeat("a", 64), RootKeyRevision: 1, ExchangeKeyRevision: 1, BindingProfile: ForwardBindingProfile, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	copy(c.RootPublicKey[:], pub)
	copy(c.ExchangePublicKey[:], exchange.PublicKey().Bytes())
	raw, e := c.SigningBytes()
	if e != nil {
		t.Fatal(e)
	}
	return SignedPeerCertificate{c, ed25519.Sign(private, raw)}, private, now
}
func TestPeerCertificateExactRootProfileKeyAndTime(t *testing.T) {
	c, _, now := peerFixture(t)
	if VerifyPeerCertificate(c, now) != nil {
		t.Fatal("genuine certificate denied")
	}
	original, e := c.Digest()
	if e != nil || original == ([32]byte{}) {
		t.Fatal(e)
	}
	changes := []func(*PeerCertificate){
		func(c *PeerCertificate) { c.StoreID = strings.Repeat("b", 64) }, func(c *PeerCertificate) { c.ExchangePublicKey[0] ^= 1 }, func(c *PeerCertificate) { c.ExchangeKeyRevision++ }, func(c *PeerCertificate) { c.RootKeyRevision++ }, func(c *PeerCertificate) { c.BindingProfile = "foreign.profile" }, func(c *PeerCertificate) { c.RootPublicKey[0] ^= 1 }, func(c *PeerCertificate) { c.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano) },
	}
	for _, change := range changes {
		changed := c
		change(&changed.Certificate)
		if VerifyPeerCertificate(changed, now) == nil {
			t.Fatal("altered certificate accepted")
		}
	}
	for _, outside := range []time.Time{time.Time{}, now.Add(-2 * time.Minute), now.Add(time.Hour)} {
		if VerifyPeerCertificate(c, outside) == nil {
			t.Fatal("certificate validity ignored")
		}
	}
	bad := c
	bad.Certificate.ExchangePublicKey = [32]byte{}
	if _, e = bad.Certificate.SigningBytes(); e == nil {
		t.Fatal("low-order key accepted")
	}
	bad = c
	bad.Certificate.ExpiresAt = now.Add(367 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, e = bad.Certificate.SigningBytes(); e == nil {
		t.Fatal("unbounded validity accepted")
	}
}
