package spiffe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// Fixed clock for deterministic time-bound assertions.
var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// genRoot generates a self-signed ECDSA root CA that can sign CAs and CRLs.
func genRoot(t *testing.T, subject string, keyID []byte) ca {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert: cert, key: key, der: der}
}

// genIntermediate generates an intermediate CA signed by root.
func genIntermediate(t *testing.T, root ca) ca {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0x0a},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca{cert: cert, key: key, der: der}
}

// genSVID generates a SPIFFE X.509-SVID leaf signed by signer, carrying exactly
// the given SPIFFE ID as its single URI SAN.
func genSVID(t *testing.T, signer ca, id string, serial int64, from, to time.Time) []byte {
	t.Helper()
	u, err := url.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{}, // no common name
		NotBefore:             from,
		NotAfter:              to,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// genSVIDRaw generates an arbitrary leaf (for structure-rejection tests),
// signed by signer, from an explicit template.
func genSVIDRaw(t *testing.T, signer ca, tmpl *x509.Certificate) []byte {
	t.Helper()
	key := genKey(t)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func genCRL(t *testing.T, signer ca, serials []int64, thisUpdate, nextUpdate, revokedAt time.Time) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: revokedAt})
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate, RevokedCertificateEntries: entries}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, signer.cert, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func pemCRL(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}) }

func bundleFrom(t *testing.T, root ca, crlDER []byte, audience string) *TrustBundle {
	t.Helper()
	var crlPEM []byte
	if crlDER != nil {
		crlPEM = pemCRL(crlDER)
	}
	b, err := NewTrustBundle(pemCert(root.der), crlPEM, audience)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	tid = "spiffe://local.test/owner"
	ttd = "local.test"
)

func TestValidSPIFFEID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"spiffe://local.test/owner", true},
		{"spiffe://local.test", true},
		{"spiffe://example.org/agent/123", true},
		{"spiffe://01234567-89ab-cdef-0123-456789abcdef/owner", true},
		{"spiffe://td/path.with.dots_and~tilde-dash", true},
		{"https://local.test/owner", false},
		{"spiffe:/local.test/owner", false},
		{"spiffe:///owner", false},
		{"spiffe://local.test/upper space", false},
		{"spiffe://local.test/bad!path", false},
		{"spiffe://-td/owner", false},
		{"spiffe://td.-owner", false},
	}
	for _, c := range cases {
		if got := ValidSPIFFEID(c.in); got != c.want {
			t.Errorf("ValidSPIFFEID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSVIDParseAndExtract(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	der := genSVID(t, root, tid, 7, now.Add(-time.Hour), now.Add(time.Hour))
	svid, err := NewSVID(der)
	if err != nil {
		t.Fatal(err)
	}
	if svid.SPIFFEID() != tid {
		t.Fatalf("SPIFFEID = %q, want %q", svid.SPIFFEID(), tid)
	}
	if svid.TrustDomain() != ttd {
		t.Fatalf("TrustDomain = %q, want %q", svid.TrustDomain(), ttd)
	}
	if svid.SerialNumber().Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("serial = %v, want 7", svid.SerialNumber())
	}
	if !svid.NotBefore().Equal(now.Add(-time.Hour)) || !svid.NotAfter().Equal(now.Add(time.Hour)) {
		t.Fatalf("timestamps mismatch: %v .. %v", svid.NotBefore(), svid.NotAfter())
	}
	if svid.Fingerprint() == [32]byte{} {
		t.Fatal("fingerprint is zero")
	}
}

func TestSVIDStructureRejections(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// A common name is forbidden in an SVID.
	cnDER := genSVIDRaw(t, root, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forbidden"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{mustURL(t, tid)},
	})
	if _, err := NewSVID(cnDER); !errors.Is(err, ErrNotSVID) {
		t.Fatalf("CN SVID: got %v, want ErrNotSVID", err)
	}
	// A DNS SAN is forbidden.
	dnsDER := genSVIDRaw(t, root, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{mustURL(t, tid)}, DNSNames: []string{"evil.example"},
	})
	if _, err := NewSVID(dnsDER); !errors.Is(err, ErrNotSVID) {
		t.Fatalf("DNS SVID: got %v, want ErrNotSVID", err)
	}
	// A CA certificate is not a leaf SVID.
	caDER := genRoot(t, "root2", []byte{2}).der
	if _, err := NewSVID(caDER); !errors.Is(err, ErrNotSVID) {
		t.Fatalf("CA SVID: got %v, want ErrNotSVID", err)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestChainValidation(t *testing.T) {
	root := genRoot(t, "trusted root", []byte{1})
	rogue := genRoot(t, "rogue root", []byte{9})

	// Valid: SVID chains to the pinned root.
	goodDER := genSVID(t, root, tid, 1, now.Add(-time.Hour), now.Add(time.Hour))
	b := bundleFrom(t, root, nil, ttd)
	svid, err := NewSVID(goodDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(svid, now); err != nil {
		t.Fatalf("valid chain: %v", err)
	}

	// Untrusted: SVID chains to a root not in the bundle.
	badDER := genSVID(t, rogue, tid, 1, now.Add(-time.Hour), now.Add(time.Hour))
	bad, _ := NewSVID(badDER)
	if err := b.Validate(bad, now); !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("untrusted chain: got %v, want ErrUntrustedChain", err)
	}

	// Chain through an intermediate CA.
	inter := genIntermediate(t, root)
	leafDER := genSVID(t, inter, tid, 2, now.Add(-time.Hour), now.Add(time.Hour))
	leaf, err := NewSVID(leafDER, inter.der)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(leaf, now); err != nil {
		t.Fatalf("intermediate chain: %v", err)
	}

	// The same leaf without its intermediate does NOT chain.
	leafAlone, _ := NewSVID(leafDER)
	if err := b.Validate(leafAlone, now); !errors.Is(err, ErrUntrustedChain) {
		t.Fatalf("missing intermediate: got %v, want ErrUntrustedChain", err)
	}
}

func TestAudienceMismatch(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// SVID in trust domain "other.test", but the bundle audience is "local.test".
	der := genSVID(t, root, "spiffe://other.test/owner", 1, now.Add(-time.Hour), now.Add(time.Hour))
	svid, _ := NewSVID(der)
	b := bundleFrom(t, root, nil, ttd)
	if err := b.Validate(svid, now); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("audience: got %v, want ErrWrongAudience", err)
	}
}

func TestExpiration(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	b := bundleFrom(t, root, nil, ttd)

	expiredDER := genSVID(t, root, tid, 1, now.Add(-3*time.Hour), now.Add(-time.Hour))
	expired, _ := NewSVID(expiredDER)
	if err := b.Validate(expired, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: got %v, want ErrExpired", err)
	}

	futureDER := genSVID(t, root, tid, 2, now.Add(time.Hour), now.Add(3*time.Hour))
	future, _ := NewSVID(futureDER)
	if err := b.Validate(future, now); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("not yet valid: got %v, want ErrNotYetValid", err)
	}
}

func TestRevocation(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// CRL revokes serial 1 at time `now`; it is consulted from `now-2h`.
	crlDER := genCRL(t, root, []int64{1}, now.Add(-2*time.Hour), now.Add(2*time.Hour), now)
	b := bundleFrom(t, root, crlDER, ttd)

	// Before the revocation time the serial is not yet revoked.
	beforeDER := genSVID(t, root, tid, 1, now.Add(-2*time.Hour), now.Add(time.Hour))
	before, _ := NewSVID(beforeDER)
	if err := b.Validate(before, now.Add(-time.Minute)); err != nil {
		t.Fatalf("before revocation: got %v, want nil", err)
	}
	// After the revocation time the same serial is denied.
	if err := b.Validate(before, now.Add(time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after revocation: got %v, want ErrRevoked", err)
	}
}

func TestRotation(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// The old SVID (serial 1) is revoked at `now`; the renewed SVID (serial 2,
	// same SPIFFE ID) is a fresh, unrevoked certificate.
	crlDER := genCRL(t, root, []int64{1}, now.Add(-2*time.Hour), now.Add(2*time.Hour), now)
	b := bundleFrom(t, root, crlDER, ttd)

	oldDER := genSVID(t, root, tid, 1, now.Add(-2*time.Hour), now.Add(time.Hour))
	renewedDER := genSVID(t, root, tid, 2, now.Add(-time.Hour), now.Add(2*time.Hour))
	old, _ := NewSVID(oldDER)
	renewed, _ := NewSVID(renewedDER)

	// After rotation: the renewed SVID is accepted, the old one is denied.
	if err := b.Validate(renewed, now.Add(time.Minute)); err != nil {
		t.Fatalf("renewed SVID not accepted: %v", err)
	}
	if err := b.Validate(old, now.Add(time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old SVID not denied: got %v, want ErrRevoked", err)
	}
}

func TestWorkloadBinding(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	der := genSVID(t, root, tid, 1, now.Add(-time.Hour), now.Add(time.Hour))
	svid, _ := NewSVID(der)

	// Exact match binds.
	ok := principal(tid, "local.owner", ttd)
	if _, err := BindWorkload(svid, ok); err != nil {
		t.Fatalf("valid binding: %v", err)
	}
	// Principal.Ref mismatch is denied.
	if _, err := BindWorkload(svid, principal("spiffe://local.test/other", "local.owner", ttd)); !errors.Is(err, ErrWorkloadMismatch) {
		t.Fatalf("ref mismatch: got %v, want ErrWorkloadMismatch", err)
	}
	// Issuer mismatch is denied.
	if _, err := BindWorkload(svid, principal(tid, "local.owner", "wrong.test")); !errors.Is(err, ErrWorkloadMismatch) {
		t.Fatalf("issuer mismatch: got %v, want ErrWorkloadMismatch", err)
	}
	// Invalid kind is denied.
	if _, err := BindWorkload(svid, principal(tid, "no-dot-kind", ttd)); !errors.Is(err, ErrWorkloadMismatch) {
		t.Fatalf("kind mismatch: got %v, want ErrWorkloadMismatch", err)
	}
}

func TestCRLAuthenticity(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// A CRL signed by a rogue CA must be rejected by the bundle.
	rogue := genRoot(t, "rogue", []byte{9})
	rogueCRL := genCRL(t, rogue, []int64{1}, now.Add(-time.Hour), now.Add(time.Hour), now)
	_, err := NewTrustBundle(pemCert(root.der), pemCRL(rogueCRL), ttd)
	if !errors.Is(err, ErrCRLNotAuthentic) {
		t.Fatalf("forged CRL: got %v, want ErrCRLNotAuthentic", err)
	}
	// A CRL signed by the trusted root is accepted.
	goodCRL := genCRL(t, root, []int64{1}, now.Add(-time.Hour), now.Add(time.Hour), now)
	if _, err := NewTrustBundle(pemCert(root.der), pemCRL(goodCRL), ttd); err != nil {
		t.Fatalf("trusted CRL: %v", err)
	}
}

func TestTrustBundleConfig(t *testing.T) {
	root := genRoot(t, "root", []byte{1})
	// No roots is rejected.
	if _, err := NewTrustBundle(nil, nil, ttd); !errors.Is(err, ErrNoRoots) {
		t.Fatalf("no roots: got %v, want ErrNoRoots", err)
	}
	// Invalid audience is rejected.
	if _, err := NewTrustBundle(pemCert(root.der), nil, ""); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("bad audience: got %v, want ErrInvalidAudience", err)
	}
	// DER constructor works and reports the audience.
	der := genSVID(t, root, tid, 1, now.Add(-time.Hour), now.Add(time.Hour))
	b, err := NewTrustBundleDER([][]byte{root.der}, nil, ttd)
	if err != nil {
		t.Fatal(err)
	}
	if b.Audience() != ttd {
		t.Fatalf("audience = %q, want %q", b.Audience(), ttd)
	}
	if _, err := NewSVID(der); err != nil {
		t.Fatal(err)
	}
}

func principal(ref, kind, issuer string) fabric.Principal {
	return fabric.Principal{Ref: ref, Kind: kind, Issuer: issuer}
}
