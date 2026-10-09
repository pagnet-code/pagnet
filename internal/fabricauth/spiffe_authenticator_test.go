package fabricauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/spiffe"
)

var faNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

const faTID = "spiffe://local.test/owner"
const faTD = "local.test"

func faKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// faRoot returns a self-signed ECDSA root that can sign CAs and CRLs.
func faRoot(t *testing.T) (cert *x509.Certificate, key *ecdsa.PrivateKey, der []byte) {
	t.Helper()
	key = faKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fa root"},
		NotBefore: faNow.Add(-2 * time.Hour), NotAfter: faNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, SubjectKeyId: []byte{1},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func faSVID(t *testing.T, signer *x509.Certificate, signerKey *ecdsa.PrivateKey, serial int64, from, to time.Time) []byte {
	t.Helper()
	u, _ := url.Parse(faTID)
	key := faKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{},
		NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: false, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func faCRL(t *testing.T, signer *x509.Certificate, signerKey *ecdsa.PrivateKey, serials []int64, thisUpdate, nextUpdate, revokedAt time.Time) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: revokedAt})
	}
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate, RevokedCertificateEntries: entries}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, signer, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// faEnvelope builds a discover envelope whose asserted principal is the SPIFFE
// subject, exactly as an authenticated local workload would send it.
func faEnvelope(t *testing.T, ref string) []byte {
	t.Helper()
	env := fabric.Envelope{
		ProtocolVersion: fabric.CurrentProtocolVersion,
		ID:              "env-1",
		Operation:       fabric.OperationDiscover,
		Principal:       fabric.Principal{Ref: ref, Kind: "local.owner", Issuer: faTD},
		Source:          ref,
		CreatedAt:       faNow,
		Payload:         json.RawMessage(`{"query":"local","limit":10}`),
		Context:         fabric.EnvelopeContext{Origin: ref},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// faProviderAt builds a SPIFFE provider whose clock is fixed at `at`, to
// exercise time-bound (expiration/revocation) states deterministically.
func faProviderAt(t *testing.T, name fabric.ProviderName, bundle *spiffe.TrustBundle, at time.Time) *SpiffeProvider {
	t.Helper()
	p, err := NewSpiffeProvider(name, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return p.WithNow(func() time.Time { return at })
}

// faBundle builds a trust bundle for faTD from a root and an optional CRL.
func faBundle(t *testing.T, root *x509.Certificate, rootDER, crlDER []byte) *spiffe.TrustBundle {
	t.Helper()
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	var crlPEM []byte
	if crlDER != nil {
		crlPEM = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	}
	b, err := spiffe.NewTrustBundle(rootPEM, crlPEM, faTD)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSpiffeAuthenticateHappyPath(t *testing.T) {
	rootCert, rootKey, rootDER := faRoot(t)
	bundle := faBundle(t, rootCert, rootDER, nil)
	p := faProviderAt(t, "spiffe", bundle, faNow)
	svidDER := faSVID(t, rootCert, rootKey, 1, faNow.Add(-time.Hour), faNow.Add(time.Hour))
	svid, err := spiffe.NewSVID(svidDER)
	if err != nil {
		t.Fatal(err)
	}
	raw := faEnvelope(t, faTID)
	ctx, err := p.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: faTD, PeerEvidence: svid})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	envelope, err := ctx.DecodeVerifiedEnvelope(raw, faTD)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Principal.Ref != faTID || ctx.PrincipalView().Ref != faTID {
		t.Fatalf("principal mismatch: %v", envelope.Principal)
	}
	// The evidence is private to the SPIFFE provider.
	if ctx.AuthenticationEvidence().(*svidEvidence).provider != p {
		t.Fatal("evidence provider mismatch")
	}
}

func TestSpiffeAuthenticateDenials(t *testing.T) {
	rootCert, rootKey, rootDER := faRoot(t)
	bundle := faBundle(t, rootCert, rootDER, nil)
	p := faProviderAt(t, "spiffe", bundle, faNow)
	svidDER := faSVID(t, rootCert, rootKey, 1, faNow.Add(-time.Hour), faNow.Add(time.Hour))
	svid, _ := spiffe.NewSVID(svidDER)

	// Principal.Ref mismatch: the envelope claims a different identity than the SVID.
	if _, err := p.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: faEnvelope(t, "spiffe://local.test/other"), Audience: faTD, PeerEvidence: svid}); err == nil {
		t.Fatal("principal mismatch should be denied")
	}
	// Wrong audience.
	if _, err := p.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: faEnvelope(t, faTID), Audience: "other.test", PeerEvidence: svid}); err == nil {
		t.Fatal("wrong audience should be denied")
	}
	// No SVID presented.
	if _, err := p.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: faEnvelope(t, faTID), Audience: faTD, PeerEvidence: "not-an-svid"}); err == nil {
		t.Fatal("missing SVID should be denied")
	}
	// A SVID from a different root is untrusted.
	rogueCert, rogueKey, _ := faRoot(t)
	rogueSvidDER := faSVID(t, rogueCert, rogueKey, 1, faNow.Add(-time.Hour), faNow.Add(time.Hour))
	rogueSvid, _ := spiffe.NewSVID(rogueSvidDER)
	if _, err := p.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: faEnvelope(t, faTID), Audience: faTD, PeerEvidence: rogueSvid}); err == nil {
		t.Fatal("untrusted SVID should be denied")
	}
}

// TestSpiffeRevocationAndHistoricalRead is the E4.2 revocation-handling
// contract: a NEW invocation is denied once the SVID is revoked, but a past
// invocation that was authorized remains readable (historical read retention).
func TestSpiffeRevocationAndHistoricalRead(t *testing.T) {
	rootCert, rootKey, rootDER := faRoot(t)
	// The SVID (serial 1) is revoked at faNow. The CRL is effective from faNow-2h.
	crlDER := faCRL(t, rootCert, rootKey, []int64{1}, faNow.Add(-2*time.Hour), faNow.Add(2*time.Hour), faNow)
	bundle := faBundle(t, rootCert, rootDER, crlDER)
	svidDER := faSVID(t, rootCert, rootKey, 1, faNow.Add(-time.Hour), faNow.Add(time.Hour))
	svid, _ := spiffe.NewSVID(svidDER)
	raw := faEnvelope(t, faTID)

	before := faNow.Add(-time.Minute)
	after := faNow.Add(time.Minute)
	pBefore := faProviderAt(t, "spiffe", bundle, before)
	pAfter := faProviderAt(t, "spiffe", bundle, after)

	// NEW invocation before revocation: accepted.
	historical, err := pBefore.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: faTD, PeerEvidence: svid})
	if err != nil {
		t.Fatalf("pre-revocation authenticate: %v", err)
	}
	// NEW invocation after revocation: denied.
	if _, err := pAfter.Authenticate(context.Background(), fabric.AuthenticationRequest{ExactEnvelope: raw, Audience: faTD, PeerEvidence: svid}); err == nil {
		t.Fatal("post-revocation new invocation should be denied")
	}
	// Historical read of the pre-revocation invocation: retained.
	read := false
	if err := pBefore.WithRetainedCaller(context.Background(), historical, raw, func(context.Context) error {
		read = true
		return nil
	}); err != nil {
		t.Fatalf("historical read should be retained: %v", err)
	}
	if !read {
		t.Fatal("historical read callback was not invoked")
	}
	// A historical read with tampered original bytes is denied.
	if err := pBefore.WithRetainedCaller(context.Background(), historical, faEnvelope(t, "spiffe://local.test/other"), func(context.Context) error { return nil }); err == nil {
		t.Fatal("tampered original should be denied")
	}
}

// TestProviderSelection is the pluggable SPI: explicit selection, default-to-
// local-kernel, and no auto-discovery.
func TestProviderSelection(t *testing.T) {
	rootCert, _, rootDER := faRoot(t)
	bundle := faBundle(t, rootCert, rootDER, nil)
	spiffeProv, _ := NewSpiffeProvider("spiffe", bundle)

	local := localKernelStub{fabric.ProviderLocalKernel}
	set := fabric.NewProviderSet(local)
	if err := set.Register(spiffeProv); err != nil {
		t.Fatal(err)
	}
	// Registering a duplicate name is refused (no override, no discovery).
	if err := set.Register(spiffeProv); err == nil {
		t.Fatal("duplicate registration should be refused")
	}
	// Empty name selects the explicit default (local kernel).
	def, err := set.Select("")
	if err != nil || def.Name() != fabric.ProviderLocalKernel {
		t.Fatalf("default selection: %v %v", def, err)
	}
	// Explicit name selects the SPIFFE provider.
	sp, err := set.Select("spiffe")
	if err != nil || sp.Name() != "spiffe" {
		t.Fatalf("explicit selection: %v %v", sp, err)
	}
	// An unknown name is an error: providers are never discovered or inferred.
	if _, err := set.Select("unknown"); err == nil {
		t.Fatal("unknown provider should error")
	}
}

// localKernelStub stands in for the unchanged local kernel authority so the
// default-to-local selection can be exercised without a real Unix socket. It
// authenticates nothing; it only proves the SPI selection contract.
type localKernelStub struct{ name fabric.ProviderName }

func (s localKernelStub) Name() fabric.ProviderName { return s.name }
func (s localKernelStub) Authenticate(context.Context, fabric.AuthenticationRequest) (fabric.ExecutionContext, error) {
	return fabric.ExecutionContext{}, errors.New("local kernel stub: not used for authentication")
}
