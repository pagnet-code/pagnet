package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for trust-bundle validation.
var (
	// ErrNoRoots means the bundle was supplied without any pinned root.
	ErrNoRoots = errors.New("spiffe: trust bundle requires at least one pinned root")
	// ErrInvalidAudience means the expected audience (trust domain) is empty or malformed.
	ErrInvalidAudience = errors.New("spiffe: invalid trust bundle audience")
	// ErrWrongAudience means the SVID trust domain does not equal the bundle audience.
	ErrWrongAudience = errors.New("spiffe: SVID trust domain does not match the expected audience")
	// ErrExpired means the SVID is past its NotAfter at the check time.
	ErrExpired = errors.New("spiffe: SVID is expired")
	// ErrNotYetValid means the SVID is before its NotBefore at the check time.
	ErrNotYetValid = errors.New("spiffe: SVID is not yet valid")
	// ErrUntrustedChain means the SVID does not chain to a pinned root.
	ErrUntrustedChain = errors.New("spiffe: SVID does not chain to a pinned root")
	// ErrRevoked means the SVID serial appears in a trusted CRL.
	ErrRevoked = errors.New("spiffe: SVID is revoked")
	// ErrCRLNotAuthentic means a CRL signature does not verify against a pinned root.
	ErrCRLNotAuthentic = errors.New("spiffe: CRL is not signed by a pinned root")
)

// TrustBundle is an operator-supplied, explicitly pinned trust anchor for one
// audience (trust domain): a set of pinned root CAs and one or more
// certificate revocation lists. It is constructed explicitly from operator
// material; nothing is discovered. It is immutable once built.
type TrustBundle struct {
	audience  string
	roots     *x509.CertPool
	rootCerts []*x509.Certificate
	crls      []*x509.RevocationList
}

// NewTrustBundle builds a bundle from operator-supplied PEM roots, PEM CRLs
// and the explicit expected audience (trust domain). The audience is required
// and must be a valid trust domain. At least one root is required. CRLs are
// optional but, when present, each must be signed by one of the pinned roots.
func NewTrustBundle(rootsPEM, crlsPEM []byte, audience string) (*TrustBundle, error) {
	if !validTrustDomain(audience) {
		return nil, ErrInvalidAudience
	}
	roots, err := parseCertsPEM(rootsPEM)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, ErrNoRoots
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	var crls []*x509.RevocationList
	if len(crlsPEM) > 0 {
		crls, err = parseCRLsPEM(crlsPEM)
		if err != nil {
			return nil, err
		}
		for _, crl := range crls {
			if err := authenticCRL(crl, roots); err != nil {
				return nil, err
			}
		}
	}
	return &TrustBundle{audience: audience, roots: pool, rootCerts: roots, crls: crls}, nil
}

// NewTrustBundleDER is the DER counterpart of NewTrustBundle for callers that
// hold the pinned material as individual DER documents.
func NewTrustBundleDER(rootDERs [][]byte, crlDERs [][]byte, audience string) (*TrustBundle, error) {
	if !validTrustDomain(audience) {
		return nil, ErrInvalidAudience
	}
	roots := make([]*x509.Certificate, 0, len(rootDERs))
	for _, der := range rootDERs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("spiffe: invalid pinned root: %w", err)
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return nil, ErrNoRoots
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	var crls []*x509.RevocationList
	for _, der := range crlDERs {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, fmt.Errorf("spiffe: invalid CRL: %w", err)
		}
		crls = append(crls, crl)
	}
	for _, crl := range crls {
		if err := authenticCRL(crl, roots); err != nil {
			return nil, err
		}
	}
	return &TrustBundle{audience: audience, roots: pool, rootCerts: roots, crls: crls}, nil
}

// Audience returns the explicit trust domain this bundle authenticates.
func (b *TrustBundle) Audience() string { return b.audience }

// Validate is the current-status check used for NEW invocations. It verifies,
// in order: the SVID belongs to the bundle audience (trust domain), the SVID is
// within its validity window, the SVID chains to a pinned root, and the SVID is
// not revoked by a trusted CRL. Any failure denies the invocation.
func (b *TrustBundle) Validate(svid *SVID, now time.Time) error {
	if svid == nil {
		return ErrNotSVID
	}
	if svid.TrustDomain() != b.audience {
		return ErrWrongAudience
	}
	leaf := svid.Certificate()
	if now.Before(leaf.NotBefore) {
		return ErrNotYetValid
	}
	if !now.Before(leaf.NotAfter) {
		return ErrExpired
	}
	if err := b.verifyChain(svid, now); err != nil {
		return err
	}
	return b.checkRevocation(svid, now)
}

// verifyChain chains the SVID leaf (with its presented intermediates) to a
// pinned root for clientAuth, at the given time.
func (b *TrustBundle) verifyChain(svid *SVID, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, c := range svid.Intermediates() {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         b.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}
	if _, err := svid.Certificate().Verify(opts); err != nil {
		return fmt.Errorf("spiffe: %w: %w", ErrUntrustedChain, err)
	}
	return nil
}

// checkRevocation reports ErrRevoked when the SVID serial appears in any
// trusted CRL whose revocation time has taken effect. CRLs are only consulted
// when the operator supplied them; absence of CRLs means the operator
// publishes no CRLs for this audience.
func (b *TrustBundle) checkRevocation(svid *SVID, now time.Time) error {
	serial := svid.SerialNumber()
	for _, crl := range b.crls {
		if now.Before(crl.ThisUpdate) {
			continue // not yet effective
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(serial) == 0 && !now.Before(entry.RevocationTime) {
				return ErrRevoked
			}
		}
	}
	return nil
}

// authenticCRL verifies that a CRL is signed by one of the pinned roots and
// that the CRL issuer name matches that root's subject. A CRL that does not
// verify against a pinned root is rejected so an attacker cannot publish a
// forged CRL to revoke, or by omission fail to revoke, a serial.
func authenticCRL(crl *x509.RevocationList, roots []*x509.Certificate) error {
	for _, root := range roots {
		if !sameName(root.Subject, crl.Issuer) {
			continue
		}
		if err := verifyCRLSignature(crl, root); err != nil {
			return err
		}
		return nil
	}
	return ErrCRLNotAuthentic
}

func sameName(a, b pkix.Name) bool {
	ma, ea := asn1.Marshal(a)
	mb, eb := asn1.Marshal(b)
	return ea == nil && eb == nil && string(ma) == string(mb)
}

// verifyCRLSignature checks the CRL signature over its TBS against the root
// public key using the CRL's declared signature algorithm.
func verifyCRLSignature(crl *x509.RevocationList, root *x509.Certificate) error {
	tbs := crl.RawTBSRevocationList
	switch key := root.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsaVerified(key, crl.SignatureAlgorithm, tbs, crl.Signature) {
			return ErrCRLNotAuthentic
		}
	case *rsa.PublicKey:
		hash, sigAlg, ok := rsaDigest(crl.SignatureAlgorithm, tbs)
		if !ok {
			return ErrCRLNotAuthentic
		}
		if err := rsa.VerifyPKCS1v15(key, sigAlg, hash, crl.Signature); err != nil {
			return ErrCRLNotAuthentic
		}
	default:
		return ErrCRLNotAuthentic
	}
	return nil
}

func ecdsaVerified(key *ecdsa.PublicKey, alg x509.SignatureAlgorithm, tbs, sig []byte) bool {
	if alg != x509.ECDSAWithSHA256 {
		return false
	}
	sum := sha256.Sum256(tbs)
	return ecdsa.VerifyASN1(key, sum[:], sig)
}

func rsaDigest(alg x509.SignatureAlgorithm, tbs []byte) ([]byte, crypto.Hash, bool) {
	if alg != x509.SHA256WithRSA {
		return nil, 0, false
	}
	sum := sha256.Sum256(tbs)
	return sum[:], crypto.SHA256, true
}

// parseCertsPEM decodes every CERTIFICATE block in the PEM input.
func parseCertsPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("spiffe: invalid pinned certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// parseCRLsPEM decodes every X509 CRL block in the PEM input.
func parseCRLsPEM(pemBytes []byte) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("spiffe: invalid CRL: %w", err)
		}
		crls = append(crls, crl)
	}
	return crls, nil
}
