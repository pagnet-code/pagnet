// Package spiffe implements SPIFFE-compatible X.509-SVID verification using
// only the Go standard library. A SPIFFE SVID is an ordinary X.509 certificate
// whose workload identity is carried exclusively in a single spiffe:// URI
// subject-alternative-name, and which is validated against an operator-supplied,
// explicitly pinned trust bundle (pinned roots + CRLs). There is no issuer
// auto-discovery and no SPIRE dependency: the trust anchor is pinned
// configuration, never inferred.
package spiffe

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Sentinel errors for SVID parsing and structure validation. Callers compare
// with errors.Is and never parse the message.
var (
	// ErrNotSVID means the certificate is not a well-formed SPIFFE X.509-SVID
	// (wrong SAN shape, a common name, CA assertions, missing key usage, ...).
	ErrNotSVID = errors.New("spiffe: certificate is not a valid X.509-SVID")
	// ErrInvalidSPIFFEID means the single URI SAN is present but is not a
	// well-formed spiffe:// identity.
	ErrInvalidSPIFFEID = errors.New("spiffe: the URI subject alternative name is not a valid SPIFFE ID")
	// ErrInvalidIntermediate means a supplied intermediate is not a CA.
	ErrInvalidIntermediate = errors.New("spiffe: an intermediate certificate is not a certificate authority")
)

// SVID is a parsed, structurally validated SPIFFE X.509-SVID together with the
// intermediate certificates exactly as presented by the workload. It is
// in-process verification material, never a wire value or a credential.
type SVID struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	spiffeID      string
	trustDomain   string
}

func (SVID) MarshalJSON() ([]byte, error) { return nil, errors.New("spiffe: SVID is not a wire value") }
func (*SVID) UnmarshalJSON([]byte) error {
	return errors.New("spiffe: wire data cannot create an SVID")
}

// NewSVID parses a DER-encoded leaf X.509 certificate as a SPIFFE SVID,
// validating its structure per the SPIFFE X.509-SVID specification, plus any
// DER-encoded intermediate CAs presented in order toward the trust anchor.
// It performs no chain validation, expiration, revocation or audience checks;
// those are TrustBundle.Validate's responsibility.
func NewSVID(leafDER []byte, intermediateDERs ...[]byte) (*SVID, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("spiffe: %w: %w", ErrNotSVID, err)
	}
	if err := validateSVIDStructure(leaf); err != nil {
		return nil, err
	}
	id, err := extractSPIFFEID(leaf)
	if err != nil {
		return nil, err
	}
	intermediates := make([]*x509.Certificate, 0, len(intermediateDERs))
	for _, der := range intermediateDERs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("spiffe: %w: %w", ErrInvalidIntermediate, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, ErrInvalidIntermediate
		}
		intermediates = append(intermediates, c)
	}
	return &SVID{leaf: leaf, intermediates: intermediates, spiffeID: id, trustDomain: trustDomainOf(id)}, nil
}

// Certificate returns the parsed leaf SVID certificate.
func (s *SVID) Certificate() *x509.Certificate { return s.leaf }

// Intermediates returns the presented intermediate CAs in order, if any.
func (s *SVID) Intermediates() []*x509.Certificate { return s.intermediates }

// SPIFFEID returns the exact spiffe:// identity carried in the URI SAN.
func (s *SVID) SPIFFEID() string { return s.spiffeID }

// TrustDomain returns the authority component of the SPIFFE ID.
func (s *SVID) TrustDomain() string { return s.trustDomain }

// SerialNumber returns the SVID serial; it is the revocation identity.
func (s *SVID) SerialNumber() *big.Int { return s.leaf.SerialNumber }

// NotBefore returns the SVID validity start.
func (s *SVID) NotBefore() time.Time { return s.leaf.NotBefore }

// NotAfter returns the SVID validity end.
func (s *SVID) NotAfter() time.Time { return s.leaf.NotAfter }

// Fingerprint returns the SHA-256 of the leaf DER, for exact pinning.
func (s *SVID) Fingerprint() [32]byte { return sha256.Sum256(s.leaf.Raw) }

// validateSVIDStructure enforces the SPIFFE X.509-SVID structural rules that are
// independent of any trust anchor: v3, a leaf (not a CA), an empty subject
// common name, digital-signature key usage, clientAuth extended key usage and a
// positive serial number.
func validateSVIDStructure(cert *x509.Certificate) error {
	if cert.Version != 3 {
		return ErrNotSVID
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return ErrNotSVID
	}
	if cert.Subject.CommonName != "" {
		return ErrNotSVID
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		return ErrNotSVID
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrNotSVID
	}
	return hasEKU(cert, x509.ExtKeyUsageClientAuth)
}

func hasEKU(cert *x509.Certificate, usage x509.ExtKeyUsage) error {
	for _, u := range cert.ExtKeyUsage {
		if u == usage {
			return nil
		}
	}
	return ErrNotSVID
}

// extractSPIFFEID enforces that the SVID carries exactly one URI
// subject-alternative-name that is a valid SPIFFE ID, and no DNS, IP, email or
// other SAN types. It returns the exact SPIFFE ID.
func extractSPIFFEID(cert *x509.Certificate) (string, error) {
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return "", ErrNotSVID
	}
	var id string
	for _, uri := range cert.URIs {
		if uri == nil {
			return "", ErrNotSVID
		}
		if id != "" {
			return "", ErrNotSVID // more than one URI SAN
		}
		id = uri.String()
	}
	if id == "" {
		return "", ErrNotSVID
	}
	if !ValidSPIFFEID(id) {
		return "", ErrInvalidSPIFFEID
	}
	return id, nil
}

// ValidSPIFFEID reports whether s is a well-formed SPIFFE ID of the form
// spiffe://<trust-domain>[/<path>]. Both the trust domain and the path are
// case-sensitive; nothing is normalized.
func ValidSPIFFEID(s string) bool {
	if !strings.HasPrefix(s, "spiffe://") {
		return false
	}
	rest := strings.TrimPrefix(s, "spiffe://")
	idx := strings.IndexByte(rest, '/')
	var trustDomain, path string
	if idx < 0 {
		trustDomain = rest
	} else {
		trustDomain, path = rest[:idx], rest[idx+1:]
	}
	return validTrustDomain(trustDomain) && validPath(path)
}

// trustDomainOf returns the authority component of a well-formed SPIFFE ID.
// The caller must have validated the ID first.
func trustDomainOf(spiffeID string) string {
	rest := strings.TrimPrefix(spiffeID, "spiffe://")
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// validTrustDomain accepts a hostname (DNS labels) or a lowercase UUID, per the
// SPIFFE ID specification. A port is not part of a canonical trust domain.
func validTrustDomain(td string) bool {
	if len(td) < 1 || len(td) > 255 {
		return false
	}
	if isUUID(td) {
		return true
	}
	for _, label := range strings.Split(td, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validPath enforces the SPIFFE ID path character set and 0-255 byte bound.
func validPath(p string) bool {
	if len(p) > 255 {
		return false
	}
	for _, c := range p {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '.' || c == '_' || c == '~' || c == '-':
		default:
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
