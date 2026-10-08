package spiffe

import (
	"errors"
	"math/big"

	"github.com/pagnet-code/pagnet/fabric"
)

// ErrWorkloadMismatch means the request's asserted principal does not equal the
// SVID's verified SPIFFE subject. The SVID is the workload identity the trust
// anchor established (bound by the transport to the actual peer connection,
// which for a local peer is its kernel identity); a request cannot claim a
// different identity than the SVID it presented.
var ErrWorkloadMismatch = errors.New("spiffe: asserted principal does not match the SVID SPIFFE subject")

// WorkloadBinding is the immutable association between a verified SVID subject
// (the workload's SPIFFE identity) and the fabric principal a request asserts.
// It is established only after the SVID has passed chain, expiration, revocation
// and audience validation, so the SPIFFE ID it carries is trust-anchor-verified.
// It is private in-process material, never a wire value.
type WorkloadBinding struct {
	spiffeID    string
	serial      *big.Int
	fingerprint [32]byte
	principal   fabric.Principal
}

func (WorkloadBinding) MarshalJSON() ([]byte, error) { return nil, errors.New("spiffe: workload binding is not a wire value") }
func (*WorkloadBinding) UnmarshalJSON([]byte) error  { return errors.New("spiffe: wire data cannot create a workload binding") }

// BindWorkload maps the verified SVID subject to the asserted fabric principal.
// It denies the binding when the asserted Principal.Ref does not exactly equal
// the SVID's SPIFFE ID (the URI SAN), when the asserted issuer is not the SVID
// trust domain, or when the asserted kind is not a valid namespaced name. The
// returned binding ties the exact SVID (serial + fingerprint) to the principal.
func BindWorkload(svid *SVID, asserted fabric.Principal) (WorkloadBinding, error) {
	if svid == nil {
		return WorkloadBinding{}, ErrWorkloadMismatch
	}
	if asserted.Ref != svid.SPIFFEID() {
		return WorkloadBinding{}, ErrWorkloadMismatch
	}
	if asserted.Issuer != svid.TrustDomain() {
		return WorkloadBinding{}, ErrWorkloadMismatch
	}
	if !fabric.ValidNamespacedName(asserted.Kind) {
		return WorkloadBinding{}, ErrWorkloadMismatch
	}
	return WorkloadBinding{
		spiffeID:    svid.SPIFFEID(),
		serial:      svid.SerialNumber(),
		fingerprint: svid.Fingerprint(),
		principal:   asserted,
	}, nil
}

// Principal returns the bound, verified fabric principal.
func (b WorkloadBinding) Principal() fabric.Principal { return b.principal }
// SPIFFEID returns the verified SPIFFE subject of the bound SVID.
func (b WorkloadBinding) SPIFFEID() string { return b.spiffeID }
// Serial returns the bound SVID serial (the revocation identity).
func (b WorkloadBinding) Serial() *big.Int { return b.serial }
// Fingerprint returns the SHA-256 of the bound SVID leaf DER.
func (b WorkloadBinding) Fingerprint() [32]byte { return b.fingerprint }
