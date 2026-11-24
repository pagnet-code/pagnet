package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const DirectManagedSourceBindingProtocol = "direct_managed_source_binding_v1"

var errDirectManagedSourceBinding = errors.New("transport: invalid closed direct managed source binding")

// DirectManagedSourceBindingV1 mirrors the server migration 0188 subject in exact field order.
// It is public closed evidence and grants no channel or execution authority.
type DirectManagedSourceBindingV1 struct {
	ID                      domain.ID `json:"id"`
	DirectIntentID          domain.ID `json:"directIntentId"`
	ProtocolVersion         string    `json:"protocolVersion"`
	TenantID                domain.ID `json:"tenantId"`
	AccountID               domain.ID `json:"accountId"`
	OwnershipScope          string    `json:"ownershipScope"`
	PrincipalID             domain.ID `json:"principalId"`
	EndpointID              domain.ID `json:"endpointId"`
	InstanceID              domain.ID `json:"instanceId"`
	OriginID                domain.ID `json:"originId"`
	NativeGeneration        string    `json:"nativeGeneration"`
	NativeSessionID         string    `json:"nativeSessionId"`
	OwnershipID             domain.ID `json:"ownershipId"`
	OwnershipGeneration     string    `json:"ownershipGeneration"`
	NativeAdmissionID       domain.ID `json:"nativeAdmissionId"`
	ConnectionIncarnationID domain.ID `json:"connectionIncarnationId"`
	HostID                  domain.ID `json:"hostId"`
	HostCredentialID        domain.ID `json:"hostCredentialId"`
	RunnerID                domain.ID `json:"runnerId"`
	RunnerConnectedAt       time.Time `json:"runnerConnectedAt"`
	BootID                  string    `json:"bootId"`
	BindingGeneration       int64     `json:"bindingGeneration"`
	State                   string    `json:"state"`
	CreatedAt               time.Time `json:"createdAt"`
	ExpiresAt               time.Time `json:"expiresAt"`

	Role                                string    `json:"role"`
	ProposalID                          domain.ID `json:"proposalId"`
	ProposalVersion                     int64     `json:"proposalVersion"`
	GrantID                             domain.ID `json:"grantId"`
	GrantGeneration                     int64     `json:"grantGeneration"`
	NetworkID                           domain.ID `json:"networkId"`
	SourcePrincipalID                   domain.ID `json:"sourcePrincipalId"`
	TargetPrincipalID                   domain.ID `json:"targetPrincipalId"`
	SourceAuthorityGeneration           string    `json:"sourceAuthorityGeneration"`
	SourceMembershipAuthorityGeneration string    `json:"sourceMembershipAuthorityGeneration"`
	TargetAuthorityGeneration           string    `json:"targetAuthorityGeneration"`
	BudgetID                            domain.ID `json:"budgetId"`
	BudgetAcceptedRevision              int64     `json:"budgetAcceptedRevision"`
	BudgetTermsDigest                   string    `json:"budgetTermsDigest"`
}

func (p DirectManagedSourceBindingV1) CanonicalBytes() ([]byte, error) {
	if p.Role != "S" || p.PrincipalID != p.SourcePrincipalID || p.ProposalVersion < 1 || p.GrantGeneration < 1 || p.BudgetAcceptedRevision < 1 || !nativeShareBindingHex(p.BudgetTermsDigest) || p.ProtocolVersion != DirectManagedSourceBindingProtocol || p.OwnershipScope != "personal" || p.BindingGeneration != 1 || p.State != "pending_closed" || p.ConnectionIncarnationID != p.NativeAdmissionID {
		return nil, errDirectManagedSourceBinding
	}
	for _, id := range []domain.ID{p.ID, p.DirectIntentID, p.TenantID, p.AccountID, p.PrincipalID, p.EndpointID, p.InstanceID, p.OriginID, p.OwnershipID, p.NativeAdmissionID, p.ConnectionIncarnationID, p.HostID, p.HostCredentialID, p.RunnerID, p.ProposalID, p.GrantID, p.NetworkID, p.SourcePrincipalID, p.TargetPrincipalID, p.BudgetID, domain.ID(p.SourceAuthorityGeneration), domain.ID(p.SourceMembershipAuthorityGeneration), domain.ID(p.TargetAuthorityGeneration)} {
		if !nativeShareBindingID(id) {
			return nil, errDirectManagedSourceBinding
		}
	}
	for _, value := range []string{p.NativeGeneration, p.NativeSessionID, p.OwnershipGeneration, p.BootID} {
		if !nativeShareOpaque(value) {
			return nil, errDirectManagedSourceBinding
		}
	}
	for _, value := range []time.Time{p.RunnerConnectedAt, p.CreatedAt, p.ExpiresAt} {
		if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
			return nil, errDirectManagedSourceBinding
		}
	}
	if !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.Sub(p.CreatedAt) > 5*time.Minute {
		return nil, errDirectManagedSourceBinding
	}
	p.RunnerConnectedAt = p.RunnerConnectedAt.UTC()
	p.CreatedAt = p.CreatedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return json.Marshal(p)
}

// DirectManagedSourceKeyReservation is public closed evidence only. EnrollmentDigest
// binds the complete server subject, configured origin, installation and key.
// The caller supplies the independently trusted server URL and a freshly generated
// host public key; this pure wire type cannot authenticate the URL or establish freshness.
type DirectManagedSourceKeyReservation struct {
	Subject          DirectManagedSourceBindingV1 `json:"subject"`
	ServerURL        string                       `json:"serverUrl"`
	InstallationID   domain.ID                    `json:"installationId"`
	KeyGeneration    uint64                       `json:"keyGeneration"`
	X25519           string                       `json:"x25519"`
	EnrollmentDigest string                       `json:"enrollmentDigest"`
}

// Digest binds the canonical complete subject, origin, installation and public
// key. EnrollmentDigest itself is excluded. This is evidence, not authority.
func (p DirectManagedSourceKeyReservation) Digest() (string, error) {
	subject, err := p.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(subject, &p.Subject) != nil || p.KeyGeneration != 1 || !nativeShareBindingID(p.InstallationID) || !nativeShareBindingHex(p.X25519) || !managedEndpointServerURL(p.ServerURL) {
		return "", errDirectManagedSourceBinding
	}
	pub, _ := hex.DecodeString(p.X25519)
	if !directManagedSourceUsableX25519(pub) {
		return "", errDirectManagedSourceBinding
	}
	p.EnrollmentDigest = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", errDirectManagedSourceBinding
	}
	sum := sha256.Sum256(append([]byte("pagnet/closed-direct-managed-source-key/v1/"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalBytes validates the reservation digest and emits UTC subject times.
func (p DirectManagedSourceKeyReservation) CanonicalBytes() ([]byte, error) {
	digest, err := p.Digest()
	if err != nil || !nativeShareBindingHex(p.EnrollmentDigest) || p.EnrollmentDigest != digest {
		return nil, errDirectManagedSourceBinding
	}
	subject, _ := p.Subject.CanonicalBytes()
	if json.Unmarshal(subject, &p.Subject) != nil {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourceKeyReservation(raw []byte) (DirectManagedSourceKeyReservation, error) {
	var p DirectManagedSourceKeyReservation
	if !managedEndpointCanonicalDecode(raw, &p, 24*1024) {
		return DirectManagedSourceKeyReservation{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// VerifySubject compares every immutable field, using canonical UTC instants.
func (p DirectManagedSourceKeyReservation) VerifySubject(expected DirectManagedSourceBindingV1) error {
	if _, err := p.CanonicalBytes(); err != nil {
		return errDirectManagedSourceBinding
	}
	actual, err := p.Subject.CanonicalBytes()
	retained, retainedErr := expected.CanonicalBytes()
	if err != nil || retainedErr != nil || !bytes.Equal(actual, retained) {
		return errDirectManagedSourceBinding
	}
	return nil
}

func (p DirectManagedSourceBindingV1) Digest() (string, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return managedEndpointDigest("pagnet/direct-managed-source-binding/v1/", raw), nil
}
func DecodeDirectManagedSourceBindingV1(raw []byte) (DirectManagedSourceBindingV1, error) {
	var p DirectManagedSourceBindingV1
	if !managedEndpointCanonicalDecode(raw, &p, 32*1024) {
		return DirectManagedSourceBindingV1{}, errDirectManagedSourceBinding
	}
	return p, nil
}

// Validate canonical public encoding and reject low-order points before retaining evidence.
func directManagedSourceUsableX25519(pub []byte) bool {
	if !managedEndpointCanonicalX25519(pub) {
		return false
	}
	key, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return false
	}
	private, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x31}, 32))
	shared, err := private.ECDH(key)
	clear(shared)
	return err == nil
}
