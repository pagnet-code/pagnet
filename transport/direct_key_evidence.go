package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const (
	DirectKeyEvidenceDomainV1             = "pagnet/direct-key-evidence/v1"
	DirectKeyEvidenceTranscriptMaxBytesV1 = 8192
)

var errDirectKeyEvidence = errors.New("transport: invalid direct key evidence v1 transcript")

// Declaration order defines canonical JSON. All fields are required public evidence.
type DirectKeyEvidencePartyV1 struct {
	TenantID     string `json:"tenantId"`
	PrincipalID  string `json:"principalId"`
	EndpointID   string `json:"endpointId"`
	CredentialID string `json:"credentialId"`
	PublicKey    string `json:"publicKey"`
}
type DirectKeyEvidenceBindingV1 struct {
	BindingID             string `json:"bindingId"`
	BindingGeneration     string `json:"bindingGeneration"`
	BindingTranscriptHash string `json:"bindingTranscriptHash"`
}
type DirectKeyEvidenceReservationV1 struct {
	InstallationID   string `json:"installationId"`
	KeyGeneration    string `json:"keyGeneration"`
	EnrollmentDigest string `json:"enrollmentDigest"`
}
type DirectKeyEvidenceDigestsV1 struct {
	PrepareDigest             string `json:"prepareDigest"`
	PrepareReceiptDigest      string `json:"prepareReceiptDigest"`
	PoPTranscriptHash         string `json:"popTranscriptHash"`
	PoPProofDigest            string `json:"popProofDigest"`
	CredentialTranscriptHash  string `json:"credentialTranscriptHash"`
	InstallationReceiptDigest string `json:"installationReceiptDigest"`
}

// DirectKeyEvidenceTranscriptV1 commits public closed evidence for one V2 party.
// Validation does not establish current authority, retained evidence, or activation.
// Callers must resolve the binding subject and check its principal, endpoint and
// host against the selected party and retained evidence.
type DirectKeyEvidenceTranscriptV1 struct {
	Domain                              string                         `json:"domain"`
	Role                                string                         `json:"role"`
	BindingProtocol                     string                         `json:"bindingProtocol"`
	PrepareProtocol                     string                         `json:"prepareProtocol"`
	PoPProtocol                         string                         `json:"popProtocol"`
	CredentialProtocol                  string                         `json:"credentialProtocol"`
	NetworkID                           string                         `json:"networkId"`
	DirectIntentID                      string                         `json:"directIntentId"`
	ProposalID                          string                         `json:"proposalId"`
	ProposalVersion                     string                         `json:"proposalVersion"`
	ParentGrantID                       string                         `json:"parentGrantId"`
	GrantGeneration                     string                         `json:"grantGeneration"`
	ChannelGeneration                   string                         `json:"channelGeneration"`
	AuthorizationDigest                 string                         `json:"authorizationDigest"`
	SourcePrincipalID                   string                         `json:"sourcePrincipalId"`
	TargetPrincipalID                   string                         `json:"targetPrincipalId"`
	SourceAuthorityGeneration           string                         `json:"sourceAuthorityGeneration"`
	SourceMembershipAuthorityGeneration string                         `json:"sourceMembershipAuthorityGeneration"`
	TargetAuthorityGeneration           string                         `json:"targetAuthorityGeneration"`
	Party                               DirectKeyEvidencePartyV1       `json:"party"`
	Binding                             DirectKeyEvidenceBindingV1     `json:"binding"`
	Reservation                         DirectKeyEvidenceReservationV1 `json:"reservation"`
	Evidence                            DirectKeyEvidenceDigestsV1     `json:"evidence"`
	Budget                              DirectChannelBudgetV2          `json:"budget"`
	Limits                              DirectChannelLimitsV2          `json:"limits"`
	EffectiveExpiresAt                  string                         `json:"effectiveExpiresAt"`
}

func (t DirectKeyEvidenceTranscriptV1) CanonicalBytes() ([]byte, error) {
	if t.Domain != DirectKeyEvidenceDomainV1 || t.SourcePrincipalID == t.TargetPrincipalID {
		return nil, errDirectKeyEvidence
	}
	switch t.Role {
	case "S":
		if t.BindingProtocol != DirectManagedSourceBindingProtocol || t.PrepareProtocol != DirectManagedSourcePrepareProtocol || t.PoPProtocol != DirectManagedSourcePoPProtocol || t.CredentialProtocol != DirectManagedSourceCredentialProtocol || t.Party.PrincipalID != t.SourcePrincipalID {
			return nil, errDirectKeyEvidence
		}
	case "P":
		if t.BindingProtocol != ManagedEndpointBindingProtocol || t.PrepareProtocol != ManagedEndpointPrepareProtocol || t.PoPProtocol != ManagedEndpointPoPProtocol || t.CredentialProtocol != ManagedDirectCredentialProtocol || t.Party.PrincipalID != t.TargetPrincipalID {
			return nil, errDirectKeyEvidence
		}
	default:
		return nil, errDirectKeyEvidence
	}
	for _, s := range []string{t.NetworkID, t.DirectIntentID, t.ProposalID, t.ParentGrantID, t.SourcePrincipalID, t.TargetPrincipalID, t.SourceAuthorityGeneration, t.SourceMembershipAuthorityGeneration, t.TargetAuthorityGeneration, t.Party.TenantID, t.Party.PrincipalID, t.Party.EndpointID, t.Party.CredentialID, t.Binding.BindingID, t.Reservation.InstallationID, t.Budget.AgreementID} {
		if !directV2ID(s) {
			return nil, errDirectKeyEvidence
		}
	}
	for _, s := range []string{t.ProposalVersion, t.GrantGeneration, t.ChannelGeneration, t.Binding.BindingGeneration, t.Reservation.KeyGeneration, t.Budget.AcceptedRevision} {
		if !directV2Decimal(s) {
			return nil, errDirectKeyEvidence
		}
	}
	for _, s := range []string{t.AuthorizationDigest, t.Binding.BindingTranscriptHash, t.Reservation.EnrollmentDigest, t.Evidence.PrepareDigest, t.Evidence.PrepareReceiptDigest, t.Evidence.PoPTranscriptHash, t.Evidence.PoPProofDigest, t.Evidence.CredentialTranscriptHash, t.Evidence.InstallationReceiptDigest, t.Budget.TermsDigest} {
		if !directV2Digest(s) {
			return nil, errDirectKeyEvidence
		}
	}
	expiry, ok := directV2Time(t.EffectiveExpiresAt)
	budgetExpiry, bok := directV2Time(t.Budget.ExpiresAt)
	if !ok || !bok || expiry.After(budgetExpiry) || t.Budget.AcceptedRevision == "1" || !directV2PublicKey(t.Party.PublicKey) || !t.Limits.validForCounting(t.Budget.CountingVersion) || !t.Budget.GrantLimits.validForCounting(t.Budget.CountingVersion) || !t.Limits.within(t.Budget.GrantLimits) {
		return nil, errDirectKeyEvidence
	}
	return directV2Canonical(t, DirectKeyEvidenceTranscriptMaxBytesV1)
}

func DecodeDirectKeyEvidenceTranscriptV1(raw []byte) (DirectKeyEvidenceTranscriptV1, error) {
	var t DirectKeyEvidenceTranscriptV1
	if directV2Decode(raw, &t, DirectKeyEvidenceTranscriptMaxBytesV1) != nil {
		return DirectKeyEvidenceTranscriptV1{}, errDirectKeyEvidence
	}
	if _, err := t.CanonicalBytes(); err != nil {
		return DirectKeyEvidenceTranscriptV1{}, err
	}
	return t, nil
}

// Digest is the lowercase hexadecimal keyEvidenceDigest of the canonical transcript.
func (t DirectKeyEvidenceTranscriptV1) Digest() (string, error) {
	raw, err := t.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// DirectKeyEvidenceBindingTranscriptHashV1 hashes exact canonical binding subject
// bytes, including every role-specific public field, without reserializing them.
func DirectKeyEvidenceBindingTranscriptHashV1(role string, raw []byte) (string, error) {
	var canonical []byte
	switch role {
	case "S":
		subject, err := DecodeDirectManagedSourceBindingV1(raw)
		if err != nil {
			return "", errDirectKeyEvidence
		}
		canonical, err = subject.CanonicalBytes()
		if err != nil {
			return "", errDirectKeyEvidence
		}
	case "P":
		subject, err := DecodeManagedEndpointBindingIntent(raw)
		if err != nil {
			return "", errDirectKeyEvidence
		}
		canonical, err = subject.CanonicalBytes()
		if err != nil {
			return "", errDirectKeyEvidence
		}
	default:
		return "", errDirectKeyEvidence
	}
	if !bytes.Equal(raw, canonical) {
		return "", errDirectKeyEvidence
	}
	sum := sha256.Sum256(append([]byte("pagnet/direct-key-evidence/binding/v1/"), raw...))
	return hex.EncodeToString(sum[:]), nil
}
