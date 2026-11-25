package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const (
	DirectKeyEvidenceDomainV2             = "pagnet/direct-key-evidence/v2"
	DirectKeyEvidenceTranscriptMaxBytesV2 = 8192
)

var errDirectKeyEvidenceV2 = errors.New("transport: invalid direct key evidence v2 transcript")

// DirectKeyEvidenceTranscriptV2 commits public closed evidence for a source-v2 party.
// This initial path supports generation one only; rollover is unsupported.
// Target evidence continues to use DirectKeyEvidenceTranscriptV1.
// Validation does not establish current authority, retained evidence, or activation.
// Callers must resolve the binding subject and check its principal, endpoint and
// host against the selected party and retained evidence.
type DirectKeyEvidenceTranscriptV2 struct {
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
	AuthorizationExpiresAt              string                         `json:"authorizationExpiresAt"`
	CredentialExpiresAt                 string                         `json:"credentialExpiresAt"`
	EffectiveExpiresAt                  string                         `json:"effectiveExpiresAt"`
}

func (t DirectKeyEvidenceTranscriptV2) CanonicalBytes() ([]byte, error) {
	if t.Domain != DirectKeyEvidenceDomainV2 || t.SourcePrincipalID == t.TargetPrincipalID {
		return nil, errDirectKeyEvidenceV2
	}
	if t.Role != "S" || t.BindingProtocol != DirectManagedSourceBindingProtocolV2 || t.PrepareProtocol != DirectManagedSourcePrepareProtocolV2 || t.PoPProtocol != DirectManagedSourcePoPProtocolV2 || t.CredentialProtocol != DirectManagedSourceCredentialProtocolV2 || t.Party.PrincipalID != t.SourcePrincipalID || t.Binding.BindingGeneration != "1" || t.Reservation.KeyGeneration != "1" || t.ChannelGeneration != "1" {
		return nil, errDirectKeyEvidenceV2
	}
	for _, s := range []string{t.NetworkID, t.DirectIntentID, t.ProposalID, t.ParentGrantID, t.SourcePrincipalID, t.TargetPrincipalID, t.SourceAuthorityGeneration, t.SourceMembershipAuthorityGeneration, t.TargetAuthorityGeneration, t.Party.TenantID, t.Party.PrincipalID, t.Party.EndpointID, t.Party.CredentialID, t.Binding.BindingID, t.Reservation.InstallationID, t.Budget.AgreementID} {
		if !directV2ID(s) {
			return nil, errDirectKeyEvidenceV2
		}
	}
	for _, s := range []string{t.ProposalVersion, t.GrantGeneration, t.ChannelGeneration, t.Binding.BindingGeneration, t.Reservation.KeyGeneration, t.Budget.AcceptedRevision} {
		if !directV2Decimal(s) {
			return nil, errDirectKeyEvidenceV2
		}
	}
	for _, s := range []string{t.AuthorizationDigest, t.Binding.BindingTranscriptHash, t.Reservation.EnrollmentDigest, t.Evidence.PrepareDigest, t.Evidence.PrepareReceiptDigest, t.Evidence.PoPTranscriptHash, t.Evidence.PoPProofDigest, t.Evidence.CredentialTranscriptHash, t.Evidence.InstallationReceiptDigest, t.Budget.TermsDigest} {
		if !directV2Digest(s) {
			return nil, errDirectKeyEvidenceV2
		}
	}
	expiry, ok := directV2Time(t.EffectiveExpiresAt)
	budgetExpiry, bok := directV2Time(t.Budget.ExpiresAt)
	authorizationExpiry, aok := directV2Time(t.AuthorizationExpiresAt)
	credentialExpiry, cok := directV2Time(t.CredentialExpiresAt)
	if !ok || !bok || !aok || !cok || !expiry.Equal(credentialExpiry) || expiry.After(authorizationExpiry) || expiry.After(budgetExpiry) || t.Budget.AcceptedRevision == "1" || !directV2PublicKey(t.Party.PublicKey) || !t.Limits.validForCounting(t.Budget.CountingVersion) || !t.Budget.GrantLimits.validForCounting(t.Budget.CountingVersion) || !t.Limits.within(t.Budget.GrantLimits) {
		return nil, errDirectKeyEvidenceV2
	}
	return directV2Canonical(t, DirectKeyEvidenceTranscriptMaxBytesV2)
}

func DecodeDirectKeyEvidenceTranscriptV2(raw []byte) (DirectKeyEvidenceTranscriptV2, error) {
	var t DirectKeyEvidenceTranscriptV2
	if directV2Decode(raw, &t, DirectKeyEvidenceTranscriptMaxBytesV2) != nil {
		return DirectKeyEvidenceTranscriptV2{}, errDirectKeyEvidenceV2
	}
	if _, err := t.CanonicalBytes(); err != nil {
		return DirectKeyEvidenceTranscriptV2{}, err
	}
	return t, nil
}

// Digest is the lowercase hexadecimal keyEvidenceDigest of the canonical transcript.
func (t DirectKeyEvidenceTranscriptV2) Digest() (string, error) {
	raw, err := t.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// DirectKeyEvidenceBindingTranscriptHashV2 hashes exact canonical source-v2 binding
// subject bytes. Generation two and rollover are unsupported by this initial path.
// It never probes or falls back to a v1 or target binding decoder.
func DirectKeyEvidenceBindingTranscriptHashV2(role string, raw []byte) (string, error) {
	if role != "S" {
		return "", errDirectKeyEvidenceV2
	}
	subject, err := DecodeDirectManagedSourceBindingV2(raw)
	if err != nil || subject.BindingGeneration != "1" || subject.PredecessorBindingID != "" || subject.PreviousCredentialID != "" {
		return "", errDirectKeyEvidenceV2
	}
	canonical, err := subject.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return "", errDirectKeyEvidenceV2
	}
	sum := sha256.Sum256(append([]byte("pagnet/direct-key-evidence/binding/v2/"), raw...))
	return hex.EncodeToString(sum[:]), nil
}
