package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const DirectAuthorizationSnapshotProtocol = "direct_authorization_snapshot_v1"

type DirectAuthorizationSourceV1 struct {
	PrincipalID                   domain.ID `json:"principalId"`
	AuthorityGeneration           string    `json:"authorityGeneration"`
	MembershipAuthorityGeneration string    `json:"membershipAuthorityGeneration"`
}

type DirectAuthorizationTargetV1 struct {
	PrincipalID                   domain.ID  `json:"principalId"`
	AuthorityGeneration           string     `json:"authorityGeneration"`
	NetworkID                     *domain.ID `json:"networkId"`
	MembershipAuthorityGeneration *string    `json:"membershipAuthorityGeneration"`
}

// DirectAuthorizationSnapshotV1 is immutable public consent evidence. It grants
// no authority by itself. Canonical JSON uses the declared field order, UTC
// RFC3339Nano times, numeric int64 versions/generation, and explicit nulls.
type DirectAuthorizationSnapshotV1 struct {
	ProtocolVersion      string                        `json:"protocolVersion"`
	DirectIntentID       domain.ID                     `json:"directIntentId"`
	EpochID              domain.ID                     `json:"epochId"`
	ProposalID           domain.ID                     `json:"proposalId"`
	ProposalVersion      int64                         `json:"proposalVersion"`
	GrantID              domain.ID                     `json:"grantId"`
	GrantGeneration      int64                         `json:"grantGeneration"`
	NetworkID            domain.ID                     `json:"networkId"`
	InviterTenantID      domain.ID                     `json:"inviterTenantId"`
	InviterAccountID     domain.ID                     `json:"inviterAccountId"`
	InviteeTenantID      domain.ID                     `json:"inviteeTenantId"`
	InviteeAccountID     domain.ID                     `json:"inviteeAccountId"`
	SourcePrincipalID    domain.ID                     `json:"sourcePrincipalId"`
	SelectedSources      []DirectAuthorizationSourceV1 `json:"selectedSources"`
	Target               DirectAuthorizationTargetV1   `json:"target"`
	ConsentVersion       int64                         `json:"consentVersion"`
	CommunicationProfile string                        `json:"communicationProfile"`
	Permissions          []string                      `json:"permissions"`
	HistoryPolicy        string                        `json:"historyPolicy"`
	HolderScope          string                        `json:"holderScope"`
	CreatedAt            time.Time                     `json:"createdAt"`
	ExpiresAt            time.Time                     `json:"expiresAt"`
	GrantExpiresAt       time.Time                     `json:"grantExpiresAt"`
}

func (p DirectAuthorizationSnapshotV1) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectAuthorizationSnapshotProtocol || p.ProposalVersion != 3 || p.ConsentVersion != 3 || p.GrantGeneration < 1 || p.CommunicationProfile != "direct_ask_reply_v1" || p.HistoryPolicy != "future_only" || p.HolderScope != "selected_direct_channel_endpoints" || len(p.Permissions) != 2 || p.Permissions[0] != "direct_ask" || p.Permissions[1] != "direct_reply" || len(p.SelectedSources) < 1 || len(p.SelectedSources) > 4 {
		return nil, errManagedEndpointBinding
	}
	for _, id := range []domain.ID{p.DirectIntentID, p.EpochID, p.ProposalID, p.GrantID, p.NetworkID, p.InviterTenantID, p.InviterAccountID, p.InviteeTenantID, p.InviteeAccountID, p.SourcePrincipalID, p.Target.PrincipalID, domain.ID(p.Target.AuthorityGeneration)} {
		if !nativeShareBindingID(id) {
			return nil, errManagedEndpointBinding
		}
	}
	found := false
	for i, s := range p.SelectedSources {
		if !nativeShareBindingID(s.PrincipalID) || !nativeShareBindingID(domain.ID(s.AuthorityGeneration)) || !nativeShareBindingID(domain.ID(s.MembershipAuthorityGeneration)) || (i > 0 && p.SelectedSources[i-1].PrincipalID >= s.PrincipalID) {
			return nil, errManagedEndpointBinding
		}
		found = found || s.PrincipalID == p.SourcePrincipalID
	}
	if !found || (p.Target.NetworkID == nil) != (p.Target.MembershipAuthorityGeneration == nil) {
		return nil, errManagedEndpointBinding
	}
	if p.Target.NetworkID != nil && (!nativeShareBindingID(*p.Target.NetworkID) || !nativeShareBindingID(domain.ID(*p.Target.MembershipAuthorityGeneration))) {
		return nil, errManagedEndpointBinding
	}
	for _, v := range []time.Time{p.CreatedAt, p.ExpiresAt, p.GrantExpiresAt} {
		if v.IsZero() || v.Year() < 1 || v.Year() > 9999 {
			return nil, errManagedEndpointBinding
		}
	}
	if !p.CreatedAt.Before(p.ExpiresAt) || p.ExpiresAt.After(p.GrantExpiresAt) {
		return nil, errManagedEndpointBinding
	}
	p.CreatedAt = p.CreatedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	p.GrantExpiresAt = p.GrantExpiresAt.UTC()
	return json.Marshal(p)
}

func (p DirectAuthorizationSnapshotV1) Digest() (string, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return managedEndpointDigest("pagnet/direct-authorization-snapshot/v1/", raw), nil
}

func DecodeDirectAuthorizationSnapshotV1(raw []byte) (DirectAuthorizationSnapshotV1, error) {
	var p DirectAuthorizationSnapshotV1
	if !managedEndpointCanonicalDecode(raw, &p, 32*1024) {
		return DirectAuthorizationSnapshotV1{}, errManagedEndpointBinding
	}
	return p, nil
}

func managedEndpointDigest(domain string, raw []byte) string {
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:])
}

// Exact canonical comparison also rejects unknown/missing fields, duplicate
// keys, noncanonical numbers/times/escapes, malformed Unicode and trailing data.
func managedEndpointCanonicalDecode(raw []byte, p interface{ CanonicalBytes() ([]byte, error) }, limit int) bool {
	if len(raw) > limit || !managedEndpointJSONStringsValid(raw) || json.Unmarshal(raw, p) != nil {
		return false
	}
	canonical, err := p.CanonicalBytes()
	return err == nil && bytes.Equal(raw, canonical)
}
