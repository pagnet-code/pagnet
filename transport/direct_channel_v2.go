package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	DirectChannelDomainV2                     = "pagnet/direct_ask_reply_v2"
	DirectChannelSuiteV2                      = "X25519-HKDF-SHA256-AES-256-GCM-Auth"
	DirectChannelCountingVersionV2            = "canonical_encrypted_wire_bytes_utc_minute_day_ask_reply_each_v1"
	DirectChannelReadinessProtocolV2          = "direct_channel_readiness_v2"
	DirectChannelDescriptorMaxBytesV2         = 8192
	DirectChannelPublicationMaxBytesV2        = 12288
	DirectChannelReadinessChallengeMaxBytesV2 = 4096
	DirectChannelReadinessProofMaxBytesV2     = 1024
)

var errDirectChannelV2 = errors.New("transport: invalid direct channel v2 contract")

// Declaration order defines canonical JSON. All fields are required.
type DirectChannelEndpointV2 struct {
	TenantID          string `json:"tenantId"`
	PrincipalID       string `json:"principalId"`
	EndpointID        string `json:"endpointId"`
	PublicKey         string `json:"publicKey"`
	CredentialID      string `json:"credentialId"`
	KeyEvidenceDigest string `json:"keyEvidenceDigest"`
}
type DirectChannelLimitsV2 struct {
	MaxMessageWireBytes  int `json:"maxMessageWireBytes"`
	MaxMessagesPerMinute int `json:"maxMessagesPerMinute"`
	MaxMessagesPerDay    int `json:"maxMessagesPerDay"`
	MaxWireBytesPerDay   int `json:"maxWireBytesPerDay"`
	MaxInFlight          int `json:"maxInFlight"`
	MaxTurnsPerThread    int `json:"maxTurnsPerThread"`
}
type DirectChannelBudgetV2 struct {
	AgreementID      string                `json:"agreementId"`
	AcceptedRevision string                `json:"acceptedRevision"`
	TermsDigest      string                `json:"termsDigest"`
	ExpiresAt        string                `json:"expiresAt"`
	CountingVersion  string                `json:"countingVersion"`
	GrantLimits      DirectChannelLimitsV2 `json:"grantLimits"`
}
type DirectChannelDescriptorV2 struct {
	Domain              string                  `json:"domain"`
	Suite               string                  `json:"suite"`
	ParentGrantID       string                  `json:"parentGrantId"`
	GrantGeneration     string                  `json:"grantGeneration"`
	ChannelGeneration   string                  `json:"channelGeneration"`
	DirectIntentID      string                  `json:"directIntentId"`
	NetworkID           string                  `json:"networkId"`
	AuthorizationDigest string                  `json:"authorizationDigest"`
	S                   DirectChannelEndpointV2 `json:"s"`
	P                   DirectChannelEndpointV2 `json:"p"`
	EpochID             string                  `json:"epochId"`
	ExpiresAt           string                  `json:"expiresAt"`
	Budget              DirectChannelBudgetV2   `json:"budget"`
	Limits              DirectChannelLimitsV2   `json:"limits"`
}
type DirectChannelPublicationV2 struct {
	Descriptor DirectChannelDescriptorV2 `json:"descriptor"`
	Enc        string                    `json:"enc"`
	Ciphertext string                    `json:"ciphertext"`
}
type DirectChannelReadinessChallengeV2 struct {
	Domain            string `json:"domain"`
	ChallengeID       string `json:"challengeId"`
	Role              string `json:"role"`
	PrincipalID       string `json:"principalId"`
	EndpointID        string `json:"endpointId"`
	CredentialID      string `json:"credentialId"`
	ChannelID         string `json:"channelId"`
	ParentGrantID     string `json:"parentGrantId"`
	GrantGeneration   string `json:"grantGeneration"`
	ChannelGeneration string `json:"channelGeneration"`
	DirectIntentID    string `json:"directIntentId"`
	DescriptorHash    string `json:"descriptorHash"`
	PublicationHash   string `json:"publicationHash"`
	EpochID           string `json:"epochId"`
	Nonce             string `json:"nonce"`
	IssuedAt          string `json:"issuedAt"`
	ExpiresAt         string `json:"expiresAt"`
}
type DirectChannelReadinessProofV2 struct {
	ProtocolVersion string `json:"protocolVersion"`
	ChallengeID     string `json:"challengeId"`
	TranscriptHash  string `json:"transcriptHash"`
	Confirmation    string `json:"confirmation"`
}

func directV2ID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
func directV2Decimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func directV2Time(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil && t.UTC().Format(time.RFC3339Nano) == s
}
func directV2Binary(s string, size int) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) == size && base64.RawURLEncoding.EncodeToString(b) == s
}
func directV2Digest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func directV2PublicKey(s string) bool {
	b, ok := directV2Binary(s, 32)
	if !ok || b[31]&128 != 0 {
		return false
	}
	// X25519 masks/reduces encodings; require the canonical field element < 2^255-19.
	prime := [32]byte{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
	less := false
	for i := 31; i >= 0; i-- {
		if b[i] != prime[i] {
			less = b[i] < prime[i]
			break
		}
	}
	if !less {
		return false
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return false
	}
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		return false
	}
	_, err = private.ECDH(pub) // Reject every low-order point, including nonzero ones.
	return err == nil
}
func (p DirectChannelEndpointV2) valid() bool {
	return directV2ID(p.TenantID) && directV2ID(p.PrincipalID) && directV2ID(p.EndpointID) && directV2ID(p.CredentialID) && directV2PublicKey(p.PublicKey) && directV2Digest(p.KeyEvidenceDigest)
}
func (l DirectChannelLimitsV2) valid() bool {
	return l.MaxMessageWireBytes >= 1024 && l.MaxMessageWireBytes <= 65536 && l.MaxMessagesPerMinute >= 1 && l.MaxMessagesPerMinute <= 10 && l.MaxMessagesPerDay >= 1 && l.MaxMessagesPerDay <= 200 && l.MaxWireBytesPerDay >= l.MaxMessageWireBytes && l.MaxWireBytesPerDay <= 8388608 && l.MaxInFlight >= 1 && l.MaxInFlight <= 2 && l.MaxTurnsPerThread >= 1 && l.MaxTurnsPerThread <= 16
}
func (l DirectChannelLimitsV2) within(g DirectChannelLimitsV2) bool {
	return l.MaxMessageWireBytes <= g.MaxMessageWireBytes && l.MaxMessagesPerMinute <= g.MaxMessagesPerMinute && l.MaxMessagesPerDay <= g.MaxMessagesPerDay && l.MaxWireBytesPerDay <= g.MaxWireBytesPerDay && l.MaxInFlight <= g.MaxInFlight && l.MaxTurnsPerThread <= g.MaxTurnsPerThread
}

// ValidateDirectChannelDescriptorV2 validates structure and expiry only. It does
// not authenticate current endpoint authority, consent, or budget. Callers must
// resolve retained evidence and pin the exact selected S endpoint before use.
func ValidateDirectChannelDescriptorV2(d DirectChannelDescriptorV2, now time.Time) error {
	expiry, ok := directV2Time(d.ExpiresAt)
	budgetExpiry, bok := directV2Time(d.Budget.ExpiresAt)
	epoch, err := uuid.Parse(d.EpochID)
	if d.Domain != DirectChannelDomainV2 || d.Suite != DirectChannelSuiteV2 || !directV2ID(d.ParentGrantID) || !directV2Decimal(d.GrantGeneration) || !directV2Decimal(d.ChannelGeneration) || !directV2ID(d.DirectIntentID) || !directV2ID(d.NetworkID) || !directV2Digest(d.AuthorizationDigest) || !d.S.valid() || !d.P.valid() || d.S.PrincipalID == d.P.PrincipalID || d.S.EndpointID == d.P.EndpointID || d.S.PublicKey == d.P.PublicKey || err != nil || !directV2ID(d.EpochID) || epoch.Version() != 7 || !ok || !bok || !expiry.After(now) || expiry.After(budgetExpiry) || !directV2ID(d.Budget.AgreementID) || (!directV2Decimal(d.Budget.AcceptedRevision) || d.Budget.AcceptedRevision == "1") || !directV2Digest(d.Budget.TermsDigest) || d.Budget.CountingVersion != DirectChannelCountingVersionV2 || !d.Limits.valid() || !d.Budget.GrantLimits.valid() || !d.Limits.within(d.Budget.GrantLimits) {
		return errDirectChannelV2
	}
	return nil
}
func directV2Canonical(value any, max int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > max {
		return nil, errDirectChannelV2
	}
	return raw, nil
}
func directV2Decode(raw []byte, value any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) || json.Unmarshal(raw, value) != nil {
		return errDirectChannelV2
	}
	canonical, err := directV2Canonical(value, max)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errDirectChannelV2
	}
	return nil
}
func (d DirectChannelDescriptorV2) CanonicalBytes() ([]byte, error) {
	if err := ValidateDirectChannelDescriptorV2(d, time.Time{}); err != nil {
		return nil, err
	}
	return directV2Canonical(d, DirectChannelDescriptorMaxBytesV2)
}
func DecodeDirectChannelDescriptorV2(raw []byte) (DirectChannelDescriptorV2, error) {
	var d DirectChannelDescriptorV2
	if directV2Decode(raw, &d, DirectChannelDescriptorMaxBytesV2) != nil {
		return DirectChannelDescriptorV2{}, errDirectChannelV2
	}
	if _, err := d.CanonicalBytes(); err != nil {
		return DirectChannelDescriptorV2{}, err
	}
	return d, nil
}
func (p DirectChannelPublicationV2) CanonicalBytes() ([]byte, error) {
	if _, err := p.Descriptor.CanonicalBytes(); err != nil {
		return nil, err
	}
	if _, ok := directV2Binary(p.Ciphertext, 48); !ok || !directV2PublicKey(p.Enc) {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(p, DirectChannelPublicationMaxBytesV2)
}
func DecodeDirectChannelPublicationV2(raw []byte) (DirectChannelPublicationV2, error) {
	var p DirectChannelPublicationV2
	if directV2Decode(raw, &p, DirectChannelPublicationMaxBytesV2) != nil {
		return DirectChannelPublicationV2{}, errDirectChannelV2
	}
	if _, err := p.CanonicalBytes(); err != nil {
		return DirectChannelPublicationV2{}, err
	}
	return p, nil
}
func directV2Hash(raw []byte) string {
	h := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func DirectChannelIDV2(d DirectChannelDescriptorV2) (string, error) {
	if _, err := d.CanonicalBytes(); err != nil {
		return "", err
	}
	identity := struct {
		Domain            string                  `json:"domain"`
		ParentGrantID     string                  `json:"parentGrantId"`
		GrantGeneration   string                  `json:"grantGeneration"`
		ChannelGeneration string                  `json:"channelGeneration"`
		DirectIntentID    string                  `json:"directIntentId"`
		S                 DirectChannelEndpointV2 `json:"s"`
		P                 DirectChannelEndpointV2 `json:"p"`
		EpochID           string                  `json:"epochId"`
	}{DirectChannelDomainV2 + "/channel-id", d.ParentGrantID, d.GrantGeneration, d.ChannelGeneration, d.DirectIntentID, d.S, d.P, d.EpochID}
	raw, err := json.Marshal(identity)
	return directV2Hash(raw), err
}
func DescriptorHashV2(d DirectChannelDescriptorV2) (string, error) {
	raw, err := d.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return directV2Hash(raw), nil
}
func PublicationHashV2(p DirectChannelPublicationV2) (string, error) {
	raw, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return directV2Hash(raw), nil
}
func (c DirectChannelReadinessChallengeV2) CanonicalBytes() ([]byte, error) {
	issued, iok := directV2Time(c.IssuedAt)
	expiry, eok := directV2Time(c.ExpiresAt)
	epoch, err := uuid.Parse(c.EpochID)
	if c.Domain != DirectChannelDomainV2+"/proof" || !directV2ID(c.ChallengeID) || (c.Role != "S" && c.Role != "P") || !directV2ID(c.PrincipalID) || !directV2ID(c.EndpointID) || !directV2ID(c.CredentialID) || !directV2ID(c.ParentGrantID) || !directV2Decimal(c.GrantGeneration) || !directV2Decimal(c.ChannelGeneration) || !directV2ID(c.DirectIntentID) || !directV2ID(c.EpochID) || err != nil || epoch.Version() != 7 || !iok || !eok || !expiry.After(issued) || expiry.After(issued.Add(5*time.Minute)) {
		return nil, errDirectChannelV2
	}
	for _, s := range []string{c.ChannelID, c.DescriptorHash, c.PublicationHash, c.Nonce} {
		if _, ok := directV2Binary(s, 32); !ok {
			return nil, errDirectChannelV2
		}
	}
	return directV2Canonical(c, DirectChannelReadinessChallengeMaxBytesV2)
}
func DecodeDirectChannelReadinessChallengeV2(raw []byte) (DirectChannelReadinessChallengeV2, error) {
	var c DirectChannelReadinessChallengeV2
	if directV2Decode(raw, &c, DirectChannelReadinessChallengeMaxBytesV2) != nil {
		return DirectChannelReadinessChallengeV2{}, errDirectChannelV2
	}
	if _, err := c.CanonicalBytes(); err != nil {
		return DirectChannelReadinessChallengeV2{}, err
	}
	return c, nil
}
func (p DirectChannelReadinessProofV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectChannelReadinessProtocolV2 || !directV2ID(p.ChallengeID) {
		return nil, errDirectChannelV2
	}
	for _, s := range []string{p.TranscriptHash, p.Confirmation} {
		if _, ok := directV2Binary(s, 32); !ok {
			return nil, errDirectChannelV2
		}
	}
	return directV2Canonical(p, DirectChannelReadinessProofMaxBytesV2)
}
func DecodeDirectChannelReadinessProofV2(raw []byte) (DirectChannelReadinessProofV2, error) {
	var p DirectChannelReadinessProofV2
	if directV2Decode(raw, &p, DirectChannelReadinessProofMaxBytesV2) != nil {
		return DirectChannelReadinessProofV2{}, errDirectChannelV2
	}
	if _, err := p.CanonicalBytes(); err != nil {
		return DirectChannelReadinessProofV2{}, err
	}
	return p, nil
}

// VerifyDirectChannelReadinessProofV2 binds possession of readinessKey to the
// exact publication, selected role/endpoint and time-bounded challenge. It does
// not establish current authority, consent, budget availability, or activation;
// the caller must authenticate retained evidence and the selected S endpoint.
func VerifyDirectChannelReadinessProofV2(publication DirectChannelPublicationV2, challenge DirectChannelReadinessChallengeV2, proof DirectChannelReadinessProofV2, readinessKey []byte, now time.Time) error {
	if len(readinessKey) != 32 || ValidateDirectChannelDescriptorV2(publication.Descriptor, now) != nil {
		return errDirectChannelV2
	}
	raw, err := challenge.CanonicalBytes()
	if err != nil {
		return err
	}
	if _, err = proof.CanonicalBytes(); err != nil {
		return err
	}
	publicationHash, err := PublicationHashV2(publication)
	if err != nil {
		return err
	}
	d := publication.Descriptor
	descriptorHash, _ := DescriptorHashV2(d)
	channelID, _ := DirectChannelIDV2(d)
	party := d.S
	if challenge.Role == "P" {
		party = d.P
	}
	issued, _ := directV2Time(challenge.IssuedAt)
	expiry, _ := directV2Time(challenge.ExpiresAt)
	descriptorExpiry, _ := directV2Time(d.ExpiresAt)
	if now.Before(issued) || !expiry.After(now) || expiry.After(descriptorExpiry) || challenge.PrincipalID != party.PrincipalID || challenge.EndpointID != party.EndpointID || challenge.CredentialID != party.CredentialID || challenge.ChannelID != channelID || challenge.ParentGrantID != d.ParentGrantID || challenge.GrantGeneration != d.GrantGeneration || challenge.ChannelGeneration != d.ChannelGeneration || challenge.DirectIntentID != d.DirectIntentID || challenge.DescriptorHash != descriptorHash || challenge.PublicationHash != publicationHash || challenge.EpochID != d.EpochID || proof.ChallengeID != challenge.ChallengeID {
		return errDirectChannelV2
	}
	transcript := sha256.Sum256(raw)
	claimed, _ := directV2Binary(proof.TranscriptHash, 32)
	mac := hmac.New(sha256.New, readinessKey)
	mac.Write(raw)
	confirmation, _ := directV2Binary(proof.Confirmation, 32)
	if !hmac.Equal(transcript[:], claimed) || !hmac.Equal(mac.Sum(nil), confirmation) {
		return errDirectChannelV2
	}
	return nil
}
