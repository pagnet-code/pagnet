package directhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/transport"
)

// Enrollment is the caller's retained enrollment evidence. It contains no peer
// readiness evidence or purpose-limited secrets.
type Enrollment struct {
	DescriptorHash  string                `json:"descriptorHash"`
	PublicationHash *string               `json:"publicationHash"`
	Challenge       *EnrollmentChallenge  `json:"challenge"`
	Proof           *EnrollmentProof      `json:"proof"`
	Activation      *EnrollmentActivation `json:"activation"`
	Authority       EnrollmentAuthority   `json:"authority"`
	ObservedAt      time.Time             `json:"observedAt"`
}

type EnrollmentChallenge struct {
	Challenge      transport.DirectChannelReadinessChallengeV2 `json:"challenge"`
	TranscriptHash string                                      `json:"transcriptHash"`
}

type EnrollmentProof struct {
	Digest     string    `json:"digest"`
	ReceivedAt time.Time `json:"receivedAt"`
}

type EnrollmentActivation struct {
	ActivatedAt time.Time `json:"activatedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type EnrollmentAuthority struct {
	ParentGrantID     string    `json:"parentGrantId"`
	GrantGeneration   string    `json:"grantGeneration"`
	ChannelID         string    `json:"channelId"`
	ChannelGeneration string    `json:"channelGeneration"`
	EpochID           string    `json:"epochId"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

func enrollmentTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && offset == 0
}

func enrollmentDecimal(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}

// Enrollment reads recovery evidence without issuing challenges or mutating
// enrollment. The server scopes it through credential possession and the intent
// path. When Challenge is absent, callers must bind the hash and authority to a
// separately fetched descriptor to establish the local party binding.
func (c *Client) Enrollment(ctx context.Context, credential, id, role string) (Enrollment, error) {
	if role != "S" && role != "P" {
		return Enrollment{}, failure(Invalid)
	}
	raw, err := c.intent(ctx, credential, id, "GET", "/enrollment", nil, 8192, false)
	if err != nil {
		return Enrollment{}, err
	}
	var v Enrollment
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return Enrollment{}, failure(Protocol)
	}
	// Exact re-encoding also rejects duplicate or missing fields, alternate field
	// spellings, noncanonical times, whitespace and trailing JSON.
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) || !v.valid(credential, id, role) {
		return Enrollment{}, failure(Protocol)
	}
	return v, nil
}

func (v Enrollment) valid(credential, id, role string) bool {
	a := v.Authority
	epoch, err := uuid.Parse(a.EpochID)
	if !validBinary(v.DescriptorHash) || !validID(a.ParentGrantID) || !enrollmentDecimal(a.GrantGeneration) || !validBinary(a.ChannelID) || !enrollmentDecimal(a.ChannelGeneration) || !validID(a.EpochID) || err != nil || epoch.Version() != 7 || epoch.Variant() != uuid.RFC4122 || !enrollmentTime(a.ExpiresAt) || !enrollmentTime(v.ObservedAt) || !v.ObservedAt.Before(a.ExpiresAt) {
		return false
	}
	if v.PublicationHash != nil && !validBinary(*v.PublicationHash) {
		return false
	}
	if v.Challenge != nil {
		ch := v.Challenge.Challenge
		raw, err := ch.CanonicalBytes()
		sum := sha256.Sum256(raw)
		cid, _ := credentialID(credential)
		issued, _ := time.Parse(time.RFC3339Nano, ch.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, ch.ExpiresAt)
		if err != nil || v.PublicationHash == nil || ch.Role != role || ch.CredentialID != cid || ch.DirectIntentID != id || ch.DescriptorHash != v.DescriptorHash || ch.PublicationHash != *v.PublicationHash || ch.ParentGrantID != a.ParentGrantID || ch.GrantGeneration != a.GrantGeneration || ch.ChannelID != a.ChannelID || ch.ChannelGeneration != a.ChannelGeneration || ch.EpochID != a.EpochID || issued.After(v.ObservedAt) || expires.After(a.ExpiresAt) || v.Challenge.TranscriptHash != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return false
		}
	}
	if v.Proof != nil {
		if v.Challenge == nil || !validBinary(v.Proof.Digest) || !enrollmentTime(v.Proof.ReceivedAt) || v.Proof.ReceivedAt.After(v.ObservedAt) {
			return false
		}
		issued, _ := time.Parse(time.RFC3339Nano, v.Challenge.Challenge.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, v.Challenge.Challenge.ExpiresAt)
		if v.Proof.ReceivedAt.Before(issued) || !v.Proof.ReceivedAt.Before(expires) {
			return false
		}
	}
	if v.Activation != nil {
		x := v.Activation
		if v.Proof == nil || !enrollmentTime(x.ActivatedAt) || !enrollmentTime(x.ExpiresAt) || x.ActivatedAt.Before(v.Proof.ReceivedAt) || x.ActivatedAt.After(v.ObservedAt) || !x.ExpiresAt.After(x.ActivatedAt) || !x.ExpiresAt.Equal(a.ExpiresAt) {
			return false
		}
	}
	return true
}
