// Package continuation stores private, single-use deferred execution evidence.
// A durable claim is not evidence that endpoint effects completed. Recovery never
// automatically executes a claimed continuation. Trusted engine composition owns
// authorization, pipeline interpretation and explicit effect settlement.
package continuation

import (
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type Scope struct {
	Audience string `json:"audience"`
}
type Options struct {
	MaxRecords       int64
	MaxBytes         int64
	MaxSnapshotBytes int
	MaxOutcomeBytes  int
	MaxDatabaseBytes int64
	MaxTTL           time.Duration
	MaxJSONDepth     int
	MaxJSONMembers   int
}

func DefaultOptions() Options {
	return Options{MaxRecords: 100000, MaxBytes: 256 << 20, MaxSnapshotBytes: 8 << 20, MaxOutcomeBytes: 1 << 20, MaxDatabaseBytes: 512 << 20, MaxTTL: 7 * 24 * time.Hour, MaxJSONDepth: 64, MaxJSONMembers: 65536}
}

type Snapshot struct {
	Format                  uint32             `json:"format"`
	DeferralID              string             `json:"deferralId"`
	OriginalEnvelope        []byte             `json:"originalEnvelope"`
	OriginalPrincipal       fabric.Principal   `json:"originalPrincipal"`
	AllowedResumePrincipals []fabric.Principal `json:"allowedResumePrincipals"`
	PlanRevision            fabric.Revision    `json:"planRevision"`
	PlanVersion             string             `json:"planVersion"`
	PlanDigest              string             `json:"planDigest"`
	Pipeline                []byte             `json:"pipeline"`
	State                   []byte             `json:"state"`
}

// Capability deliberately redacts formatting and refuses wire serialization.
// Token is an explicit private delivery operation; never insert it in outcomes.
type Capability struct{ token string }

func (Capability) String() string   { return "[private continuation capability]" }
func (Capability) GoString() string { return "[private continuation capability]" }
func (Capability) MarshalJSON() ([]byte, error) {
	return nil, invalid("private capability is not public JSON")
}
func (c Capability) Token() string { return c.token }

type Issued struct {
	ID                 string     `json:"id"`
	CapabilityRevision uint64     `json:"capabilityRevision"`
	Created            bool       `json:"created"`
	Capability         Capability `json:"-"`
}
type State string

const (
	Pending  State = "pending"
	Claimed  State = "claimed"
	Complete State = "complete"
)

type Receipt struct {
	ID                 string           `json:"id"`
	ClaimID            string           `json:"claimId"`
	Principal          fabric.Principal `json:"principal"`
	Audience           string           `json:"audience"`
	SnapshotDigest     string           `json:"snapshotDigest"`
	PlanDigest         string           `json:"planDigest"`
	CapabilityRevision uint64           `json:"capabilityRevision"`
	ClaimedAt          time.Time        `json:"claimedAt"`
}
type Outcome struct {
	Effect fabric.EffectState `json:"effect"`
	Data   []byte             `json:"data"`
}
type ClaimResult struct {
	Receipt  Receipt  `json:"receipt"`
	Snapshot Snapshot `json:"snapshot"`
	State    State    `json:"state"`
	Fresh    bool     `json:"fresh"`
	Outcome  *Outcome `json:"outcome,omitempty"`
}
