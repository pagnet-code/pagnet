package federation

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type AdmissionAction string

const (
	ActionAdmit      AdmissionAction = "admit"
	ActionAttempt    AdmissionAction = "attempt"
	ActionAssociate  AdmissionAction = "associate"
	ActionRead       AdmissionAction = "read"
	ActionCancel     AdmissionAction = "cancel"
	ActionCheckpoint AdmissionAction = "checkpoint"
)

// These are bounded local retained-state checks only. External authorization
// belongs in the extension pipeline BEFORE admission, never under the SQL lock.
type CurrentCallerPolicy interface {
	AuthorizeTx(context.Context, *registry.AuthorityTx, AdmissionAction, fabric.ExecutionContext, AdmissionFacts) error
}

type AdmissionLimits struct {
	MaxInvocations uint64 `json:"maxInvocations,string"`
	MaxBytes       uint64 `json:"maxBytes,string"`
}

func (l AdmissionLimits) valid() bool {
	return l.MaxInvocations > 0 && l.MaxInvocations <= 1000000 && l.MaxBytes >= 4096 && l.MaxBytes <= 1<<40
}

type AdmissionConfig struct {
	Store *registry.Store
	Owner func(context.Context) (fabric.ExecutionContext, error)
	// Protector is pre-resolved synchronous bounded local crypto. Seal/Open
	// must never perform credential/provider IO or recurse into registry SQL.
	Protector    durable.DataProtector
	Peers        PeerTxGate
	Policy       CurrentCallerPolicy
	Limits       AdmissionLimits
	Verification VerifyLimits
}
type AdmissionFacts struct {
	Principal                       fabric.Principal
	InvocationID                    string
	BundleDigest                    [32]byte
	OriginalDigest, ForwardedDigest [32]byte
	Source, Destination             PeerBinding
	Target                          *fabric.EndpointRef
	ExpectedRevision                fabric.Revision
}

// Admission is an opaque in-process reference to an actual retained admission.
// Restart obtains it only by authenticating/readback of the exact original
// bundle, never by decoding arbitrary request labels or selecting a new target.
type Admission struct {
	ledger *AdmissionLedger
	key    string
	digest [32]byte
}

func (Admission) MarshalJSON() ([]byte, error) { return nil, protocolError() }
func (*Admission) UnmarshalJSON([]byte) error  { return authError() }

type Association struct {
	Protocol         string          `json:"protocol"`
	BindingDigest    [32]byte        `json:"bindingDigest"`
	PrivateReference json.RawMessage `json:"privateReference"`
}
type ConsumerCursor struct {
	Ordinal     int64    `json:"ordinal,string"`
	FrameDigest [32]byte `json:"frameDigest"`
}

// CursorVerifier verifies an actual original adapter/native frame. A received
// cursor/hash is not evidence. Checkpoint must commit BEFORE acknowledging the
// corresponding source-retained frame; no distributed atomicity is claimed.
// The verifier performs bounded local retained-state checks only, never remote
// provider IO or another registry transaction while this transaction is held.
type CursorVerifier interface {
	VerifyCursorTx(context.Context, *registry.AuthorityTx, AdmissionFacts, Association, ConsumerCursor) error
}
type AdmissionStatus struct {
	Attempted       bool
	CancelRequested bool
	Association     *Association
	Cursor          ConsumerCursor
}
type AttemptPermit struct {
	admission Admission
	attemptID string
}

func (AttemptPermit) MarshalJSON() ([]byte, error) { return nil, protocolError() }
func (*AttemptPermit) UnmarshalJSON([]byte) error  { return authError() }
func (p AttemptPermit) ID() string                 { return p.attemptID }
