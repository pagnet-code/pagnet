package transport

import (
	"github.com/pagnet-code/pagnet/e2ee"
	"time"
)

const NativeWorkerOwnershipProtocol = "native-worker-ownership-v1"
const (
	MsgNativeOwnershipRegister   = "host.native_ownership_register"
	MsgNativeOwnershipRegistered = "host.native_ownership_registered"
	MsgNativeOwnershipRetire     = "host.native_ownership_retire"
	MsgNativeOwnershipRetired    = "host.native_ownership_retired"
)

type NativeOwnershipRegisterPayload struct {
	RequestID           string `json:"requestId"`
	NativeAdmissionID   string `json:"nativeAdmissionId"`
	InstanceID          string `json:"instanceId"`
	OwnershipGeneration string `json:"ownershipGeneration"`
	Runtime             string `json:"runtime"`
	Profile             string `json:"profile"`
	PreviousOwnershipID string `json:"previousOwnershipId,omitempty"`
	ProfileFingerprint  string `json:"profileFingerprint"`
}
type NativeWorkerOwnership struct {
	DeletionProof        *NativeOwnershipDeletionProof `json:"deletionProof,omitempty"`
	ID                   string                        `json:"id"`
	InstanceID           string                        `json:"instanceId"`
	OwnershipGeneration  string                        `json:"ownershipGeneration"`
	Runtime              string                        `json:"runtime"`
	Profile              string                        `json:"profile"`
	OriginalAdmissionID  string                        `json:"originalAdmissionId"`
	State                string                        `json:"state"`
	LastDispatchSequence int64                         `json:"lastDispatchSequence"`
	RetiredFloor         int64                         `json:"retiredFloor"`
	ProfileFingerprint   string                        `json:"profileFingerprint"`
}

// Present only on authenticated retired ownership after explicit owner deletion
// and genuine original stopped receipt. It authorizes no new native execution.
type NativeOwnershipDeletionProof struct {
	DeleteRequestID       string              `json:"deleteRequestId"`
	StopProof             NativeDispatchProof `json:"stopProof"`
	OriginID              string              `json:"originId"`
	NativeGeneration      string              `json:"nativeGeneration"`
	NativeSessionID       string              `json:"nativeSessionId"`
	StoppedObservationID  string              `json:"stoppedObservationId"`
	StoppedDigest         string              `json:"stoppedDigest"`
	StoppedDisposition    string              `json:"stoppedDisposition"`
	StoppedSourceSequence int64               `json:"stoppedSourceSequence"`
	StoppedObservedAt     time.Time           `json:"stoppedObservedAt"`
	StoppedExpiresAt      time.Time           `json:"stoppedExpiresAt"`
}

// Retirement advances only contiguous settled dispatch outcomes. Uncertain ordinals
// are above the claimed floor and remain permanently non-replayable blockers.
type NativeOwnershipRetirePayload struct {
	// Explicit completed stop of an owner with no materialized native endpoint.
	// This is controller lifecycle evidence, never a fabricated runtime EOF.
	UnstartedStop              *NativeDispatchProof `json:"unstartedStop,omitempty"`
	RequestID                  string               `json:"requestId"`
	OwnershipID                string               `json:"ownershipId"`
	OwnershipGeneration        string               `json:"ownershipGeneration"`
	RetiredDispatchSequence    int64                `json:"retiredDispatchSequence"`
	UncertainDispatchSequences []int64              `json:"uncertainDispatchSequences,omitempty"`
	Retire                     bool                 `json:"retire,omitempty"`
}
type NativeDispatchProof struct {
	InvocationSource    *NativeInvocationSource `json:"invocationSource,omitempty"`
	TaskSource          *NativeTaskSource       `json:"taskSource,omitempty"`
	SourceBootID        string                  `json:"sourceBootId"`
	OwnershipID         string                  `json:"ownershipId"`
	OwnershipGeneration string                  `json:"ownershipGeneration"`
	DispatchSequence    int64                   `json:"dispatchSequence"`
	SourceCommandID     string                  `json:"sourceCommandId"`
	SourceAdmissionID   string                  `json:"sourceAdmissionId"`
	SourceRunnerID      string                  `json:"sourceRunnerId"`
	SourceRunnerEpoch   time.Time               `json:"sourceRunnerEpoch"`
}

type NativeOwnershipRegisteredPayload struct {
	UnstartedStop *NativeDispatchProof   `json:"unstartedStop,omitempty"`
	RequestID     string                 `json:"requestId"`
	Ownership     *NativeWorkerOwnership `json:"ownership,omitempty"`
	PublicError   string                 `json:"publicError,omitempty"`
	Retryable     bool                   `json:"retryable,omitempty"`
}

const MsgNativeOwnershipPrepare = "host.native_ownership_prepare"

// Preparation is configuration only. It has no dispatch ordinal, admission or
// authorization to execute native input. Launch retains the original command ID
// and encrypted configuration/AAD; it must never enter the command submit path.
type NativeOwnershipPreparePayload struct {
	ProtectedContextRequired bool                   `json:"protectedContextRequired,omitempty"`
	ProtectedContextReady    bool                   `json:"protectedContextReady,omitempty"`
	ProtectedContext         *e2ee.ProtectedContext `json:"protectedContext,omitempty"`
	ProtectedContextEpochID  string                 `json:"protectedContextEpochId,omitempty"`
	SourceCommandID          string                 `json:"sourceCommandId"`
	SourceCommandType        string                 `json:"sourceCommandType"`
	InstanceID               string                 `json:"instanceId"`
	Runtime                  string                 `json:"runtime"`
	Profile                  string                 `json:"profile"`
	Launch                   *LaunchAgentPayload    `json:"launch,omitempty"`
	Ownership                *NativeWorkerOwnership `json:"ownership,omitempty"`
}
