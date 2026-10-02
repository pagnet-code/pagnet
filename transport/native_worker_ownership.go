package transport

import "time"

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
	ID                   string `json:"id"`
	InstanceID           string `json:"instanceId"`
	OwnershipGeneration  string `json:"ownershipGeneration"`
	Runtime              string `json:"runtime"`
	Profile              string `json:"profile"`
	OriginalAdmissionID  string `json:"originalAdmissionId"`
	State                string `json:"state"`
	LastDispatchSequence int64  `json:"lastDispatchSequence"`
	RetiredFloor         int64  `json:"retiredFloor"`
	ProfileFingerprint   string `json:"profileFingerprint"`
}

// Retirement advances only contiguous settled dispatch outcomes. Uncertain ordinals
// are above the claimed floor and remain permanently non-replayable blockers.
type NativeOwnershipRetirePayload struct {
	RequestID                  string  `json:"requestId"`
	OwnershipID                string  `json:"ownershipId"`
	OwnershipGeneration        string  `json:"ownershipGeneration"`
	RetiredDispatchSequence    int64   `json:"retiredDispatchSequence"`
	UncertainDispatchSequences []int64 `json:"uncertainDispatchSequences,omitempty"`
	Retire                     bool    `json:"retire,omitempty"`
}
type NativeDispatchProof struct {
	TaskSource          *NativeTaskSource `json:"taskSource,omitempty"`
	SourceBootID        string            `json:"sourceBootId"`
	OwnershipID         string            `json:"ownershipId"`
	OwnershipGeneration string            `json:"ownershipGeneration"`
	DispatchSequence    int64             `json:"dispatchSequence"`
	SourceCommandID     string            `json:"sourceCommandId"`
	SourceAdmissionID   string            `json:"sourceAdmissionId"`
	SourceRunnerID      string            `json:"sourceRunnerId"`
	SourceRunnerEpoch   time.Time         `json:"sourceRunnerEpoch"`
}

type NativeOwnershipRegisteredPayload struct {
	RequestID   string                 `json:"requestId"`
	Ownership   *NativeWorkerOwnership `json:"ownership,omitempty"`
	PublicError string                 `json:"publicError,omitempty"`
	Retryable   bool                   `json:"retryable,omitempty"`
}

const MsgNativeOwnershipPrepare = "host.native_ownership_prepare"

// Preparation is configuration only. It has no dispatch ordinal, admission or
// authorization to execute native input. Launch retains the original command ID
// and encrypted configuration/AAD; it must never enter the command submit path.
type NativeOwnershipPreparePayload struct {
	SourceCommandID   string                 `json:"sourceCommandId"`
	SourceCommandType string                 `json:"sourceCommandType"`
	InstanceID        string                 `json:"instanceId"`
	Runtime           string                 `json:"runtime"`
	Profile           string                 `json:"profile"`
	Launch            *LaunchAgentPayload    `json:"launch,omitempty"`
	Ownership         *NativeWorkerOwnership `json:"ownership,omitempty"`
}
