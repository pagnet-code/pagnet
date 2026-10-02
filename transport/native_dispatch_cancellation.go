package transport

const MsgNativeDispatchCancelProposals = "host.native_dispatch_cancel_proposals"
const MsgNativeDispatchCancelProposed = "host.native_dispatch_cancel_proposed"
const MsgNativeDispatchCancel = "host.native_dispatch_cancel"
const MsgNativeDispatchCancelled = "host.native_dispatch_cancelled"

// A proposal is metadata only and grants no right to skip an accepted effect.
type NativeDispatchCancellationProposal struct {
	InstanceID  string              `json:"instanceId"`
	CommandType string              `json:"commandType"`
	Reason      string              `json:"reason"`
	Proof       NativeDispatchProof `json:"proof"`
}
type NativeDispatchCancelProposalsPayload struct {
	RequestID             string `json:"requestId"`
	OwnershipID           string `json:"ownershipId"`
	OwnershipGeneration   string `json:"ownershipGeneration"`
	AfterDispatchSequence int64  `json:"afterDispatchSequence"`
	Limit                 int    `json:"limit"`
}
type NativeDispatchCancelProposedPayload struct {
	RequestID           string                               `json:"requestId"`
	OwnershipID         string                               `json:"ownershipId"`
	OwnershipGeneration string                               `json:"ownershipGeneration"`
	Proposals           []NativeDispatchCancellationProposal `json:"proposals"`
	NextAfter           *int64                               `json:"nextAfter,omitempty"`
	PublicError         string                               `json:"publicError,omitempty"`
	Retryable           bool                                 `json:"retryable,omitempty"`
}

// PreparationID identifies the worker's FULL-fsync cancel_prepare tombstone.
// It must be created while atomically proving no accepted/pending/uncertain
// mapping exists and fencing subsequent admission on the same original ordinal.
type NativeDispatchCancelPayload struct {
	RequestID           string `json:"requestId"`
	PreparationID       string `json:"preparationId"`
	InstanceID          string `json:"instanceId"`
	OwnershipID         string `json:"ownershipId"`
	OwnershipGeneration string `json:"ownershipGeneration"`
	DispatchSequence    int64  `json:"dispatchSequence"`
	SourceCommandID     string `json:"sourceCommandId"`
	SourceAdmissionID   string `json:"sourceAdmissionId"`
}
type NativeDispatchCancelledPayload struct {
	RequestID     string               `json:"requestId"`
	PreparationID string               `json:"preparationId"`
	InstanceID    string               `json:"instanceId"`
	Proof         *NativeDispatchProof `json:"proof,omitempty"`
	Disposition   string               `json:"disposition,omitempty"`
	PublicError   string               `json:"publicError,omitempty"`
	Retryable     bool                 `json:"retryable,omitempty"`
}
