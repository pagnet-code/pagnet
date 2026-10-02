package transport

const NativeOwnedDeletionProtocol = "native-owned-deletion-v1"
const MsgNativeInstanceForgotten = "host.native_instance_forgotten"

// Emitted only after the typed forget outcome and deletion-job transition
// COMMIT. The original immutable ownership metadata scopes private GC replay.
type NativeInstanceForgottenPayload struct {
	CommandID           string `json:"commandId"`
	DeleteRequestID     string `json:"deleteRequestId"`
	InstanceID          string `json:"instanceId"`
	OwnershipID         string `json:"ownershipId"`
	OwnershipGeneration string `json:"ownershipGeneration"`
	Disposition         string `json:"disposition"`
}
