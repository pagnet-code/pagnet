package transport

import "github.com/pagnet-code/pagnet/e2ee"

const MsgNativeTaskInput = "host.native_task_input"
const MsgNativeTaskInputRead = "host.native_task_input_read"

// NativeTaskInputPayload asks for the exact encrypted input retained at original
// dispatch. Fresh transport admission never replaces this source identity.
type NativeTaskInputPayload struct {
	RequestID         string `json:"requestId"`
	SourceCommandID   string `json:"sourceCommandId"`
	SourceAdmissionID string `json:"sourceAdmissionId"`
	InstanceID        string `json:"instanceId"`
}
type NativeTaskInputReadPayload struct {
	RequestID         string                   `json:"requestId"`
	SourceCommandID   string                   `json:"sourceCommandId"`
	SourceAdmissionID string                   `json:"sourceAdmissionId"`
	InstanceID        string                   `json:"instanceId"`
	TaskSource        *NativeTaskSource        `json:"taskSource,omitempty"`
	Envelope          *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	PublicError       string                   `json:"publicError,omitempty"`
	Retryable         bool                     `json:"retryable,omitempty"`
}
