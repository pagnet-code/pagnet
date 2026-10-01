package transport

import (
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

const OwnerContextProtocol = "owner-context-v1"
const MsgPrepareProtectedContext = "host.prepare_protected_context"

type PrepareProtectedContextPayload struct {
	CommandID       string                `json:"commandId"`
	InstanceID      string                `json:"instanceId"`
	Context         e2ee.ProtectedContext `json:"context"`
	HostX25519      string                `json:"hostX25519"`
	HostEd25519     string                `json:"hostEd25519"`
	ExpectedEpochID string                `json:"expectedEpochId,omitempty"`
	Rotate          bool                  `json:"rotate,omitempty"`
}
type ProtectedContextReadyPayload struct {
	CommandID   string                `json:"commandId"`
	InstanceID  string                `json:"instanceId"`
	Context     e2ee.ProtectedContext `json:"context"`
	EpochID     string                `json:"epochId"`
	HostX25519  string                `json:"hostX25519"`
	HostEd25519 string                `json:"hostEd25519"`
	Signature   string                `json:"signature"`
}
type OwnerInteractionDetail struct {
	Format        string          `json:"format"`
	Summary       string          `json:"summary"`
	NativePayload any             `json:"nativePayload"`
	Inspection    OwnerInspection `json:"inspection"`
}
type OwnerInspection struct {
	Secret              string `json:"secret"`
	InstanceID          string `json:"instanceId"`
	SessionID           string `json:"sessionId"`
	NativeInteractionID string `json:"nativeInteractionId"`
}
type ProtectedContextSessionBinding struct {
	Context    e2ee.ProtectedContext `json:"context"`
	SessionID  string                `json:"sessionId"`
	UserID     string                `json:"userId"`
	BrowserPub string                `json:"browserPub"`
	ExpiresAt  time.Time             `json:"expiresAt"`
}

// SignatureBytes contains public registration metadata only. The signature
// pins the context epoch to the exact attested host identity and preparation.
func (p ProtectedContextReadyPayload) SignatureBytes() []byte {
	p.Signature = ""
	b, _ := json.Marshal(p)
	return b
}
