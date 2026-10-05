package federation

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// ControlPayload is a closed action-specific union. Status/cancel carry {}.
// Pull requires Cursor and 1..4 credit. ACK requires Cursor and NextCursor.
type ControlPayload struct {
	Cursor     *ConsumerCursor `json:"cursor,omitempty"`
	NextCursor *ConsumerCursor `json:"nextCursor,omitempty"`
	Credit     uint8           `json:"credit,omitempty"`
}
type ControlRequest struct {
	Proof   fabric.SignedControlProof `json:"proof"`
	Payload json.RawMessage           `json:"payload"`
}

// ControlAuthenticator supplies independently CURRENT opaque caller evidence
// bound to Frame.SigningBytes and destination audience. The historical signature
// is never current-session authentication. It must not hold registry SQL while
// calling accept, and must honor the finite context. No permissive default exists.
type ControlAuthenticator interface {
	AuthenticateControl(context.Context, Config, ControlRequest, func(context.Context, fabric.ExecutionContext) error) error
}
type ControlConfig struct {
	Ledger        *AdmissionLedger
	Authenticator ControlAuthenticator
	MaxControls   uint64
	Cursors       CursorVerifier
	Results       ControlResultVerifier
}

// ControlResult records genuine source-specific actuation evidence, not output
// itself. Original frames remain with the original adapter/native source until
// consumer ACK. StopAcknowledged is distinct from any completion frame.
type ControlResult struct {
	State            string          `json:"state"`
	ResponseDigest   [32]byte        `json:"responseDigest"`
	FrameCount       uint8           `json:"frameCount,omitempty"`
	Cursor           *ConsumerCursor `json:"cursor,omitempty"`
	StopAcknowledged bool            `json:"stopAcknowledged,omitempty"`
}

// Result verification is bounded local retained-source/current-state evidence
// only. Native IPC, providers and nested registry calls are forbidden under TX.
type ControlResultVerifier interface {
	VerifyControlResultTx(context.Context, *registry.AuthorityTx, AdmissionFacts, ControlRequest, ControlResult) error
}
type ControlPermit struct {
	ledger     *ControlLedger
	key        string
	digest     [32]byte
	request    ControlRequest
	invocation Admission
}

func (ControlPermit) MarshalJSON() ([]byte, error) { return nil, authError() }
func (*ControlPermit) UnmarshalJSON([]byte) error  { return authError() }

// Invocation is an opaque retained admission, not a bearer credential. Every
// subsequent source lookup still requires current caller/pair authorization.
func (p ControlPermit) Invocation() Admission { return p.invocation }

type ControlState struct {
	Result *ControlResult
	Status AdmissionStatus
}
