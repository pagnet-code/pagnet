package extension

import (
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type Action string

const (
	Continue Action = "CONTINUE"
	Modify   Action = "MODIFY"
	Reject   Action = "REJECT"
	Respond  Action = "RESPOND"
	Redirect Action = "REDIRECT"
	Defer    Action = "DEFER"
)

// InterceptRequest belongs to source/destination execution only. A relay must
// use its separate metadata-only transport view, never serialize this type.
// The node supplies verified identity and provenance; extensions see no adapter
// credentials, private runtime paths, signing keys or resume capabilities.
type InterceptRequest struct {
	ProtocolVersion fabric.ProtocolVersion  `json:"protocolVersion"`
	InterceptorID   string                  `json:"interceptorId"`
	Operation       fabric.Operation        `json:"operation"`
	Stage           string                  `json:"stage"`
	Phase           Phase                   `json:"phase"`
	Envelope        fabric.Envelope         `json:"envelope"`
	Content         json.RawMessage         `json:"content,omitempty"`
	ContentEncoding string                  `json:"contentEncoding,omitempty"`
	Response        json.RawMessage         `json:"response,omitempty"`
	Failure         *fabric.Error           `json:"failure,omitempty"`
	Frame           *fabric.InvocationFrame `json:"frame,omitempty"`
}
type RedirectTarget struct {
	Ref              fabric.EndpointRef `json:"ref"`
	ExpectedRevision fabric.Revision    `json:"expectedRevision,omitempty"`
}
type Deferral struct {
	ExpiresAt time.Time `json:"expiresAt"`
	// Principal references are explicit authenticated resume constraints. Their
	// organizational meaning is understood by the extension, not by Pagnet.
	ResumePrincipals []string `json:"resumePrincipals"`
	Durable          bool     `json:"durable"`
}
type Decision struct {
	Action   Action          `json:"action"`
	Patch    json.RawMessage `json:"patch,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	Failure  *fabric.Error   `json:"failure,omitempty"`
	Redirect *RedirectTarget `json:"redirect,omitempty"`
	Deferral *Deferral       `json:"deferral,omitempty"`
}

// ValidateDecision rejects contradictory controls rather than interpreting one
// field preferentially. Suspension/redirect are impossible after output starts;
// read operations cannot manufacture work or redirect into an invocation.
func ValidateDecision(req InterceptRequest, d Decision, outputStarted bool, now time.Time) error {
	invalid := func() error { return fabric.NewError(fabric.CodeProtocolError, "Invalid interceptor decision") }
	switch d.Action {
	case Continue:
		if len(d.Patch) != 0 || len(d.Response) != 0 || d.Failure != nil || d.Redirect != nil || d.Deferral != nil {
			return invalid()
		}
	case Modify:
		if len(d.Patch) == 0 || len(d.Response) != 0 || d.Failure != nil || d.Redirect != nil || d.Deferral != nil || (req.Phase != PhaseRequest && req.Phase != PhaseResponse && req.Phase != PhaseChunk) {
			return invalid()
		}
		if req.Phase == PhaseChunk && req.Frame == nil || req.Phase == PhaseResponse && req.Frame == nil && len(req.Response) == 0 {
			return invalid()
		}
		if req.Frame != nil && (req.Frame.Kind != fabric.FrameChunk && req.Frame.Kind != fabric.FrameProgress) {
			return invalid()
		}
		if req.Frame != nil && req.ContentEncoding == "unavailable" {
			return invalid()
		}
	case Reject:
		if d.Failure == nil || d.Failure.Code == "" || len(d.Patch) != 0 || len(d.Response) != 0 || d.Redirect != nil || d.Deferral != nil {
			return invalid()
		}
		if len(d.Failure.Code) > 256 || len(d.Failure.Message) > 1024 {
			return invalid()
		}
		switch d.Failure.Effect {
		case fabric.EffectUnknown, fabric.EffectNotStarted, fabric.EffectCompleted:
		default:
			return invalid()
		}
	case Respond:
		if len(d.Response) == 0 || len(d.Patch) != 0 || d.Failure != nil || d.Redirect != nil || d.Deferral != nil || req.Phase != PhaseRequest || outputStarted {
			return invalid()
		}
		var response any
		if fabric.DecodeJSON(d.Response, &response) != nil {
			return invalid()
		}
	case Redirect:
		if req.Operation != fabric.OperationInvoke || req.Phase != PhaseRequest || outputStarted || d.Redirect == nil || len(d.Patch) != 0 || len(d.Response) != 0 || d.Failure != nil || d.Deferral != nil {
			return invalid()
		}
		if _, err := fabric.ParseEndpointRef(d.Redirect.Ref.String()); err != nil || len(d.Redirect.ExpectedRevision) > 256 {
			return invalid()
		}
	case Defer:
		if req.Operation != fabric.OperationInvoke || req.Phase != PhaseRequest || outputStarted || d.Deferral == nil || len(d.Patch) != 0 || len(d.Response) != 0 || d.Failure != nil || d.Redirect != nil {
			return invalid()
		}
		f := d.Deferral
		if !f.ExpiresAt.After(now) || f.ExpiresAt.Sub(now) > 30*24*time.Hour || len(f.ResumePrincipals) < 1 || len(f.ResumePrincipals) > 64 {
			return invalid()
		}
		seen := map[string]bool{}
		for _, principal := range f.ResumePrincipals {
			if principal == "" || len(principal) > 4096 || seen[principal] {
				return invalid()
			}
			seen[principal] = true
		}
	default:
		return invalid()
	}
	return nil
}
