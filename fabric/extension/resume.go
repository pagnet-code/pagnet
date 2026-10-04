package extension

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// ResumePermit is an opaque in-process fresh-claim capability, never a wire
// assertion. Only trusted continuation composition constructs it AFTER checking
// an authenticated single-claim store receipt with Fresh=true. Copying a JSON
// snapshot or sending a 'fresh' boolean cannot authorize execution.
type ResumePermit struct {
	mu             sync.Mutex
	used           bool
	principal      fabric.Principal
	audience       string
	originalDigest [32]byte
	stateDigest    [32]byte
}

func (*ResumePermit) MarshalJSON() ([]byte, error) {
	return nil, fabric.NewError(fabric.CodeUnauthenticated, "Resume permits cannot be serialized")
}
func (*ResumePermit) UnmarshalJSON([]byte) error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Resume permits cannot be deserialized")
}
func NewVerifiedResumePermit(caller fabric.ExecutionContext, original []byte, state PipelineState) (*ResumePermit, error) {
	envelope, err := caller.DecodeVerifiedEnvelope(original, caller.Audience())
	if err != nil {
		return nil, err
	}
	// Snapshot authenticity comes from the store; these invariants additionally
	// ensure even a bad composition cannot replace immutable original fields.
	a, b := envelope, state.Envelope
	a.Payload = nil
	b.Payload = nil
	a.Metadata = nil
	b.Metadata = nil
	a.Target = nil
	b.Target = nil
	a.ExpectedRevision = ""
	b.ExpectedRevision = ""
	if !reflect.DeepEqual(a, b) {
		return nil, fabric.NewError(fabric.CodeInvalidMutation, "Continuation changed immutable fields")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return &ResumePermit{principal: caller.PrincipalView(), audience: caller.Audience(), originalDigest: sha256.Sum256(original), stateDigest: sha256.Sum256(raw)}, nil
}
func (p *ResumePermit) consume(caller fabric.ExecutionContext, original []byte, state PipelineState) error {
	if p == nil {
		return fabric.NewError(fabric.CodeUnauthenticated, "Fresh continuation claim is required")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used || p.principal != caller.PrincipalView() || p.audience != caller.Audience() || p.originalDigest != sha256.Sum256(original) || p.stateDigest != sha256.Sum256(raw) {
		return fabric.NewError(fabric.CodeStaleContinuation, "Continuation claim is stale or mismatched")
	}
	p.used = true
	return nil
}
