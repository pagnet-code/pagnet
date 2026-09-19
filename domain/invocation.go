package domain

import (
	"encoding/json"
	"time"
)

// InvocationState is the lifecycle state of a capability invocation.
type InvocationState string

const (
	InvocationPending    InvocationState = "pending"
	InvocationDispatched InvocationState = "dispatched"
	InvocationRunning    InvocationState = "running"
	InvocationCompleted  InvocationState = "completed"
	InvocationFailed     InvocationState = "failed"
	InvocationCancelled  InvocationState = "cancelled"
)

// Valid reports whether s is a known invocation state.
func (s InvocationState) Valid() bool {
	switch s {
	case InvocationPending, InvocationDispatched, InvocationRunning,
		InvocationCompleted, InvocationFailed, InvocationCancelled:
		return true
	}
	return false
}

// Terminal reports whether no further state transition is possible.
func (s InvocationState) Terminal() bool {
	return s == InvocationCompleted || s == InvocationFailed || s == InvocationCancelled
}

// CapabilityInvocation is one call of a principal's capability by another
// principal. The input/output/error content is protected (encrypted
// envelope, AAD-bound) — the control plane routes and persists the record
// but never sees the content.
//
// Idempotency is keyed by (network, caller, IdempotencyKey): the same key
// returns the existing invocation, never a duplicate.
type CapabilityInvocation struct {
	ID                ID
	NetworkID         ID
	CallerPrincipalID ID
	CallerEndpointID  *ID
	TargetPrincipalID ID
	// TargetEndpointID is the endpoint the invocation was dispatched to
	// (set at dispatch; nil while pending).
	TargetEndpointID  *ID
	CapabilityID      string
	CapabilityVersion int
	State             InvocationState
	IdempotencyKey    string
	CorrelationID     *ID
	CausationID       *ID
	// ProtectedInput is the encrypted invocation input (object type
	// invocation_input).
	ProtectedInput json.RawMessage
	// ProtectedOutput is the encrypted invocation output (object type
	// invocation_output).
	ProtectedOutput json.RawMessage
	// ProtectedError is the encrypted error detail for a failed invocation
	// (object type invocation_error).
	ProtectedError json.RawMessage
	// PublicResultCode is the public-safe outcome code (stable code only —
	// never protected content).
	PublicResultCode string
	UsageMetadata    map[string]any
	CreatedAt        time.Time
	DispatchedAt     *time.Time
	StartedAt        *time.Time
	CompletedAt      *time.Time
}
