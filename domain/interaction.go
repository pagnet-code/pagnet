package domain

import (
	"encoding/json"
	"time"
)

// RuntimeInteractionKind classifies a native runtime interaction — a
// question, permission prompt, plan approval, ... that the runtime's own
// UI presents to a human. Kinds are generic (never runtime-specific): the
// vendor schema stays in the opaque NativePayload.
type RuntimeInteractionKind string

const (
	InteractionKindQuestion       RuntimeInteractionKind = "question"
	InteractionKindPermission     RuntimeInteractionKind = "permission"
	InteractionKindPlanApproval   RuntimeInteractionKind = "plan_approval"
	InteractionKindAuthentication RuntimeInteractionKind = "authentication"
	InteractionKindConfirmation   RuntimeInteractionKind = "confirmation"
	InteractionKindOther          RuntimeInteractionKind = "other"
)

// Valid reports whether k is a known interaction kind.
func (k RuntimeInteractionKind) Valid() bool {
	switch k {
	case InteractionKindQuestion, InteractionKindPermission,
		InteractionKindPlanApproval, InteractionKindAuthentication,
		InteractionKindConfirmation, InteractionKindOther:
		return true
	}
	return false
}

// RuntimeInteractionState is the guarded state machine of an observed
// interaction. Only pending -> resolved|declined|cancelled is a legal
// resolution transition (and pending -> expired via the TTL sweep); a
// re-resolve of an already-decided interaction is an idempotent no-op that
// returns the existing state.
type RuntimeInteractionState string

const (
	InteractionStatePending   RuntimeInteractionState = "pending"
	InteractionStateResolved  RuntimeInteractionState = "resolved"
	InteractionStateDeclined  RuntimeInteractionState = "declined"
	InteractionStateCancelled RuntimeInteractionState = "cancelled"
	InteractionStateExpired   RuntimeInteractionState = "expired"
)

// Valid reports whether s is a known interaction state.
func (s RuntimeInteractionState) Valid() bool {
	switch s {
	case InteractionStatePending, InteractionStateResolved,
		InteractionStateDeclined, InteractionStateCancelled, InteractionStateExpired:
		return true
	}
	return false
}

// Terminal reports whether no further state transition is possible.
func (s RuntimeInteractionState) Terminal() bool {
	return s != InteractionStatePending
}

// RuntimeInteraction is one observed native runtime interaction. Pagnet
// records it and orchestrates around it; it does NOT render it — the
// vendor's native UI remains the place a human answers (plan §8.1).
type RuntimeInteraction struct {
	ID              ID
	TenantID        ID
	NetworkID       *ID
	AgentInstanceID ID
	// RuntimeSessionID is the runtime-native session the interaction
	// belongs to (the resumable identity), when the adapter reported one.
	RuntimeSessionID *string
	Runtime          RuntimeName
	// NativeInteractionID is the runtime's own id for the interaction,
	// when it has one (nil for runtimes that do not name them).
	NativeInteractionID *string
	Kind                RuntimeInteractionKind
	State               RuntimeInteractionState
	// Summary is a public-safe one-liner (notifications/UI). It is NEVER
	// protected content — the protected material stays in the native TUI.
	Summary *string
	// NativePayload is the opaque, versioned vendor payload. Stored as-is;
	// the server never parses it for correctness.
	NativePayload json.RawMessage
	CorrelationID *string
	// Answer is the remote answer, stored opaque (only set when the
	// interaction was resolved through the remote-resolve API).
	Answer *string
	CreatedAt  time.Time
	ResolvedAt *time.Time
}

// RuntimeCapability is the persisted compatibility-matrix row for one
// (runtime, version): the OBSERVED capability flags, reported by the
// daemon from the adapter (plan §8.6 — tested behavior, not assumptions).
// The per-kind maps are bools keyed by interaction kind; an absent kind is
// "not supported".
type RuntimeCapability struct {
	Runtime             RuntimeName
	Version             string
	ObserveInteractions bool
	NativeInteractiveUI bool
	// DeferredInteraction[kind] = the runtime can let a turn exit safely
	// while a pending interaction of that kind is stored (headless defer).
	DeferredInteraction map[string]bool
	// RemoteResolve[kind] = a pending interaction of that kind can be
	// resolved remotely (the runtime can supply the answer back into the
	// native session). When false, the answer must be given in the native
	// TUI and the remote-resolve API rejects with 409.
	RemoteResolve map[string]bool
	UpdatedAt     time.Time
}

// CanDefer reports whether a pending interaction of kind may be deferred
// (turn exits, instance hibernates).
func (c *RuntimeCapability) CanDefer(kind string) bool {
	return c != nil && c.DeferredInteraction[kind]
}

// CanRemoteResolve reports whether a pending interaction of kind may be
// resolved remotely.
func (c *RuntimeCapability) CanRemoteResolve(kind string) bool {
	return c != nil && c.RemoteResolve[kind]
}

// Event types for native runtime interactions (generic, runtime-neutral —
// the same rule as the other runtime.* events: vendor detail stays in the
// metadata, the name never becomes runtime-specific).
const (
	// EventRuntimeInteractionPending: an interaction was observed and is
	// waiting for a human. This is the seam the notifications phase
	// (Phase 6) fans out from — emitted through the same path as every
	// other orchestration event.
	EventRuntimeInteractionPending = "runtime.interaction.pending"
	// EventRuntimeInteractionResolved: a pending interaction was resolved
	// (native TUI or remote).
	EventRuntimeInteractionResolved = "runtime.interaction.resolved"
	// EventRuntimeInteractionExpired: a pending interaction outlived its
	// TTL and was expired by the sweep.
	EventRuntimeInteractionExpired = "runtime.interaction.expired"
)
