// Package session is the vendor-agnostic persistent-session core of the
// pagnet daemon (runtime-lifecycle refactor, Phase 1).
//
// It models the three distinct concepts the binding addendum separates:
//
//   - RuntimeSession: the LOGICAL native conversation. It carries the
//     opaque vendor session/thread id (persisted by pagnet, never listed
//     from the vendor), its lifecycle state, its materialised flag, its
//     ownership, and its capability set. A session survives endpoint
//     hibernation where the runtime supports persistence.
//
//   - RuntimeEndpoint: the currently LIVE execution endpoint (the process
//     / service / gateway that services one or more sessions). It carries
//     ownership, lease state, the process handle (when pagnet owns it),
//     health, and the sessions it hosts. Topology is NOT forced 1:1 — an
//     endpoint MAY host several sessions.
//
//   - TerminalAttachment: a HUMAN view/input path onto the native UI.
//     Modelled here only as a capability (the core never drives a PTY);
//     the attachment itself is owned by the terminal plane (Phase 3).
//
// The package is deliberately dependency-light: it imports only the domain
// package. It knows nothing about any specific runtime, no vendor wire
// format, and no process supervisor. A vendor implementation satisfies the
// Driver interface (driver.go); the Manager (manager.go) is the stateful
// orchestrator the daemon drives.
//
// Design constraints absorbed from the runtime research (the generic core
// must express these or later vendor phases become impossible):
//
//   - materialised (Codex R3, Hermes R3): a session is resumable only
//     after its first real exchange. The Materialised flag is set by the
//     Manager after the first completed exchange, and a resume of a
//     non-materialised session is refused (ErrNotMaterialised) — never a
//     silent fresh session.
//
//   - pagnet owns serialisation (Codex R8, Hermes R2/R7): no vendor
//     serialises submits the way a queue would. The core therefore exposes
//     a per-session submit path with explicit busy semantics (BusyPolicy:
//     queue / steer / interrupt) that the adapter configures, not assumes.
//
//   - ownership/lease as first-class (Hermes R4): a live session may be
//     process-local behind a lease (foreign refusal, reclaim). The
//     Ownership + LeaseState model represents claimed / foreign /
//     reclaimed so the daemon can react without retry-storms.
//
//   - terminal attachment is rejoin-and-cooperate (Codex R7): no vendor
//     offers a read-only attach. Capabilities advertises
//     TerminalAttachmentFullAuthority so the UI is honest that an attached
//     human has FULL authority over the session.
//
//   - session id is pagnet-persisted, not vendor-listed (Codex R4): the
//     NativeID is an opaque string pagnet stores; the core never derives
//     liveness from a vendor directory listing. A resume that finds no
//     usable session maps to EventSessionLost, not a generic error.
package session

import (
	"encoding/json"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// Ownership is who owns a session or endpoint. A pagnet-owned endpoint may
// be terminated/reconciled by the supervisor; an external one may NEVER be
// (addendum invariant G).
type Ownership int

const (
	// OwnershipPagnet: pagnet launched and owns the endpoint.
	OwnershipPagnet Ownership = iota
	// OwnershipExternal: the endpoint was started outside pagnet (joined).
	OwnershipExternal
)

func (o Ownership) String() string {
	if o == OwnershipExternal {
		return "external"
	}
	return "pagnet"
}

// LeaseState models the process-local lease a live session may sit behind
// (Hermes R4: a live session is process-local, refused to a foreign owner
// with a 4090-style code, and reclaimed after a TTL). The endpoint
// ownership model must represent these so the daemon reacts (detach /
// resume-from-persistence) instead of retry-storming a foreign lease.
type LeaseState int

const (
	// LeaseNone: no lease concept applies (the endpoint is directly owned).
	LeaseNone LeaseState = iota
	// LeaseClaimed: pagnet holds the live lease for this session.
	LeaseClaimed
	// LeaseForeign: another owner holds the live lease; pagnet must not
	// drive it (refused, e.g. Hermes 4090).
	LeaseForeign
	// LeaseReclaimed: the lease was reclaimed (TTL / owner gone); the live
	// session is gone and only the persisted session may be resumed.
	LeaseReclaimed
)

func (l LeaseState) String() string {
	switch l {
	case LeaseClaimed:
		return "claimed"
	case LeaseForeign:
		return "foreign"
	case LeaseReclaimed:
		return "reclaimed"
	default:
		return "none"
	}
}

// SessionState is the lifecycle phase of a RuntimeSession (addendum §18:
// HIBERNATED → ACTIVATING → ACTIVE → IDLE → HIBERNATING → HIBERNATED, plus
// the terminal LOST state for an unrecoverable resume).
type SessionState int

const (
	// StateInactive: no live endpoint (never activated, or hibernated).
	// The session is resumable iff Materialised.
	StateInactive SessionState = iota
	// StateActivating: an endpoint is being started or resumed.
	StateActivating
	// StateIdle: a live endpoint services the session; no turn in flight.
	StateIdle
	// StateBusy: a live endpoint services the session; a turn is in flight.
	StateBusy
	// StateHibernating: the endpoint is being stopped (session preserved).
	StateHibernating
	// StateLost: a resume was attempted and no usable session existed.
	// The session is unrecoverable; a human must restart cold.
	StateLost
)

func (s SessionState) String() string {
	switch s {
	case StateInactive:
		return "inactive"
	case StateActivating:
		return "activating"
	case StateIdle:
		return "idle"
	case StateBusy:
		return "busy"
	case StateHibernating:
		return "hibernating"
	case StateLost:
		return "lost"
	default:
		return "unknown"
	}
}

// Live reports whether the session currently has a live endpoint (an
// endpoint that can service a submit without activation).
func (s SessionState) Live() bool {
	return s == StateIdle || s == StateBusy
}

// Capabilities is the probed capability set of a runtime integration
// (addendum §6). The server and daemon consume these; adapters contain the
// vendor knowledge that produces them. No `if runtime == "x"` anywhere.
type Capabilities struct {
	// PersistentEndpoint: the runtime offers a long-lived endpoint that
	// services many logical turns (vs process-per-turn).
	PersistentEndpoint bool
	// MultipleSessionsPerEndpoint: one endpoint MAY host several sessions.
	MultipleSessionsPerEndpoint bool
	// StructuredEvents: the runtime emits structured (not TUI-scraped)
	// semantic events.
	StructuredEvents bool
	// NativeSubmit: semantic input is delivered through a native control
	// channel (not PTY keystrokes).
	NativeSubmit bool
	// NativeQueueWhileBusy: the runtime itself queues input while busy.
	NativeQueueWhileBusy bool
	// NativeSteer: the runtime can influence the in-flight turn natively.
	NativeSteer bool
	// Interrupt: the in-flight turn can be interrupted natively.
	Interrupt bool
	// NativeInteractionObserve: native interactions (permission, question,
	// ...) are observable as structured events.
	NativeInteractionObserve bool
	// RemoteInteractionResolve: a pending interaction can be resolved
	// remotely (the answer is supplied back into the native session).
	RemoteInteractionResolve bool
	// NativeTUI: the runtime has a native interactive TUI.
	NativeTUI bool
	// SecondClientTerminalAttach: a second native client may attach to the
	// same live session (a human terminal alongside pagnet).
	SecondClientTerminalAttach bool
	// TerminalAttachmentFullAuthority: an attached terminal has FULL
	// authority over the session (rejoin-and-cooperate, never read-only —
	// no vendor offers a read-only attach; Codex R7).
	TerminalAttachmentFullAuthority bool
	// LiveExternalAdoption: an externally-started session can be adopted
	// live (pagnet join, LIVE_FULL / LIVE_LIMITED).
	LiveExternalAdoption bool
	// ResumeExternalSession: an externally-started session can be resumed
	// under pagnet (RESUME_REQUIRED mode).
	ResumeExternalSession bool
	// NativeSessionDiscovery: the runtime offers a documented session
	// listing (browse only — never the liveness source of truth).
	NativeSessionDiscovery bool
	// DynamicModelChange: the model can change on a live endpoint.
	DynamicModelChange bool
	// DynamicMCPInjection: MCP/tool config can be injected on a live
	// endpoint.
	DynamicMCPInjection bool
}

// RuntimeSession is the logical native conversation (addendum §2). It is
// the unit that survives hibernation and the unit the daemon reasons about.
type RuntimeSession struct {
	// InstanceID is the owning AgentInstance.
	InstanceID string
	// Runtime is the canonical runtime name.
	Runtime domain.RuntimeName
	// NativeID is the opaque vendor session/thread id. pagnet PERSISTS it
	// (it is never derived from a vendor listing). Empty until the runtime
	// mints one on activation.
	NativeID string
	// Workspace is the absolute path the session runs in.
	Workspace string
	// Endpoint is the current live endpoint (nil when inactive/hibernated).
	Endpoint *RuntimeEndpoint
	// State is the lifecycle phase.
	State SessionState
	// Materialised is true once the session has had its first real
	// exchange. Only a materialised session is resumable (Codex R3,
	// Hermes R3). Set by the Manager after the first completed exchange.
	Materialised bool
	// Ownership: pagnet | external.
	Ownership Ownership
	// Capabilities is the probed capability set for this integration.
	Capabilities Capabilities
	// LastActivity is the last observed exchange (for idle policy).
	LastActivity time.Time
	// ConfigFingerprint is the standing-config fingerprint (model / MCP /
	// identity), preserved from the existing staleness concept.
	ConfigFingerprint string
}

// Resumable reports whether the session may be resumed (it must be
// materialised — a started-but-never-exchanged session has nothing to
// resume, and offering it would be a lie).
func (s *RuntimeSession) Resumable() bool {
	return s.Materialised && s.NativeID != ""
}

// RuntimeEndpoint is the currently live execution endpoint (addendum §2):
// the process / service / gateway that services one or more sessions.
type RuntimeEndpoint struct {
	// ID is the endpoint's identity (pagnet-minted).
	ID string
	// Runtime is the canonical runtime name.
	Runtime domain.RuntimeName
	// Ownership: pagnet | external.
	Ownership Ownership
	// Lease is the process-local lease state (Hermes R4).
	Lease LeaseState
	// PID / PGID are set when pagnet owns the endpoint process.
	PID  int
	PGID int
	// Healthy reports the endpoint's liveness (probed, not assumed).
	Healthy bool
	// Transport is the native transport description (e.g. "stdio",
	// "unix://..."). Never a secret; loopback-only by policy.
	Transport string
	// Sessions lists the session ids this endpoint currently hosts.
	Sessions []string
	// StartedAt is when the endpoint process started.
	StartedAt time.Time
}

// BusyPolicy is how a submit is handled when the session is already busy
// (a turn is in flight). These are POLICIES the adapter configures, not
// assumptions the core makes (Codex R8: no vendor serialises for you).
type BusyPolicy int

const (
	// BusyQueue: queue the input; it is delivered after the in-flight turn.
	BusyQueue BusyPolicy = iota
	// BusySteer: influence the in-flight turn (requires NativeSteer).
	BusySteer
	// BusyInterrupt: interrupt the in-flight turn, then deliver (requires
	// Interrupt).
	BusyInterrupt
)

// SubmitKind distinguishes the two things the submit path carries: a
// logical prompt (a turn) and an interaction resolution (an answer to a
// pending native interaction). Both travel the SAME submit path — the
// answer is delivered externally, not by the blocked turn itself.
type SubmitKind int

const (
	// SubmitPrompt: a logical input that runs a turn.
	SubmitPrompt SubmitKind = iota
	// SubmitInteraction: an answer to a pending native interaction.
	SubmitInteraction
)

// SubmitRequest is one logical input delivered into a session's live
// endpoint through the generic submit path.
type SubmitRequest struct {
	// TurnID is the pagnet-assigned correlation/idempotency id for the
	// submit (never the process identity).
	TurnID string
	// Kind selects prompt vs interaction-resolution.
	Kind SubmitKind
	// --- prompt fields (Kind == SubmitPrompt) ---
	// Input is the rendered logical input (the network work, already
	// durable).
	Input string
	// InputKind: task | ask | notice | status | wake | user_input.
	InputKind string
	// BusyPolicy applies when the session is already busy.
	BusyPolicy BusyPolicy
	// --- interaction-resolution fields (Kind == SubmitInteraction) ---
	// InteractionID is the native interaction id being answered.
	InteractionID string
	// Decision is the resolution outcome (resolved | declined | cancelled).
	Decision string
	// Answer is the (opaque) answer.
	Answer string
}

// SessionEvent is a normalized, runtime-agnostic observation of a session.
// The vocabulary mirrors the existing host-protocol event names (so the
// daemon translation is 1:1) and adds the busy/idle and identity-changed
// events the persistent model needs (addendum §31).
type SessionEvent struct {
	// Type is one of the Event* constants below.
	Type string
	// SessionID is the native session the event belongs to.
	SessionID string
	// Output is a transcript chunk (turn.output).
	Output string
	// Model, when the runtime reports it.
	Model string
	// Token usage, when the runtime reports it.
	InputTokens  *int
	OutputTokens *int
	CachedTokens *int
	// Failure fields (turn.failed).
	FailureKind string
	Error       string
	// RetryAt is ONLY set from a runtime-provided value (never guessed).
	RetryAt *string
	// Interaction is set on interaction.started / interaction.resolved.
	Interaction *InteractionEvent
}

// SessionEvent types (generic; NOT runtime-specific). The string values
// match the existing host-protocol vocabulary so the daemon can forward
// them without reshaping.
const (
	EventSessionStarted         = "runtime.session.started"
	EventSessionResumed         = "runtime.session.resumed"
	EventSessionLost            = "runtime.session.lost"
	EventSessionIdentityChanged = "runtime.session.identity_changed"
	EventBusy                   = "runtime.busy"
	EventIdle                   = "runtime.idle"
	EventTurnStarted            = "runtime.turn.started"
	EventTurnOutput             = "runtime.turn.output"
	EventTurnCompleted          = "runtime.turn.completed"
	EventTurnFailed             = "runtime.turn.failed"
	EventInteractionStarted     = "runtime.interaction.started"
	EventInteractionResolved    = "runtime.interaction.resolved"
)

// isTerminalEvent reports whether the event ends a turn's event stream
// (the driver emits nothing more for that turn after it).
func isTerminalEvent(ty string) bool {
	switch ty {
	case EventTurnCompleted, EventTurnFailed, EventSessionLost:
		return true
	}
	return false
}

// InteractionEvent is a normalized observation of a native runtime
// interaction (question, permission, plan approval, ...). The vendor
// payload stays opaque (addendum §8.2).
type InteractionEvent struct {
	// NativeInteractionID is the runtime's own id for the interaction.
	NativeInteractionID string
	// Kind: question | permission | plan_approval | authentication |
	// confirmation | other.
	Kind string
	// Summary is a public-safe one-liner.
	Summary string
	// NativePayload is the opaque, versioned vendor payload.
	NativePayload json.RawMessage
	// Resolved marks a resolution event (false = started).
	Resolved bool
	// Decision is the resolution outcome (set when Resolved).
	Decision string
	// Answer is the (opaque) answer, when reported.
	Answer string
}

// TurnResult is the settled outcome of one Submit (a prompt). The Manager
// fills it as the event stream is consumed.
type TurnResult struct {
	// Completed is true when the turn ended with turn.completed.
	Completed bool
	// Failed is true when the turn ended with turn.failed.
	Failed bool
	// SessionLost is true when the (re)activation lost the session.
	SessionLost bool
	// FailureKind / Error / RetryAt are set on failure.
	FailureKind string
	Error       string
	RetryAt     *string
	// SessionID is the native session the turn ran in.
	SessionID string
	// Model, when reported.
	Model string
	// Token usage, when reported.
	InputTokens  *int
	OutputTokens *int
	CachedTokens *int
	// PendingInteraction is true when the turn ended (or is parked) with a
	// started-but-unresolved interaction.
	PendingInteraction bool
}
