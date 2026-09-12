// Package runtime is the boundary between pagnet's domain and a specific
// coding-agent runtime (claude-code, qwen-code, opencode, fake).
//
// Per the runtime-integration addendum: the adapter is the ONLY place that
// knows how to launch a process, feed it a turn, read its events, resume a
// session, or hibernate. It normalizes everything into generic,
// runtime-agnostic TurnEvents. Domain code never sees runtime-specific
// shapes; runtime-specific data rides in a Metadata map. No runtime plugins
// are required or used in the MVP.
package runtime

import (
	"context"
	"encoding/json"
	"os/exec"

	"pagnet/internal/domain"
)

// TurnSpec describes one turn to run. The adapter decides how to translate it
// into a process invocation (it is never a shell command).
type TurnSpec struct {
	// TurnID is assigned by the daemon (idempotency/correlation for the turn).
	TurnID       string
	InstanceID   string
	DefinitionID string
	// Workspace is the absolute path the process runs in (must be under an
	// allowed root; validated by the daemon before this is called).
	Workspace string
	// SessionDir is where the runtime persists its resumable session.
	SessionDir string
	// Resume is true when a prior session should be resumed (cold start when
	// false). The adapter checks whether a session actually exists.
	Resume bool
	// Input is the rendered turn prompt (the network work, already durable).
	Input string
	// InputKind: task | ask | notice | status | wake | user_input
	InputKind string
	// WakeReason is set when this turn exists to satisfy a wake.
	WakeReason string
	// Model is the resolved model for this turn ("" = the adapter's own
	// default: its field, then its env). When set it takes precedence over
	// both — the daemon resolves launch request > definition default.
	Model string
	// AgentMDPath is the daemon-managed standing-instruction file
	// (AGENT.md-style) the runtime loads as extra system context ("" =
	// none). Claude maps it to --append-system-prompt-file; runtimes
	// without such a flag get the daemon append its text to a fresh
	// session's first turn instead (they never read this path).
	AgentMDPath string
	// Metadata carries runtime-agnostic extras (e.g. profile, transcript).
	Metadata map[string]any
	// Env is extra KEY=VALUE pairs for the spawned process (per-instance
	// pagnet injection: MCP bridge config, coordination contract,
	// identity). Appended after the adapter's own environment.
	Env []string
}

// TurnEvent is a normalized, runtime-agnostic observation of a turn.
type TurnEvent struct {
	Type string
	// SessionID is populated on SessionStarted/SessionResumed and is the
	// resumable identity for later turns.
	SessionID string
	// Output is a transcript chunk (may be empty).
	Output string
	// Model, when the runtime reports it.
	Model string
	// Tokens, when the runtime reports them.
	InputTokens  *int
	OutputTokens *int
	CachedTokens *int
	// Failure fields, set on TurnFailed.
	FailureKind domain.RuntimeFailureKind
	Error       string
	// RetryAt is ONLY set from a provider-provided value (never guessed).
	RetryAt *string
	// Interaction is set on EventInteractionStarted /
	// EventInteractionResolved (nil for all other event types).
	Interaction *InteractionEvent
}

// TurnEvent types (generic; NOT runtime-specific).
const (
	EventSessionStarted = "runtime.session.started"
	EventSessionResumed = "runtime.session.resumed"
	EventTurnStarted    = "runtime.turn.started"
	EventTurnOutput     = "runtime.turn.output"
	EventTurnCompleted  = "runtime.turn.completed"
	EventTurnFailed     = "runtime.turn.failed"
	// EventSessionLost: a resume was requested but no usable session existed.
	EventSessionLost = "runtime.session.lost"
	// EventInteractionStarted: the runtime began a native interaction
	// (question, permission prompt, plan approval, ...). Carries
	// Interaction. Pagnet observes it; it does NOT render it (plan §8.1).
	EventInteractionStarted = "runtime.interaction.started"
	// EventInteractionResolved: a pending native interaction was resolved
	// (in the native TUI or remotely). Carries Interaction (Resolved=true).
	EventInteractionResolved = "runtime.interaction.resolved"
)

// InteractionEvent is a normalized observation of a native runtime
// interaction. The adapter emits it on the turn's events channel as
// EventInteractionStarted / EventInteractionResolved; the daemon translates
// it into the host protocol. The vendor payload stays opaque — the server
// never parses it for correctness (plan §8.2).
type InteractionEvent struct {
	// Runtime is the canonical runtime name (the daemon fills it from the
	// instance when the adapter leaves it empty).
	Runtime domain.RuntimeName
	// SessionID is the runtime-native session the interaction belongs to.
	SessionID string
	// NativeInteractionID is the runtime's own id for the interaction
	// ("" when the runtime does not name them).
	NativeInteractionID string
	// Kind: question | permission | plan_approval | authentication |
	// confirmation | other.
	Kind string
	// Summary is a public-safe one-liner (notifications/UI). It is NEVER
	// protected content — the protected material stays in the native TUI.
	Summary string
	// NativePayload is the opaque, versioned vendor payload (stored as-is).
	NativePayload json.RawMessage
	// CorrelationID links the started/resolved pair and any pagnet-side
	// correlation the runtime supplied.
	CorrelationID string
	// Resolved marks a resolution event (false = started).
	Resolved bool
	// Decision is the resolution outcome (resolved|declined|cancelled),
	// set when Resolved.
	Decision string
	// Answer is the (opaque) answer, when the runtime reported one.
	Answer string
}

// Adapter is the contract a runtime implements.
type Adapter interface {
	// Name is the canonical runtime name.
	Name() domain.RuntimeName
	// StartTurn runs one turn, streaming normalized events into events until
	// the turn ends (completed/failed) or ctx is canceled. It closes the
	// events channel before returning (so consumers may range over it) and
	// returns after the process exits. The adapter is responsible for
	// persisting the session so a later Resume can succeed.
	StartTurn(ctx context.Context, spec TurnSpec, events chan TurnEvent) error
	// Stop terminates any running process for the instance (no-op if none).
	Stop(instanceID string) error
	// Available reports whether this runtime is installed and usable.
	Available() bool
	// BinaryPath reports the resolved path of the runtime's CLI binary
	// (same resolution as Available). The canonical runtime name is NOT
	// the CLI binary name (qwen-code → `qwen`, claude-code → `claude`), so
	// callers must never derive the binary from Name().
	BinaryPath() (string, bool)
	// PID is the OS pid of the instance's currently running turn process
	// (spec §59), or nil when no turn is running (process-per-turn: the
	// process only exists for the duration of a turn).
	PID(instanceID string) *int
	// InteractiveCmd builds — WITHOUT starting — the runtime's interactive
	// terminal command for an instance (addendum §7/§8: the ACTUAL runtime
	// UI under a PTY, not a pagnet reimplementation). spec.Resume selects
	// the runtime's session-resume flag when a session is stored; Dir and
	// Env are set the same way as for a turn. The caller owns the returned
	// command (it is started under a PTY by the daemon).
	InteractiveCmd(spec TurnSpec) (*exec.Cmd, error)
}

// InteractionObserver is the native-interaction capability model (plan
// §8.3). It is a SUB-interface: an Adapter that can observe the runtime's
// native interactions (questions, permission prompts, plan approvals, ...)
// implements it, and the daemon/control plane query it to decide how to
// handle a pending interaction (defer vs wait, remote-resolve vs
// native-TUI-only). Adapters without a documented observation hook do not
// implement it — the conservative default is "cannot observe" (the daemon
// treats a non-implementer as ObserveInteractions()==false).
//
// The event normalization surface is the TurnEvent channel: an observing
// adapter emits EventInteractionStarted / EventInteractionResolved (carrying
// an InteractionEvent) from StartTurn, exactly like the other turn events.
type InteractionObserver interface {
	// ObserveInteractions reports whether the adapter can observe native
	// interactions at all (a documented hook / structured output exists
	// today). Conservative: false unless a hook is actually wired.
	ObserveInteractions() bool
	// NativeInteractiveUI reports whether the runtime has a native
	// interactive TUI — the place a human answers when pagnet cannot
	// remote-resolve the interaction.
	NativeInteractiveUI() bool
	// SupportsDeferredInteraction reports whether a turn can exit safely
	// while a pending interaction of kind is stored (headless defer: the
	// instance may hibernate and be woken later).
	SupportsDeferredInteraction(kind string) bool
	// SupportsRemoteResolve reports whether a pending interaction of kind
	// can be resolved remotely (the runtime can supply the answer back
	// into the native session). When false, the answer must be given in
	// the native TUI and the remote-resolve API rejects with 409.
	SupportsRemoteResolve(kind string) bool
}
