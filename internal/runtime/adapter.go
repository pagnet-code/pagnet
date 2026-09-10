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
)

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
