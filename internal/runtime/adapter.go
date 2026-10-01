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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sandbox"
	"github.com/pagnet-code/pagnet/internal/session"
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
	// AgentMDPath is the daemon-managed standing document file (the pagnet
	// runtime/network overlay + the operator's standing agent instruction
	// when set) the runtime loads as extra system context ("" = none).
	// Claude maps it to --append-system-prompt-file; the persistent drivers
	// and opencode receive the SAME text as StandingInstructions and use
	// their native standing surfaces (they never read this path). The
	// document is NEVER appended to a turn's input.
	AgentMDPath string
	// StandingInstructions is the text of the daemon-managed standing
	// document (overlay + the operator's standing instruction when set) —
	// the vendor-neutral standing context the runtime delivers through its
	// NATIVE surface: qwen --append-system-prompt at endpoint launch,
	// opencode's instance-scoped config, (later) codex
	// developerInstructions. It is standing context, never a turn input.
	// For persistent endpoints it is FIXED AT LAUNCH (the session core
	// restarts the endpoint when it changes, like Env/Model).
	StandingInstructions string
	// Metadata carries runtime-agnostic extras (e.g. profile, transcript).
	Metadata map[string]any
	// Env is extra KEY=VALUE pairs for the spawned process (per-instance
	// pagnet injection: MCP bridge config, coordination contract,
	// identity). Appended after the adapter's own environment.
	Env []string
	// SandboxDenied is the sandbox containment set (F-CFG-1): paths that
	// must not be equal to or path-beneath any RW grant of the spec this
	// turn's launch carries. The daemon sets it to its OWN state dir, so
	// a workspace that would swallow the state dir (e.g. workspace =
	// $HOME) makes the launch fail closed with an explicit error BEFORE
	// any process starts (the supervisor's wrap validates the spec; the
	// wrapper re-validates in Apply). Empty in tests / standalone use.
	SandboxDenied []string
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
	Plan        *session.PlanSnapshot
}

// TurnEvent types (generic; NOT runtime-specific).
const (
	EventSessionStarted = "runtime.session.started"
	EventSessionResumed = "runtime.session.resumed"
	EventTurnStarted    = "runtime.turn.started"
	EventTurnOutput     = "runtime.turn.output"
	EventPlanUpdated    = "runtime.plan.updated"
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

// isTerminalEvent reports whether the event type ends the turn's event
// stream (the runtime emits nothing after it). Adapters break their stdout
// scan on a terminal event so a descendant that outlived the runtime and
// still holds the stdout pipe cannot block the turn until its context
// expires (the 2026-09-15 pipe-hold hazard).
func isTerminalEvent(ty string) bool {
	switch ty {
	case EventTurnCompleted, EventTurnFailed, EventSessionLost:
		return true
	}
	return false
}

// errorString renders an error for a turn-failure message without
// panicking on a nil error. A runtime can exit cleanly (nil wait error)
// yet still fail to emit a result line; the failure text must fall back
// to the stderr/placeholder, not crash the daemon on a nil dereference
// (external audit F-011).
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// AtomicWriteFile writes data to path atomically: write a temp file in
// the SAME directory, fsync, then rename over path. A crash mid-write
// leaves the previous file intact — never a partial/corrupt one (external
// audit F-013). The temp file is created 0600 and chmod'd to perm before
// it is linked into place, so the session/config file is never world-
// readable even transiently.
//
// The rename is also the SYMLINK-SAFE primitive (F-S2-1): rename(2)
// replaces the destination ENTRY without following it, so a file that a
// compromised same-UID process planted as a symlink at the destination
// (pointing at a secret outside the subtree) is replaced, never written
// through. Plain os.WriteFile (O_WRONLY|O_CREATE|O_TRUNC) follows the
// symlink and would clobber the pointed-at file — which is why every
// daemon/driver write into a runtime-writable dir uses this helper.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// capturedStderr captures a child's stderr under the supervisor's reap
// semantics. The supervisor reaps the direct child with Process.Wait
// (a raw waitpid) and deliberately NEVER calls cmd.Wait: cmd.Wait would
// close the child's I/O pipes in the background while the driver is
// still draining stdout (the opencode mid-turn-death regression). The
// cost: with cmd.Stderr set to an io.Writer (*bytes.Buffer), the
// copier goroutine exec.Cmd spawns internally for the pipe→buffer copy
// is joined ONLY by cmd.Wait — which the supervisor never calls — so
// h.Wait() could return while the copier was still writing, and the
// driver's post-reap stderrBuf.String() data-raced (the 2026-09-29
// -race CI finding: claude.go / opencode.go / fake.go).
//
// The driver therefore owns the drain: attachStderrDrain switches
// cmd.Stderr from the io.Writer form to StderrPipe plus a dedicated
// goroutine that reads the pipe to EOF and appends to the buffer under
// a mutex. The child's write end closes when the child exits, so the
// drain completes right after the reap — unless a descendant inherited
// and holds the write end (the same pipe-hold hazard the stdout loops
// handle with an early break); the reaper's group reclaim kills the
// holder and the drain then finishes in the background. Text never
// races: the buffer is read only under the same mutex, and Text gives
// the drain a bounded head start so the normal case returns the
// complete stream.
type capturedStderr struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	drained    chan struct{}
	drainBound time.Duration
}

// stderrDrainBound is how long Text waits for the drain to complete
// after the reap before returning a best-effort prefix. The normal
// drain (child reaped → write end closed) completes in milliseconds;
// the bound elapses only while a descendant still holds the write end,
// and the reaper's group reclaim bounds that in the background.
const stderrDrainBound = 2 * time.Second

// newCapturedStderr starts the drain goroutine on pipe and returns the
// capture. The goroutine exits when the pipe reaches EOF (the child's
// write end closes at exit — or when the reaper's group reclaim kills
// a descendant holding it).
func newCapturedStderr(pipe io.ReadCloser, drainBound time.Duration) *capturedStderr {
	c := &capturedStderr{drained: make(chan struct{}), drainBound: drainBound}
	go c.drain(pipe)
	return c
}

// attachStderrDrain sets cmd.Stderr to a driver-owned drain (see
// capturedStderr). It must be called before Start (the pipe is created
// at Start) — and before the supervisor's Launch wraps the cmd.
func attachStderrDrain(cmd *exec.Cmd) (*capturedStderr, error) {
	pipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	return newCapturedStderr(pipe, stderrDrainBound), nil
}

func (c *capturedStderr) drain(pipe io.ReadCloser) {
	defer close(c.drained)
	chunk := make([]byte, 32*1024)
	for {
		n, rerr := pipe.Read(chunk)
		if n > 0 {
			c.mu.Lock()
			c.buf.Write(chunk[:n])
			c.mu.Unlock()
		}
		if rerr != nil {
			pipe.Close()
			return
		}
	}
}

// Text returns the captured stderr. It first waits up to drainBound
// for the drain to complete (the normal case: the child is reaped, its
// write end closed, and the drain finishes in milliseconds); if the
// bound elapses a descendant is still holding the write end and the
// text is a best-effort prefix — the reaper's group reclaim kills the
// holder and the drain finishes in the background.
func (c *capturedStderr) Text() string {
	select {
	case <-c.drained:
	case <-time.After(c.drainBound):
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// InteractionEvent is a normalized observation of a native runtime
// interaction. The adapter emits it on the turn's events channel as
// EventInteractionStarted / EventInteractionResolved; the daemon translates
// it into the host protocol. The vendor payload stays opaque — the server
// never parses it for correctness (plan §8.2).
type InteractionEvent struct {
	Options []domain.RuntimeInteractionOption
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
	// SandboxSpec is the per-instance filesystem allowlist (S2) the
	// supervisor applies when it starts the runtime for this spec. It is
	// built from what the driver KNOWS for this instance (H4): the
	// workspace + pagnet session/state dirs + the runtime's OWN native
	// state dir as RW, the coarse system read + binary support paths as
	// RO, and the daemon bridge socket. The daemon's state dir is NEVER
	// an RW/RO grant (its secret contents stay denied; only the socket's
	// traversal chain is granted). It must cover BOTH the StartTurn
	// process and the InteractiveCmd process (the daemon passes the same
	// spec to both launch shapes). nil is not allowed on a launch — the
	// supervisor refuses a spec-less launch on sandbox-requiring
	// platforms (fail closed, H3).
	SandboxSpec(spec TurnSpec) *sandbox.Spec
}

// --- shared adapter helpers ----------------------------------------------------

// readStoredSession loads the last captured runtime session id, "" if none.
// The process-per-turn adapters (claude-code, opencode) persist the exact
// captured id so a later resume passes it back to the CLI.
func readStoredSession(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var s struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", err
	}
	return strings.TrimSpace(s.SessionID), nil
}

// writeStoredSession persists the captured runtime session id (0600,
// atomic — session ids are local state, never world-readable).
func writeStoredSession(path, id string) error {
	b, _ := json.Marshal(struct {
		SessionID string `json:"sessionId"`
	}{SessionID: id})
	return AtomicWriteFile(path, append(b, '\n'), 0o600)
}

// intPtr is the token-usage pointer helper (nil when the runtime reports
// nothing / zero).
func intPtr(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

// firstNonEmpty returns the first non-blank text, or a placeholder when
// none (a failure message must never be empty).
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "runtime exited without output"
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
