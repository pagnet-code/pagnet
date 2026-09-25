package runtime

// Qwen Dual Output persistent runtime driver (runtime-lifecycle refactor,
// Phase 4 / Wave A).
//
// QwenPersistent is the persistent (one long-lived process per
// AgentInstance) Qwen integration. It runs ONE interactive `qwen` TUI under
// a PTY and drives it through the DUAL OUTPUT sidecar files (doc §2):
//
//   - HUMAN plane = the PTY. The TUI renders to stdout, so the child's
//     stdin/stdout/stderr ARE the PTY slave (the supervisor's stdio-to-tty
//     launch shape, B1). A human attaching to the terminal sees and types
//     into the real Qwen TUI.
//   - MACHINE plane = two sidecar REGULAR files under the pagnet state dir
//     (§44 — never the workspace):
//     - --json-file: the JSONL event stream the daemon reads (doc §3).
//     - --input-file: the JSONL command file the daemon appends (doc §4):
//       exactly {"type":"submit","text":…} and
//       {"type":"confirmation_response","request_id":…,"allowed":…}.
//
// It implements the generic session.Driver contract (and the optional
// session.PTYOwner for the human plane, session.RemoteResolvable for the
// per-kind remote-resolution policy), so the daemon drives it through the
// session core exactly the way it drives the other persistent runtimes.
//
// Wave B removed the legacy process-per-turn Qwen adapter (qwen.go,
// StartTurn) after equivalence was proven: this driver is the ONLY qwen
// path (the daemon registers it whenever the binary resolves and routes
// every qwen instance to it).
//
// Key invariants (brief B1–B11, doc §5–§8):
//   - B1: the child's stdio is the PTY slave (PTYStdio); the machine plane
//     is files, never pipes (a driver that sets PTYStdio must NOT wire
//     Cmd.Stdin/Stdout to pipes).
//   - B2/R1/R8: the version gate is read from the session_start handshake
//     ONLY (the symlinked package version lies). Pagenet provides the
//     machine channel (--json-file/--input-file) and does NOT force a TUI
//     renderer — it follows the vendor default; a version-pinned renderer
//     override is allowed ONLY for a concrete, documented,
//     regression-tested, version-specific compatibility defect, and must
//     be removed when upstream fixes it.
//   - B3/R6/R7: NativeID = the top-level session_id from the handshake,
//     persisted WITH the exact cwd (resume resolves project-scoped against
//     cwd, doc §5.3); the stored cwd is asserted byte-identical before -r;
//     the resume id is UUID-validated client-side (a non-UUID becomes a
//     silent title lookup, doc §5.2); a resume that re-bases onto a
//     different session is a lost session, never a silent fresh one.
//   - B4: there is NO `result` event in dual-output mode; turn end is
//     the CLOSE of a model step (message_stop) on a text-only final
//     answer — a text-only assistant finalize alone does NOT end the turn
//     (a tool_use block may follow in the same step; one assistant event
//     per content block group, see qwen_persistent_state.go); usage is
//     accumulated from assistant.message.usage.
//   - B6: the input file is fresh per launch (deleted before cmd.Start),
//     0600 REGULAR (not a FIFO), append-only, one \n-terminated JSON line
//     per write, fsync'd, never truncated; a submit not acknowledged
//     (no `user` event) within the correlation deadline is surfaced, never
//     blind-retried (no idempotency, doc §4.3). The submit text is
//     normalized at the channel boundary (trailing whitespace stripped):
//     the line-protocol receiver strips it too, and the correlation is an
//     EXACT match of the echoed text against what was written (see
//     Submit).
//   - B7: the 15s startup deadline (no session_start = activation
//     failure); the 60s in-flight stall is ALERTABLE (surfaced, not a kill).
//   - §6/R3: ask_user_question is HUMAN-ONLY — the daemon must never
//     auto-resolve it (a generic allowed:true yields a phantom answer).
//     can_use_tool remote resolution expresses ONLY proceed_once / cancel.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// eventPollInterval is the readLoop's poll cadence for the events file and
// the process-liveness probe. The qwen bridge writes the events file
// synchronously (no polling on the qwen side, doc §4.5); the daemon reads
// it with this poll. 100ms bounds the turn-event latency and the unexpected
// death detection.
const eventPollInterval = 100 * time.Millisecond

// qwenStateFile is the per-instance session metadata file (the session id +
// exact cwd, the resume anchor — B3 / R6).
const qwenStateFile = "session.json"

// QwenPersistent is the Qwen Dual Output persistent driver.
type QwenPersistent struct {
	// Binary is the path to the qwen executable. When empty it is resolved
	// from PATH / next to the current executable.
	Binary string
	// Model overrides the model for managed endpoints (empty = the
	// session's launch model, then the PAGNET_QWEN_MODEL env, then the
	// user's default).
	Model string
	// Env is appended to the inherited environment for the endpoint
	// process.
	Env []string
	// PTYSize is the initial winsize for the endpoint's TUI PTY. When nil,
	// a sane default is used (the TUI needs a PTY — doc §2.4 / §7.1).
	PTYSize *pty.Winsize

	life lifecycleState

	mu        sync.Mutex
	endpoints map[string]*qwenEndpoint
}

// NewQwenPersistent builds a Qwen Dual Output persistent driver.
func NewQwenPersistent(binary string) *QwenPersistent {
	return &QwenPersistent{Binary: binary, endpoints: map[string]*qwenEndpoint{}}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (q *QwenPersistent) SetLifecycle(l proc.Lifecycle) { q.life.SetLifecycle(l) }

// Name is the canonical runtime name (the daemon registers this driver
// when the qwen binary resolves and routes every qwen instance to the
// persistent path — Wave B removed the legacy process-per-turn adapter).
func (q *QwenPersistent) Name() domain.RuntimeName { return domain.RuntimeQwenCode }

// Capabilities is the probed capability set (B8 — honest advertisement).
func (q *QwenPersistent) Capabilities() session.Capabilities {
	return session.Capabilities{
		PersistentEndpoint:          true,
		MultipleSessionsPerEndpoint: false, // one session per endpoint
		StructuredEvents:            true,
		NativeSubmit:                true,
		// The TUI queues a submit typed while a turn is in flight (the
		// input file is append-only; the TUI dispatches it on the next
		// idle). pagnet still serializes prompt turns (one in flight).
		NativeQueueWhileBusy: true,
		NativeSteer:          false,
		Interrupt:            false,
		// can_use_tool control_requests are observed as structured events
		// (doc §6.1).
		NativeInteractionObserve: true,
		// can_use_tool kinds are remotely resolvable (proceed_once /
		// cancel — the ONLY two expressible outcomes, R10). ask_user_question
		// is NOT (human-only — see SupportsRemoteResolve).
		RemoteInteractionResolve: true,
		// The endpoint OWNS a native TUI on its PTY (the human plane).
		NativeTUI:                       true,
		SecondClientTerminalAttach:      true, // a human attaches to the endpoint PTY
		TerminalAttachmentFullAuthority: true, // the attached human has full authority
		LiveExternalAdoption:            false,
		// A plain-launched (human) qwen session can be resumed under pagnet
		// (RESUME_REQUIRED — doc §5.4).
		ResumeExternalSession:  true,
		NativeSessionDiscovery: true,  // qwen sessions list --json
		DynamicModelChange:     false, // the model is fixed at launch
		DynamicMCPInjection:    false, // MCP is fixed at launch
	}
}

// SupportsRemoteResolve reports whether a pending interaction of kind can
// be resolved remotely (it implements the session.RemoteResolvable
// optional interface). ask_user_question is HUMAN-ONLY (doc §6.3 / R3): the
// daemon must never auto-resolve it — a generic allowed:true yields a
// phantom "No valid answers were provided." answer, worse than a hang.
// Everything else (can_use_tool kinds) is remotely resolvable (the only two
// expressible outcomes are proceed_once / cancel — R10).
func (q *QwenPersistent) SupportsRemoteResolve(kind string) bool {
	return kind != "question"
}

// Available reports whether the qwen binary is resolvable (the session-core
// analogue of the Adapter.Available method).
func (q *QwenPersistent) Available() bool {
	_, err := q.binary()
	return err == nil
}

// BinaryPath reports the resolved path of the qwen binary (same resolution
// as Available).
func (q *QwenPersistent) BinaryPath() (string, bool) {
	p, err := q.binary()
	return p, err == nil
}

// --- session.Driver implementation -----------------------------------------

// Activate starts (cold) or resumes the endpoint for the session. It is
// idempotent: a live endpoint is returned unchanged. A resume of a
// non-materialised session is refused (ErrNotMaterialised); a resume that
// re-bases onto a different session (or finds none) is ErrSessionLost.
func (q *QwenPersistent) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	q.mu.Lock()
	if e, ok := q.endpoints[sess.InstanceID]; ok && e.live() {
		q.mu.Unlock()
		return e.endpointInfo(sess), nil
	}
	q.mu.Unlock()

	// Resume gate (mirrors the Manager's gate; defense-in-depth for
	// standalone use).
	if sess.NativeID != "" && !sess.Materialised {
		return nil, session.ErrNotMaterialised
	}

	e, err := q.launchEndpoint(sess)
	if err != nil {
		return nil, err
	}

	// Read the activation event (the handshake).
	var actEv session.SessionEvent
	select {
	case actEv = <-e.activationCh:
	case <-ctx.Done():
		q.dropEndpoint(sess.InstanceID)
		return nil, ctx.Err()
	case <-time.After(activationTimeout):
		// B7: no session_start within the startup deadline is an
		// activation failure, not a hang.
		q.dropEndpoint(sess.InstanceID)
		return nil, errors.New("qwen persistent: activation timed out (no session_start within the startup deadline)")
	}
	if events != nil {
		events <- actEv
	}
	if actEv.Type == session.EventSessionLost {
		// The resume found no usable session (or the handshake gate
		// failed). The endpoint that was just launched for the attempt must
		// be fully stopped AND reaped so a lost resume never leaves a stale
		// endpoint in the supervisor's registry.
		q.stopEndpoint(sess.InstanceID)
		return nil, session.ErrSessionLost
	}
	sess.NativeID = actEv.SessionID
	return e.endpointInfo(sess), nil
}

// Submit delivers one logical input (a prompt or an interaction resolution)
// into the session's live endpoint. For a prompt it blocks until the turn
// settles (the reader signals turnDone on the terminal event); for an
// interaction it writes the confirmation_response and returns (the
// in-flight turn's stream carries the interaction.resolved + terminal
// events).
func (q *QwenPersistent) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	q.mu.Lock()
	e := q.endpoints[sess.InstanceID]
	q.mu.Unlock()
	if e == nil || !e.live() {
		// The endpoint is gone (dropped by the reader's exit path on an
		// unexpected death, or never launched). This is NOT a runtime turn
		// failure: the Manager re-activates and retries the submit.
		return session.ErrEndpointGone
	}
	if req.Kind == session.SubmitInteraction {
		// Remote resolution: append a confirmation_response (the ONLY two
		// expressible outcomes are proceed_once / cancel — R10). The
		// in-flight turn's stream carries the interaction.resolved.
		allowed := req.Decision == "resolved"
		cmd := qwenInputCmd{
			Type:      "confirmation_response",
			RequestID: req.InteractionID,
			Allowed:   &allowed,
		}
		if err := e.writeInput(cmd); err != nil {
			// A write to the input file fails when the process is dead (the
			// file is unlinked / the bridge is gone). Report it as
			// endpoint-gone so the Manager re-activates.
			return session.ErrEndpointGone
		}
		return nil
	}
	// Prompt: register the machine turn, write the submit, wait for the
	// turn to settle.
	e.mu.Lock()
	if e.currentTurnEvents != nil {
		e.mu.Unlock()
		return session.ErrBusy
	}
	e.currentTurnID = req.TurnID
	e.currentTurnEvents = events
	e.turnEndpointGone = false
	e.turnDone = make(chan struct{})
	done := e.turnDone
	e.mu.Unlock()
	// Channel contract: the input file is a line protocol and the TUI's
	// submit consumes the text as a line payload, stripping trailing
	// whitespace — observed against qwen 0.24.0 (a submitted "alpha\n"
	// echoes back the user event with text "alpha"). The B6 submit
	// correlation compares the ECHOED user-event text against the
	// submitted text, so the text written here must be exactly the text
	// the receiver will echo: normalize at the channel boundary. A
	// trailing newline left in the payload fails the correlation and
	// misclassifies the machine turn as a human turn — no turn.completed
	// on the machine stream, and the correlation deadline then surfaces
	// a phantom "submit not acknowledged" after the turn actually ends.
	// Trailing whitespace in a prompt is semantically inert.
	text := strings.TrimRight(req.Input, " \t\r\n")
	e.state.beginMachineTurn(req.TurnID, text)
	cmd := qwenInputCmd{Type: "submit", Text: text}
	if err := e.writeInput(cmd); err != nil {
		e.state.clearMachineTurn()
		e.clearTurn()
		return session.ErrEndpointGone
	}
	select {
	case <-done:
		e.mu.Lock()
		gone := e.turnEndpointGone
		e.mu.Unlock()
		if gone {
			// The endpoint PROCESS DIED mid-turn (cleanupOnExit woke this
			// turn; the events channel carries NO terminal turn event). This
			// is NOT a settled turn and NOT a runtime turn failure: the turn
			// consumed no work, so the Manager re-activates (resuming the
			// materialised session) and retries the logical submit once.
			// Reporting nil here is what wedged an instance as permanently
			// working with no live endpoint.
			return session.ErrEndpointGone
		}
		return nil
	case <-ctx.Done():
		e.state.clearMachineTurn()
		e.clearTurn()
		return ctx.Err()
	}
}

// Hibernate stops the endpoint, preserving the session (the qwen chat
// recording persists the session on disk — invariant F). It is a no-op when
// no endpoint is live.
func (q *QwenPersistent) Hibernate(ctx context.Context, sess *session.RuntimeSession) error {
	return q.stopEndpoint(sess.InstanceID)
}

// Stop terminates the endpoint unconditionally (daemon shutdown / explicit
// stop).
func (q *QwenPersistent) Stop(instanceID string) error {
	return q.stopEndpoint(instanceID)
}

// PID is the endpoint's process id (nil when none).
func (q *QwenPersistent) PID(instanceID string) *int {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	if e == nil {
		return nil
	}
	return e.pid()
}

// Live reports whether the instance's endpoint process is still alive. It
// is the liveness probe the Manager consults before trusting a live session
// state: when the endpoint record is absent (dropped by the reader's exit
// path on an unexpected death) or its reader has exited (the process is
// gone), the endpoint is gone and the session must be re-activated, not
// wedged.
func (q *QwenPersistent) Live(instanceID string) bool {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	return e != nil && e.live()
}

// PTYMaster is the endpoint's TUI PTY master (the human plane) — nil when
// the endpoint is not live. It implements the session.PTYOwner interface so
// the daemon's terminal plane can attach a human to the ENDPOINT'S OWN PTY
// instead of spawning a second interactive process. The master is owned by
// the process handle: callers hold it as a VIEW and never close it.
func (q *QwenPersistent) PTYMaster(instanceID string) *os.File {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	if e == nil || !e.live() || e.h == nil {
		return nil
	}
	return e.h.PTY()
}

// --- endpoint lifecycle ------------------------------------------------------

// qwenEndpoint is one live qwen dual-output endpoint process.
type qwenEndpoint struct {
	f          *QwenPersistent // back-reference (the reader's exit path drops this record)
	instanceID string
	stateDir   string
	h          *proc.Handle // set once at launch, never nilled (immutable)
	eventsPath string
	inputPath  string
	state      *qwenTurnState

	// activationCh carries the process's first (activation) event; closed
	// by the reader after it is delivered.
	activationCh chan session.SessionEvent
	// readerDone is closed when the event-file reader exits (the process
	// has exited). It is the liveness signal.
	readerDone chan struct{}

	mu                sync.Mutex
	activationSent    bool
	currentTurnID     string
	currentTurnEvents chan<- session.SessionEvent
	turnDone          chan struct{}
	// turnEndpointGone distinguishes WHY turnDone was closed: false = the
	// turn settled on a NORMAL terminal runtime event (routeEvent), true =
	// the endpoint PROCESS DIED mid-turn (cleanupOnExit). Both paths close
	// the same channel, so without this flag Submit's `case <-done` cannot
	// tell a completed turn from a cut-off one — it would report a mid-turn
	// death as success (nil), the Manager would treat the submit as
	// settled, and the instance could stay persisted as working with no
	// endpoint at all.
	//
	// It is written under mu BEFORE turnDone is closed and reset when a new
	// turn is registered, so the woken Submit always reads the value that
	// belongs to ITS turn. It is stable across the wake: cleanupOnExit
	// drops the endpoint record before closing, so no new turn can be
	// registered on a dying endpoint (Submit looks the record up first and
	// returns ErrEndpointGone when it is gone).
	turnEndpointGone bool

	inputFile *os.File
	inputMu   sync.Mutex
}

// live reports whether the endpoint process is still running. The reader
// closes readerDone when the process exits, so a closed readerDone means
// the process is gone.
func (e *qwenEndpoint) live() bool {
	select {
	case <-e.readerDone:
		return false
	default:
		return true
	}
}

// processGone reports whether the endpoint process has exited (it is a
// zombie — exited, not yet reaped — or it no longer exists). The readLoop
// polls it to detect an unexpected process death: the machine plane is
// files, not pipes, so there is no stdout EOF to signal the exit.
func (e *qwenEndpoint) processGone() bool {
	if e.h == nil {
		return true
	}
	pid := e.h.PID()
	if pid == 0 {
		return false // still starting
	}
	return proc.ProcessIsZombie(pid) || !proc.ProcessAlive(pid)
}

func (e *qwenEndpoint) pid() *int {
	if e.h == nil {
		return nil
	}
	p := e.h.PID()
	if p == 0 {
		return nil
	}
	return &p
}

func (e *qwenEndpoint) endpointInfo(sess *session.RuntimeSession) *session.RuntimeEndpoint {
	ep := &session.RuntimeEndpoint{
		ID:        "ep-" + e.instanceID,
		Runtime:   sess.Runtime,
		Ownership: session.OwnershipPagnet,
		Lease:     session.LeaseClaimed,
		Healthy:   true,
		Transport: "pty+files",
		Sessions:  []string{e.state.nativeSessionID()},
		StartedAt: time.Now(),
	}
	if e.h != nil {
		ep.PID = e.h.PID()
		ep.PGID = e.h.PGID()
	}
	return ep
}

// writeInput appends one JSONL command to the input file (B6: append-only,
// one \n-terminated JSON line per write, fsync'd, never truncated).
func (e *qwenEndpoint) writeInput(cmd qwenInputCmd) error {
	e.inputMu.Lock()
	defer e.inputMu.Unlock()
	if e.inputFile == nil {
		return errors.New("qwen input file is closed")
	}
	b, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := e.inputFile.Write(b); err != nil {
		return err
	}
	return e.inputFile.Sync()
}

// qwenInputCmd is one input-file command (doc §4.1: exactly two shapes).
type qwenInputCmd struct {
	Type      string `json:"type"` // submit | confirmation_response
	Text      string `json:"text,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Allowed   *bool  `json:"allowed,omitempty"`
}

// clearTurn resets the in-flight turn state (on a submit failure or ctx
// cancel). It does not close the events channel (the Manager owns that).
func (e *qwenEndpoint) clearTurn() {
	e.mu.Lock()
	e.currentTurnEvents = nil
	e.currentTurnID = ""
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
}

// persistSession persists the handshake's session id + exact cwd to
// session.json (B3 / R6): the resume path resolves project-scoped against
// the stored cwd and asserts it is byte-identical before passing -r.
func (e *qwenEndpoint) persistSession() {
	sid := e.state.nativeSessionID()
	if sid == "" {
		return
	}
	_ = writeStoredQwenSession(filepath.Join(e.stateDir, qwenStateFile), sid, e.state.nativeCWD())
}

// launchEndpoint starts the qwen dual-output endpoint through the
// supervisor (ClassEndpoint + PTYStdio: the child's stdio IS the PTY slave,
// B1) and wires the machine-plane files. The events-file reader is started;
// it routes the activation event to activationCh and subsequent turn events
// to the current turn.
func (q *QwenPersistent) launchEndpoint(sess *session.RuntimeSession) (*qwenEndpoint, error) {
	bin, err := q.binary()
	if err != nil {
		return nil, err
	}
	if sess.Workspace == "" {
		return nil, errors.New("qwen persistent: requires a workspace (qwen sessions are CWD-scoped)")
	}
	// Per-instance state dir (under the pagnet state dir, never the
	// workspace — §44).
	stateDir := filepath.Join(q.stateDir(), "qwen", sess.InstanceID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	eventsPath := filepath.Join(stateDir, "events.jsonl")
	inputPath := filepath.Join(stateDir, "input.jsonl")
	sessionMetaPath := filepath.Join(stateDir, qwenStateFile)

	// Fresh input file per launch (B6): delete the stale one (a stale
	// command would be replayed — the watcher re-reads the ENTIRE file on a
	// prefix change / shrink, doc §4.4), create 0600 REGULAR (not a FIFO —
	// the watcher is stat-size-based, doc §4.4).
	_ = os.Remove(inputPath)
	inputFile, err := os.OpenFile(inputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	// A stale events file would be read as the new session's stream (the
	// reader starts at offset 0): delete it so the new bridge's stream is
	// the only content.
	_ = os.Remove(eventsPath)

	resuming := sess.NativeID != ""
	var resumeID string
	if resuming {
		resumeID = sess.NativeID
		// UUID-validate client-side (R7): a non-UUID -r becomes a silent
		// title lookup (doc §5.2) — refuse it, never hang.
		if !isUUID(resumeID) {
			inputFile.Close()
			return nil, fmt.Errorf("qwen persistent: stored session id %q is not a valid UUID (refusing to resume)", resumeID)
		}
		// Assert the stored cwd is byte-identical (R6 / G6): a cwd drift
		// makes the resume look like "No saved session found" (doc §5.3).
		if _, storedCwd, rerr := readStoredQwenSession(sessionMetaPath); rerr == nil && storedCwd != "" && storedCwd != sess.Workspace {
			inputFile.Close()
			return nil, fmt.Errorf("qwen persistent: stored cwd %q != current workspace %q (cwd drift; refusing to resume)", storedCwd, sess.Workspace)
		}
	}

	args := []string{
		"--json-file", eventsPath,
		"--input-file", inputPath,
	}
	// Model precedence (B9): the session's launch model > the driver's
	// field > the PAGNET_QWEN_MODEL env > the user default.
	if model := q.modelFor(sess); model != "" {
		args = append(args, "-m", model)
	}
	// Resume: always pass an explicit -r <id> (an empty -r opens a picker
	// ⇒ hang; doc §5.2). Never --continue, never --fork-session.
	if resuming {
		args = append(args, "-r", resumeID)
	}
	// MCP bridge (B9): inline --mcp-config (merges with the user's own MCP
	// servers, writes no file into the workspace). A failure is visible.
	if mcpJSON := pagnetMCPConfig(sess.Env); mcpJSON != "" {
		var cfg struct {
			MCPServers map[string]any `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(mcpJSON), &cfg); err != nil {
			inputFile.Close()
			return nil, fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
		}
		if len(cfg.MCPServers) == 0 {
			inputFile.Close()
			return nil, errors.New("PAGNET_MCP_CONFIG has no mcpServers")
		}
		args = append(args, "--mcp-config", mcpJSON)
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = sess.Workspace
	// Launch env (Phase 2 / R8): the endpoint child receives the session's
	// launch environment (the generic spec pairs the daemon injects for the
	// instance). The env is FIXED AT LAUNCH.
	//
	// The ownership marker (R1): the endpoint child's environment carries
	// PAGNET_INSTANCE_ID=<id> (the same pair the supervisor stores in the
	// ownership record).
	env := append([]string(nil), sess.Env...)
	hasMarker := false
	for _, kv := range env {
		if kv == "PAGNET_INSTANCE_ID="+sess.InstanceID {
			hasMarker = true
			break
		}
	}
	if !hasMarker {
		env = append(env, "PAGNET_INSTANCE_ID="+sess.InstanceID)
	}
	// Native-first renderer rule: Pagenet provides the machine channel
	// (--json-file/--input-file) and does NOT force a TUI renderer — it
	// follows the vendor default. The user's own QWEN_TUI_RENDERER (if set
	// in the session's launch env) passes through untouched via sess.Env
	// above. A version-pinned renderer override is allowed ONLY for a
	// concrete, documented, regression-tested, version-specific
	// compatibility defect, and must be removed when upstream fixes it.
	cmd.Env = ChildEnv(q.Env, env)

	// The machine plane is FILES, not pipes: the child's stdio is the PTY
	// slave (the supervisor's stdio-to-tty launch shape, B1). No
	// StdinPipe/StdoutPipe.
	lif := q.life.get()
	el, ok := lif.(proc.EndpointLifecycle)
	if !ok {
		inputFile.Close()
		return nil, errors.New("qwen persistent: lifecycle does not support endpoints")
	}
	ws := q.PTYSize
	if ws == nil {
		ws = &pty.Winsize{Rows: 24, Cols: 80}
	}
	// The endpoint is LONG-LIVED: it must survive across turns (the whole
	// point of the persistent model). The launch ctx must NOT be a turn's
	// ctx (cancelled at turn end) — it is the driver's own lifetime.
	h, err := el.Launch(context.Background(), proc.LaunchRequest{
		InstanceID: sess.InstanceID,
		TurnID:     "endpoint",
		Runtime:    string(q.Name()),
		Class:      proc.ClassEndpoint,
		Cmd:        cmd,
		Marker:     "PAGNET_INSTANCE_ID=" + sess.InstanceID,
		PTYSize:    ws,
		PTYStdio:   true, // the TUI renders to the PTY (B1)
	})
	if err != nil {
		inputFile.Close()
		return nil, err
	}

	e := &qwenEndpoint{
		f:            q,
		instanceID:   sess.InstanceID,
		stateDir:     stateDir,
		h:            h,
		eventsPath:   eventsPath,
		inputPath:    inputPath,
		inputFile:    inputFile,
		state:        newQwenTurnState(resuming, resumeID, time.Now),
		activationCh: make(chan session.SessionEvent, 1),
		readerDone:   make(chan struct{}),
	}
	go e.readLoop()
	q.mu.Lock()
	q.endpoints[sess.InstanceID] = e
	q.mu.Unlock()
	return e, nil
}

// readLoop reads the events file (JSONL) and routes the normalized events:
// the first event is the activation event (→ activationCh, then closed);
// subsequent events are turn events (→ the current turn's channel). It
// polls the file (the machine plane is files, not pipes — there is no
// stdout EOF) and the process liveness. On process exit it reaps the
// process (this goroutine is the single Wait owner) and signals any waiting
// turn.
func (e *qwenEndpoint) readLoop() {
	defer close(e.readerDone)
	// Wait for the events file to appear (the bridge opens it at startup).
	f, err := e.waitForEventsFile()
	if err != nil {
		// The file never appeared: the process exited before writing it
		// (e.g. "No saved session found" — exit 1, doc §5.2) or the bridge
		// failed to open it (doc §7.2: the TUI continues without dual
		// output). Signal the activation as lost, then reap and drop.
		e.mu.Lock()
		if !e.activationSent {
			e.activationSent = true
			e.activationCh <- session.SessionEvent{
				Type:  session.EventSessionLost,
				Error: "qwen activation failed: " + err.Error(),
			}
			close(e.activationCh)
		}
		e.mu.Unlock()
		e.cleanupOnExit()
		return
	}
	defer f.Close()
	offset := int64(0)
	for {
		// Read new complete lines.
		lines, newOffset, readErr := readNewLines(f, offset)
		if readErr == nil {
			offset = newOffset
			for _, line := range lines {
				e.handleEventLine(line)
			}
		}
		// Watchdog (B6 / B7): check the time-based conditions (submit
		// correlation deadline, in-flight stall).
		for _, ev := range e.state.tick() {
			e.routeEvent(ev)
		}
		// Process exit or file gone: best-effort final read, then clean up.
		if readErr != nil || e.processGone() {
			if readErr == nil {
				if flines, _, ferr := readNewLines(f, offset); ferr == nil {
					for _, line := range flines {
						e.handleEventLine(line)
					}
				}
			}
			e.cleanupOnExit()
			return
		}
		time.Sleep(eventPollInterval)
	}
}

// waitForEventsFile waits for the events file to appear (the bridge opens
// it at startup). It returns the opened file, or an error when the file
// does not appear within the startup deadline (the bridge failed to open
// it — doc §7.2: the TUI continues without dual output) or the process
// exits first (e.g. "No saved session found" — exit 1, doc §5.2).
func (e *qwenEndpoint) waitForEventsFile() (*os.File, error) {
	deadline := time.Now().Add(activationTimeout)
	for time.Now().Before(deadline) {
		if e.processGone() {
			return nil, errors.New("qwen process exited before the event file appeared")
		}
		f, err := os.Open(e.eventsPath)
		if err == nil {
			return f, nil
		}
		time.Sleep(eventPollInterval)
	}
	return nil, errors.New("qwen event file did not appear within the startup deadline")
}

// handleEventLine processes one event line: it runs the state machine and
// routes the normalized events (activation vs. the current turn).
func (e *qwenEndpoint) handleEventLine(line []byte) {
	for _, ev := range e.state.processLine(line) {
		e.routeEvent(ev)
	}
}

// routeEvent routes a normalized event: the first event (the activation)
// goes to activationCh; subsequent events go to the current turn (when the
// TurnID matches).
func (e *qwenEndpoint) routeEvent(ev session.SessionEvent) {
	e.mu.Lock()
	if !e.activationSent {
		e.activationSent = true
		e.mu.Unlock()
		// Persist the handshake's session id + exact cwd (B3 / R6) BEFORE
		// publishing the activation event (so the caller can rely on the
		// persisted state once it observes the event).
		if ev.Type == session.EventSessionStarted || ev.Type == session.EventSessionResumed {
			e.persistSession()
		}
		e.mu.Lock()
		e.activationCh <- ev // buffered (size 1); won't block
		close(e.activationCh)
		e.mu.Unlock()
		return
	}
	ch := e.currentTurnEvents
	turnID := e.currentTurnID
	terminal := isTerminalSessionEvent(ev.Type)
	e.mu.Unlock()
	if ch == nil {
		return
	}
	// A turn NOT initiated by the current machine submit (a human turn)
	// carries a different (or empty) turn id. Its events are rendered to
	// the TUI (the human plane) and are NOT part of this submit's stream.
	if ev.TurnID != "" && ev.TurnID != turnID {
		return
	}
	ch <- ev
	if terminal {
		e.mu.Lock()
		if e.currentTurnEvents == ch {
			e.currentTurnEvents = nil
			e.currentTurnID = ""
			if e.turnDone != nil {
				close(e.turnDone)
				e.turnDone = nil
			}
		}
		e.mu.Unlock()
		e.state.clearMachineTurn()
	}
}

// cleanupOnExit runs when the process exits: it reaps the process (single
// Wait owner — this goroutine read all of the events file), drops the
// endpoint record, and signals any waiting turn. The turn is "cut off" (no
// terminal event) — it is marked endpoint-gone so the blocked Submit returns
// session.ErrEndpointGone and the Manager re-activates (resuming the
// materialised session) and retries the logical submit. It must NOT look
// like a settled turn: that is what left an instance persisted as working
// with no endpoint.
func (e *qwenEndpoint) cleanupOnExit() {
	if e.h != nil {
		e.h.Wait()
	}
	// Drop THIS endpoint's record (so Live() reports it gone and Submit
	// cannot find a dead endpoint). It runs AFTER the reap (so the
	// supervisor is already clean).
	e.f.dropEndpointRef(e)
	// Signal any in-flight turn so its Submit returns (the Manager settles
	// the session).
	e.mu.Lock()
	if e.currentTurnEvents != nil {
		e.currentTurnEvents = nil
		e.currentTurnID = ""
		// The turn is being cut off by the process death, not settled by a
		// terminal runtime event. Set the reason BEFORE closing turnDone so
		// the woken Submit observes it. Guarded by currentTurnEvents: a turn
		// that routeEvent already settled (nil currentTurnEvents, flag left
		// false) must not be reclassified as endpoint-gone after the fact.
		e.turnEndpointGone = true
	}
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
	// Close the input file.
	e.inputMu.Lock()
	if e.inputFile != nil {
		e.inputFile.Close()
		e.inputFile = nil
	}
	e.inputMu.Unlock()
}

// stopEndpoint terminates the instance's endpoint (TERM → grace → KILL via
// the supervisor) and drops its state. The qwen chat recording persists the
// session on disk, so the session survives for a later resume (invariant F).
func (q *QwenPersistent) stopEndpoint(instanceID string) error {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	if e == nil {
		return nil
	}
	lif := q.life.get()
	if el, ok := lif.(proc.EndpointLifecycle); ok {
		el.StopEndpoint(instanceID)
	}
	// Wait for the process to be reaped (bounded), then drop the state.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !e.live() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	q.dropEndpoint(instanceID)
	return nil
}

func (q *QwenPersistent) dropEndpoint(instanceID string) {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	delete(q.endpoints, instanceID)
	q.mu.Unlock()
	if e != nil {
		// Best-effort: ensure the process is terminated and reaped.
		if e.h != nil {
			e.h.Close()
		}
	}
}

// dropEndpointRef removes a SPECIFIC endpoint record (the one whose reader
// hit exit) from the registry, without touching any other endpoint for the
// same instance. A concurrent re-activation may have already launched a
// fresh endpoint for the instance; this must not drop it. It is the
// exit-path cleanup: the dying endpoint's reader is the single owner of
// this record, and it runs AFTER the reap (so the supervisor is already
// clean).
func (q *QwenPersistent) dropEndpointRef(e *qwenEndpoint) {
	q.mu.Lock()
	if q.endpoints[e.instanceID] == e {
		delete(q.endpoints, e.instanceID)
	}
	q.mu.Unlock()
}

// modelFor resolves the launch model (B9): the session's launch model > the
// driver's field > the PAGNET_QWEN_MODEL env > "" (the user default).
func (q *QwenPersistent) modelFor(sess *session.RuntimeSession) string {
	if sess != nil && sess.Model != "" {
		return sess.Model
	}
	if q.Model != "" {
		return q.Model
	}
	return os.Getenv("PAGNET_QWEN_MODEL")
}

// stateDir is where the qwen dual-output endpoint keeps its sidecar files
// (under the pagnet state dir, never the workspace — §44).
func (q *QwenPersistent) stateDir() string {
	if d := os.Getenv("PAGNET_STATE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "pagnet")
}

// binary resolves the qwen CLI path: the explicit field, then PATH, then
// next to the current executable.
func (q *QwenPersistent) binary() (string, error) {
	if q.Binary != "" {
		if _, err := os.Stat(q.Binary); err == nil {
			return q.Binary, nil
		}
	}
	if p, err := exec.LookPath("qwen"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "qwen")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("qwen CLI not found on PATH")
}

// --- session metadata persistence (B3 / R6) ----------------------------------

// writeStoredQwenSession persists the qwen session id + exact cwd (0600,
// atomic). The cwd is the resume anchor (doc §5.3): a cwd drift makes the
// resume look like a lost session, so it is stored byte-exact and asserted
// at resume time.
func writeStoredQwenSession(path, id, cwd string) error {
	b, _ := json.Marshal(struct {
		SessionID string `json:"sessionId"`
		CWD       string `json:"cwd"`
	}{SessionID: id, CWD: cwd})
	return atomicWriteFile(path, append(b, '\n'), 0o600)
}

// readStoredQwenSession loads the persisted qwen session id + cwd.
func readStoredQwenSession(path string) (id, cwd string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var s struct {
		SessionID string `json:"sessionId"`
		CWD       string `json:"cwd"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(s.SessionID), s.CWD, nil
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex UUID. A non-UUID
// -r argument becomes a silent title lookup (doc §5.2), so the resume id is
// validated client-side before it is passed to the CLI.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	hex := func(i, n int) bool {
		for j := i; j < i+n; j++ {
			c := s[j]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' &&
		hex(0, 8) && hex(9, 4) && hex(14, 4) && hex(19, 4) && hex(24, 12)
}

// readNewLines reads new complete lines from f starting at offset. It
// returns the lines (without the trailing \n), the new offset (after the
// last complete line), and an error. Incomplete trailing data (no \n) is
// left for the next call. A short read is handled: the offset is advanced
// only by the bytes actually consumed, so the unread bytes are re-read on
// the next call.
func readNewLines(f *os.File, offset int64) ([][]byte, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, offset, err
	}
	size := fi.Size()
	if size < offset {
		// The file shrank (should not happen for the events file): reset.
		offset = 0
	}
	if size == offset {
		return nil, offset, nil
	}
	n := int(size - offset)
	data := make([]byte, n)
	m, rerr := f.ReadAt(data, offset)
	if m > 0 {
		data = data[:m]
	}
	if rerr != nil && rerr != io.EOF {
		return nil, offset, rerr
	}
	var lines [][]byte
	rest := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[rest:i])
			rest = i + 1
		}
	}
	return lines, offset + int64(rest), nil
}
