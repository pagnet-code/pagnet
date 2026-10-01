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
//   - B7: the startup budget (no session_start within it = activation
//     failure) is DRIVER-OWNED: QwenPersistent.StartupTimeout, zero = the
//     production default (60s). One activation attempt gets ONE budget,
//     shared by the events-file wait and the handshake wait. It is a
//     startup-only watchdog: the submit correlation deadline and the
//     alertable (surfaced, never a kill) in-flight stall window
//     (qwen_persistent_state.go) are different, untouched watchdogs.
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
	"unicode/utf8"

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

// startupDiagTailBytes bounds the events-file tail carried in the
// startup-timeout diagnostic (the recent lines are what a failure needs;
// the rest is noise).
const startupDiagTailBytes = 240

// startupDiagLineRunes caps one line of the tail so a single huge event
// cannot blow up the error text.
const startupDiagLineRunes = 200

// QwenPersistent is the Qwen Dual Output persistent driver.
type QwenPersistent struct {
	NativeEventObserverFactory session.NativeEventObserverFactory
	// StateDir is immutable host-local storage owned by this driver instance.
	// Explicit ownership avoids process-global environment routing across workers.
	StateDir string
	// Binary is the path to the qwen executable. When empty it is resolved
	// from PATH / next to the current executable.
	Binary string
	// PrefixArgs and NativeDirs are immutable host-local execution profile settings.
	PrefixArgs []string
	NativeDirs []string
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
	// StartupTimeout is this driver's STARTUP budget: how long a launched
	// qwen process may take to complete the session_start handshake before
	// the activation fails. Zero means the production default (see
	// effectiveStartupTimeout) — the daemon deliberately leaves it unset.
	// It bounds ONLY the startup stage: it is not the submit correlation
	// deadline, not the in-flight stall window, and not a turn deadline.
	// It is owned by this driver: the fake persistent driver's test deadline
	// must not (and can no longer) decide when a real qwen startup is killed.
	StartupTimeout time.Duration
	// PTYAvailable is invoked (from the launch path, BEFORE the
	// handshake/session_start wait, and without the driver mutex held)
	// the moment the endpoint's PTY master becomes available, so the
	// daemon's terminal plane can start reading it immediately. A TUI
	// renders to its PTY before session_start: without a reader from the
	// first byte the kernel PTY buffer fills and the TUI blocks in write(),
	// starving the very session_start this activation waits for (the
	// 60s-budget activation deadlock). Nil = no observer (tests that
	// don't set it). The observer takes terminal-manager locks, so the
	// hook is fired outside this driver's critical sections — never call
	// it while holding q.mu.
	PTYAvailable func(instanceID string, master *os.File)

	life lifecycleState

	mu        sync.Mutex
	endpoints map[string]*qwenEndpoint
}

// NewQwenPersistent builds a Qwen Dual Output persistent driver.
func NewQwenPersistent(binary string) *QwenPersistent {
	return &QwenPersistent{Binary: binary, endpoints: map[string]*qwenEndpoint{}}
}

// startupTimeout is this driver's resolved startup budget (zero field = the
// production default). Tests set StartupTimeout directly to keep the startup
// scenarios deterministic.
func (q *QwenPersistent) startupTimeout() time.Duration {
	return effectiveStartupTimeout(q.StartupTimeout)
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
		// The activation context was cancelled: retire THIS endpoint
		// (pointer-specific detach + bounded termination request). This
		// path must NOT reap — the reader is the single Wait owner, and
		// blocking here on the process's exit would hold the Manager's
		// activation lock forever on an unkillable process (B7).
		q.retireEndpoint(e)
		return nil, ctx.Err()
	case <-time.After(time.Until(e.startupDeadline)):
		// B7: no session_start within the startup budget is an
		// activation failure, not a hang. The timer runs out the ONE
		// deadline this endpoint was launched with (shared with the
		// reader's events-file wait — see qwenEndpoint.startupDeadline),
		// never a fresh budget. Compute the startup diagnostic BEFORE
		// retiring: the process state must reflect the deadline moment (the
		// retirement below requests termination, which a later liveness
		// probe would report as exited). Retire THIS endpoint
		// (pointer-specific detach + bounded termination request); do NOT
		// reap — the reader owns the reap, and this path must return within
		// the startup budget (never the budget + infinity).
		diag := e.startupDiag()
		q.retireEndpoint(e)
		return nil, fmt.Errorf("qwen persistent: activation timed out (no session_start within the %s startup budget); %s", startupBudgetText(e.startupBudget), diag)
	}
	if events != nil {
		events <- actEv
	}
	if actEv.Type == session.EventSessionLost {
		// The resume found no usable session (or the handshake gate
		// failed). Retire the endpoint that was just launched for the
		// attempt: detach it from the registry and request bounded
		// termination. The reader owns the reap — a lost resume never
		// leaves a stale endpoint in the registry, and this path never
		// blocks on the process's exit.
		q.retireEndpoint(e)
		return nil, session.ErrSessionLost
	}
	// The driver sets sess.NativeID as the native exchange happens (the
	// Driver contract). This write is serialized by the Manager's
	// per-instance activation lock (EnsureActive holds it across this
	// call), so the Manager's locked NativeID query — which takes the same
	// lock — is race-free against it.
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
			// is NOT a settled turn. Which error applies depends on the
			// runtime's OWN acceptance signal — the echoed `user` event for
			// the submitted text (submitDelivered, which also produced
			// EventTurnStarted):
			//
			//   - NOT delivered: the runtime never accepted the turn — no
			//     work was consumed. ErrEndpointGone: the Manager
			//     re-activates (resuming the materialised session) and
			//     retries the logical submit once.
			//   - delivered: the runtime ACCEPTED the turn and died before
			//     a terminal result — its outcome may be partially applied.
			//     ErrTurnInterrupted: the Manager MUST NOT re-submit it.
			//
			// submitDelivered is safe to read here: the reader's best-effort
			// final read (which can still set it) runs BEFORE cleanupOnExit
			// closes turnDone, and a normally-settled turn already cleared
			// it (routeEvent's terminal path) — and the gone flag is false
			// on that path anyway.
			//
			// Reporting nil here is what wedged an instance as permanently
			// working with no live endpoint.
			if e.state.isSubmitDelivered() {
				return session.ErrTurnInterrupted
			}
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
	if q.ActiveWork(sess.InstanceID) {
		return session.ErrBusy
	}
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
	nativeObserver session.NativeEventObserver
	f              *QwenPersistent // back-reference (the reader's exit path drops this record)
	instanceID     string
	stateDir       string
	h              *proc.Handle // set once at launch, never nilled (immutable)
	eventsPath     string
	inputPath      string
	state          *qwenTurnState

	// activationCh carries the process's first (activation) event; closed
	// by the reader after it is delivered.
	activationCh chan session.SessionEvent
	// startupBudget is the driver's resolved startup budget for THIS
	// activation attempt and startupDeadline the absolute instant it
	// expires (launch time + budget). BOTH stages that wait for the
	// handshake — the reader's events-file wait and Activate's activation-
	// event wait — observe this ONE deadline: one activation attempt gets
	// one maximum startup budget, never one budget per waiting stage (two
	// independent timers would double the real limit and let the surfaced
	// error text lie about it). Set once at launch, immutable after.
	startupBudget   time.Duration
	startupDeadline time.Time
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
	// When true, Submit further consults the machine-turn state's
	// submitDelivered (the echoed `user` event / EventTurnStarted signal)
	// to classify the death: accepted → ErrTurnInterrupted (never
	// auto-retried), not accepted → ErrEndpointGone (one safe retry).
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

// startupDiag reports the two diagnostic facts the driver OWNS at the
// startup-timeout moment: the events-file state (absent, or its size + a
// bounded log-safe tail) and the process liveness, as one short line
// ("events_file=...; process=..."). The activation timeout error carries
// it, so a "no session_start within the startup budget" failure is never
// a black box: the file-appeared-but-handshake-never-arrived case (the TUI
// stuck in a pre-session state, e.g. first-run onboarding) is distinguishable
// from the bridge never opening the file and from the process dying. The
// text is self-explanatory and log-safe: no newlines, no absolute paths
// (the tail content is the qwen bridge's own event output, which is fine).
func (e *qwenEndpoint) startupDiag() string {
	return e.eventsFileDiag() + "; process=" + e.processStateDiag()
}

// processStateDiag renders the endpoint's process liveness as the
// diagnostic suffix value ("alive" / "exited").
func (e *qwenEndpoint) processStateDiag() string {
	if e.processGone() {
		return "exited"
	}
	return "alive"
}

// eventsFileDiag renders the events-file fact for the diagnostic:
// "events_file=absent" when the file does not exist, otherwise
// "events_file=<N bytes, tail=\"...\">".
func (e *qwenEndpoint) eventsFileDiag() string {
	fi, err := os.Stat(e.eventsPath)
	if err != nil {
		return "events_file=absent"
	}
	return fmt.Sprintf("events_file=%d bytes, tail=%q", fi.Size(), e.eventsFileTail(fi.Size()))
}

// eventsFileTail reads up to startupDiagTailBytes from the END of the
// events file and renders it log-safe (see sanitizeDiagTail). It is a plain
// bounded read from a FRESH open (one ReadAt at a computed offset) —
// independent of the reader's own open file and read offset, so it is
// race-safe against the readLoop's concurrent read of the same file; no
// lock is added that the readLoop would have to take. Best-effort: any
// read problem yields "" (the size is already reported).
func (e *qwenEndpoint) eventsFileTail(size int64) string {
	if size <= 0 {
		return ""
	}
	n := size
	if n > startupDiagTailBytes {
		n = startupDiagTailBytes
	}
	f, err := os.Open(e.eventsPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, n)
	m, rerr := f.ReadAt(b, size-n)
	if m > 0 {
		b = b[:m]
	}
	if rerr != nil && rerr != io.EOF {
		return ""
	}
	return sanitizeDiagTail(b)
}

// sanitizeDiagTail renders a bounded events-file tail as a log-safe
// fragment: non-printable characters (including newlines) become spaces,
// and any single line longer than startupDiagLineRunes is truncated. The
// result never contains a newline and stays bounded.
func sanitizeDiagTail(b []byte) string {
	// A byte-bounded cut may split a multi-byte UTF-8 rune at the end:
	// drop the incomplete fragment (an invalid lone byte decodes as
	// RuneError of width 1) so the tail stays valid UTF-8.
	for len(b) > 0 {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size > 1 {
			break
		}
		b = b[:len(b)-1]
	}
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		runes := []rune(line)
		if len(runes) > startupDiagLineRunes {
			runes = runes[:startupDiagLineRunes]
		}
		for j, r := range runes {
			if !diagTailPrintable(r) {
				runes[j] = ' '
			}
		}
		lines[i] = string(runes)
	}
	return strings.Join(lines, " ")
}

// diagTailPrintable reports whether a rune is safe to keep in a
// log/console diagnostic line: ASCII printable, or a non-ASCII rune outside
// the C0/C1 control blocks and the Unicode line separators (everything else
// becomes a space).
func diagTailPrintable(r rune) bool {
	if r >= 0x20 && r <= 0x7E {
		return true
	}
	if r < 0xA0 {
		return false // C0 controls, DEL, C1 controls
	}
	return r != 0x2028 && r != 0x2029
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
	// S2: the per-instance scratch (TMPDIR) must exist before launch —
	// the sandbox wrapper refuses a missing granted path (fail closed).
	if _, err := ensureScratch(stateDir); err != nil {
		return nil, err
	}
	// S2: the runtime's own native state dir (~/.qwen — the SAME list the
	// launch spec grants) is a mandatory RW grant; the launch path
	// guarantees its existence (H3), including on first use.
	if err := ensureNativeDirs(profileNativeDirs(q.NativeDirs, homeNativeDirs(".qwen"))...); err != nil {
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
	// Standing context (instruction-model Wave 3): the managed standing
	// document (the pagnet overlay + the operator's standing instruction
	// when set) rides Qwen's NATIVE standing surface — --append-system-
	// prompt, which APPENDS to Qwen's built-in system prompt (NOT
	// --system-prompt, which would replace the vendor prompt). It is FIXED
	// AT LAUNCH (session.RuntimeSession.StandingInstructions): the Manager
	// restarts the endpoint when it changes. Qwen's native QWEN.md /
	// AGENTS.md discovery keeps working — pagnet never writes into the
	// workspace.
	if sess.StandingInstructions != "" {
		args = append(args, "--append-system-prompt", sess.StandingInstructions)
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

	cmd := exec.Command(bin, append(append([]string(nil), q.PrefixArgs...), args...)...)
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
	// S2: TMPDIR is the per-instance scratch (an explicit pair — it
	// overrides any inherited TMPDIR whose target is not in the sandbox
	// allowlist).
	env = append(env, "TMPDIR="+scratchPath(stateDir))
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
	// S2: the per-instance sandbox allowlist (H4) — the endpoint driver
	// is not a turn-class Adapter, so the spec is built here from the
	// session: the workspace + this per-instance state dir as RW, the
	// runtime's OWN native state (~/.qwen) as RW, the coarse system read
	// + binary support paths as RO, and the daemon bridge socket
	// (recovered from the session's PAGNET_MCP_CONFIG). The daemon's
	// state dir is never a grant — only the socket's traversal chain
	// reaches it. The supervisor wraps the Start on sandbox-requiring
	// platforms and refuses the launch (fail closed) when the sandbox
	// cannot be applied (H2/H3).
	sb := driverSandbox(driverSandboxOpts{
		workspace:  sess.Workspace,
		stateDir:   stateDir,
		nativeDirs: profileNativeDirs(q.NativeDirs, homeNativeDirs(".qwen")),
		binary:     bin,
		env:        sess.Env,
		denied:     sess.SandboxDenied,
	})
	// The endpoint is LONG-LIVED: it must survive across turns (the whole
	// point of the persistent model). The launch ctx must NOT be a turn's
	// ctx (cancelled at turn end) — it is the driver's own lifetime.
	//
	// The ONE startup budget for this activation attempt: an absolute
	// deadline fixed at launch and observed by BOTH the reader's events-file
	// wait and Activate's activation-event wait (see
	// qwenEndpoint.startupDeadline). It is taken BEFORE the process is
	// spawned so the spawn itself is inside the budget — the production cold
	// start that motivated this fix was slow before the first event, not
	// after it.
	startupBudget := q.startupTimeout()
	startupDeadline := time.Now().Add(startupBudget)
	h, err := el.Launch(context.Background(), proc.LaunchRequest{
		InstanceID: sess.InstanceID,
		TurnID:     "endpoint",
		Runtime:    string(q.Name()),
		Class:      proc.ClassEndpoint,
		Cmd:        cmd,
		Marker:     "PAGNET_INSTANCE_ID=" + sess.InstanceID,
		PTYSize:    ws,
		PTYStdio:   true, // the TUI renders to the PTY (B1)
		Sandbox:    sb,
	})
	if err != nil {
		inputFile.Close()
		return nil, err
	}

	e := &qwenEndpoint{
		f:               q,
		instanceID:      sess.InstanceID,
		stateDir:        stateDir,
		h:               h,
		eventsPath:      eventsPath,
		inputPath:       inputPath,
		inputFile:       inputFile,
		state:           newQwenTurnState(resuming, resumeID, time.Now),
		activationCh:    make(chan session.SessionEvent, 1),
		startupBudget:   startupBudget,
		startupDeadline: startupDeadline,
		readerDone:      make(chan struct{}),
	}
	if q.NativeEventObserverFactory != nil {
		e.nativeObserver = q.NativeEventObserverFactory(sess.InstanceID)
	}
	go e.readLoop()
	q.mu.Lock()
	q.endpoints[sess.InstanceID] = e
	q.mu.Unlock()
	// The PTY is live from here: hand the master to the observer BEFORE
	// the handshake/session_start wait so the terminal plane reads it
	// from the first byte (the TUI renders before session_start — a
	// never-read master deadlocks the activation, see PTYAvailable).
	// Fired after registration (PTYMaster works) and outside q.mu (the
	// observer takes terminal-manager locks — lock ordering); nil-safe,
	// and PTY-less launches do not fire it.
	if q.PTYAvailable != nil && e.h != nil && e.h.PTY() != nil {
		q.PTYAvailable(e.instanceID, e.h.PTY())
	}
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
		// The file never appeared: either the process exited before writing
		// it (e.g. "No saved session found" — exit 1, doc §5.2) or it is
		// still alive but the bridge failed to open it (doc §7.2: the TUI
		// continues without dual output). Signal the activation as lost.
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
		// If the process is still alive, request bounded termination FIRST
		// (TERM → grace → KILL through the supervisor). The owner Wait in
		// cleanupOnExit must never block on a process that was never
		// stopped: without this, cmd.Wait on a live process hangs forever
		// (the B7 lifecycle defect). The Wait is allowed to wait in THIS
		// background reader goroutine — it holds no Manager activation
		// lock, daemon FIFO, or attach request. If the process cannot be
		// killed, the supervisor keeps tracking it and this Wait waits in
		// the background; the activation has already returned its failure.
		if !e.processGone() {
			e.f.requestEndpointStop(e)
		}
		e.cleanupOnExit()
		return
	}
	defer f.Close()
	offset := int64(0)
	for {
		// Read new complete lines.
		previousOffset := offset
		lines, newOffset, readErr := readNewLines(f, offset)
		offset = newOffset
		for _, line := range lines {
			e.handleEventLine(line)
		}
		// Watchdog (B6 / B7): check the time-based conditions (submit
		// correlation deadline, in-flight stall).
		for _, ev := range e.state.tick() {
			e.routeEvent(ev)
		}
		if readErr != nil {
			// Stop this exact owned generation before cleanup observes its reap.
			// A live process must not wedge the native reader in Handle.Wait.
			e.f.requestEndpointStop(e)
			e.cleanupOnExit()
			return
		}

		if e.processGone() {
			// Bounded batches preserve every complete backlog line, including the
			// final turn completion; no second-read-only truncation on natural exit.
			for {
				remaining, next, err := readNewLines(f, offset)
				for _, line := range remaining {
					e.handleEventLine(line)
				}
				if err != nil || next == offset {
					break
				}
				offset = next
			}
			e.cleanupOnExit()
			return
		}

		if newOffset > previousOffset {
			continue
		}
		time.Sleep(eventPollInterval)
	}
}

// waitForEventsFile waits for the events file to appear (the bridge opens
// it at startup). It returns the opened file, or an error when the file
// does not appear within the endpoint's startup deadline (the bridge failed
// to open it — doc §7.2: the TUI continues without dual output) or the
// process exits first (e.g. "No saved session found" — exit 1, doc §5.2).
//
// The deadline is the endpoint's ONE startup deadline (fixed at launch), not
// a fresh budget: the process-exit check below is what keeps an early death
// fast — this loop returns as soon as the process is gone, long before the
// deadline expires.
func (e *qwenEndpoint) waitForEventsFile() (*os.File, error) {
	for time.Now().Before(e.startupDeadline) {
		if e.processGone() {
			return nil, errors.New("qwen process exited before the event file appeared")
		}
		f, err := os.Open(e.eventsPath)
		if err == nil {
			return f, nil
		}
		time.Sleep(eventPollInterval)
	}
	// The file-absence fact is already in the message — only the process
	// state is appended (the driver owns both facts at this moment).
	return nil, fmt.Errorf("qwen event file did not appear within the %s startup budget; process=%s", startupBudgetText(e.startupBudget), e.processStateDiag())
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
	if e.nativeObserver != nil {
		if err := e.nativeObserver(ev); err != nil {
			return
		}
	}
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

// cleanupOnExit runs from the reader goroutine when the process exits: it
// REAPS the process (this goroutine is the single Wait owner — the ONLY Qwen
// driver path that calls Handle.Wait), drops the endpoint record, and
// signals any waiting turn. The Wait is the single-owner reap: it is allowed
// to block in this background reader goroutine (it holds no Manager
// activation lock, daemon FIFO, or attach request), but no activation/stop
// path may call it — that is what wedged the daemon on an unkillable process
// (B7). When the process cannot be killed, this Wait waits in the background
// and the supervisor keeps tracking the process; the activation has already
// returned its failure.
//
// The turn is "cut off" (no terminal event) — it is marked endpoint-gone so
// the blocked Submit classifies the death from the machine-turn state's
// submitDelivered: accepted → session.ErrTurnInterrupted (surfaced, never
// auto-retried), not accepted → session.ErrEndpointGone (the Manager
// re-activates — resuming the materialised session — and retries the logical
// submit once). It must NOT look like a settled turn: that is what left an
// instance persisted as working with no endpoint.
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

// stopEndpoint terminates the instance's endpoint and drops its state. The
// qwen chat recording persists the session on disk, so the session survives
// for a later resume (invariant F).
//
// Contract (B7 lifecycle): this path REQUESTS bounded termination (TERM →
// grace → KILL through the supervisor) and observes the reader's reap for a
// bounded period; it does NOT reap. The reader is the single Wait owner —
// it reaps the process after it exits and drops the endpoint record. When
// the process cannot be killed, the reader keeps polling (it does not block
// this stop) and the supervisor keeps tracking the process: the honest
// result is a bounded stop, never a wedge, and never a Close/Wait fallback
// that could block forever on an unkillable process.
func (q *QwenPersistent) stopEndpoint(instanceID string) error {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	if e == nil {
		return nil
	}
	// Request bounded termination (TERM → grace → KILL). It returns within
	// the termination grace window and does not wait on the exit.
	q.requestEndpointStop(e)
	// Bounded observation of the reader's reap: when the process is
	// killable, the reader reaps it promptly and drops the endpoint record
	// (so the detach below is a no-op). When it cannot be killed, the
	// reader keeps polling and this observation expires — the stop still
	// returns, bounded.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !e.live() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Detach the endpoint record (pointer-specific — never a newer endpoint
	// for the same instance). The supervisor continues tracking the process
	// until the reader reaps it.
	q.dropEndpointRef(e)
	return nil
}

// requestEndpointStop requests bounded termination of the endpoint's process
// group through the supervisor (TERM → grace → KILL). It is the "request
// termination" half of the lifecycle — never the reap. The endpoint's reader
// goroutine is the single Wait owner and reaps after the process exits; the
// supervisor continues tracking the process until that reap. This call
// returns within the termination grace window (bounded), even when the
// process cannot be killed (the supervisor then keeps tracking it). It must
// never call Handle.Wait/Close: that would conflate termination with the
// single-owner reap and could block the caller forever.
func (q *QwenPersistent) requestEndpointStop(e *qwenEndpoint) {
	if e == nil {
		return
	}
	if e.h != nil {
		// The immutable handle fences the process generation. A delayed old reader
		// must never stop a replacement endpoint selected only by instance ID.
		_ = e.h.Terminate("native_endpoint_stop")
	}
}

// retireEndpoint retires a SPECIFIC endpoint after a failed activation
// (timeout, context cancel, or a lost session): it detaches the endpoint
// from the registry (pointer-specific — it never removes a newer endpoint
// for the same instance) and requests bounded termination of its process
// group. It does NOT reap: the reader is the single Wait owner. This is the
// activation-failure cleanup — it must return within a bounded time (the
// termination grace window) and must never block on the process's exit, so
// the Manager's activation lock is always released.
func (q *QwenPersistent) retireEndpoint(e *qwenEndpoint) {
	if e == nil {
		return
	}
	q.dropEndpointRef(e)
	q.requestEndpointStop(e)
}

// dropEndpointRef removes a SPECIFIC endpoint record from the registry,
// without touching any other endpoint for the same instance. A concurrent
// re-activation may have already launched a fresh endpoint for the instance;
// this must not drop it. It is used by two paths:
//   - the reader's exit path (cleanupOnExit), which runs AFTER the reap (the
//     supervisor is already clean); and
//   - the activation-failure / stop paths (retireEndpoint, stopEndpoint),
//     which run BEFORE the reap — they retire the logical record while the
//     supervisor still tracks the (possibly unkillable) OS process. The
//     supervisor record is the safety mechanism that prevents a second
//     endpoint for the instance, and only the reader's reap removes it.
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
	if q.StateDir != "" {
		return q.StateDir
	}
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
	return AtomicWriteFile(path, append(b, '\n'), 0o600)
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
const maxQwenNativeLineBytes = 16 << 20
const qwenNativeReadBatchBytes = 4 << 10
const maxQwenNativeBatchLines = 256

var errQwenNativeLineTooLarge = errors.New("qwen native event exceeds the 16 MiB frame limit")

func readNewLines(f *os.File, offset int64) ([][]byte, int64, error) {
	if offset < 0 {
		return nil, offset, errors.New("invalid qwen event cursor")
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, offset, err
	}
	size := fi.Size()
	if size < offset {
		// A sidecar is append-only for this native generation. Resetting the
		// cursor would replay old effects into an already-live turn ledger.
		return nil, offset, errors.New("qwen native event file shrank behind its cursor")
	}
	if size == offset {
		return nil, offset, nil
	}
	// Read a small batch first. Only one incomplete valid large frame can grow
	// this buffer; the whole unread file and millions of empty lines never do.
	target := int64(qwenNativeReadBatchBytes)
	for {
		count := min(size-offset, target)
		data := make([]byte, int(count))
		read, err := f.ReadAt(data, offset)
		data = data[:read]
		if err != nil && err != io.EOF {
			return nil, offset, err
		}
		lines := make([][]byte, 0, min(maxQwenNativeBatchLines, read/2))
		start := 0
		for index, value := range data {
			if index-start > maxQwenNativeLineBytes {
				return lines, offset + int64(start), errQwenNativeLineTooLarge
			}
			if value == '\n' {
				if index-start > maxQwenNativeLineBytes {
					return lines, offset + int64(start), errQwenNativeLineTooLarge
				}
				lines = append(lines, data[start:index])
				start = index + 1
				if len(lines) == maxQwenNativeBatchLines {
					return lines, offset + int64(start), nil
				}
			}
		}
		if start > 0 {
			return lines, offset + int64(start), nil
		}
		if len(data) > maxQwenNativeLineBytes {
			return nil, offset, errQwenNativeLineTooLarge
		}
		if int64(read) < target || size-offset <= target {
			return nil, offset, nil
		}
		target = min(target*2, int64(maxQwenNativeLineBytes+1))
	}
}

// ActiveWork reads the native structured turn ledger, including human turns.
func (q *QwenPersistent) ActiveWork(instanceID string) bool {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	return e != nil && e.state.activeWork()
}

func (q *QwenPersistent) Materialised(instanceID string) bool {
	q.mu.Lock()
	e := q.endpoints[instanceID]
	q.mu.Unlock()
	if e == nil {
		return false
	}
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return e.state.materialised
}
