package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// activationTimeout bounds how long Activate waits for the endpoint process
// to emit its activation event (session.started / resumed / lost). A process
// that starts but never reports is a failure, not a hang.
const activationTimeout = 15 * time.Second

// PersistentFake is the deterministic FAKE PERSISTENT runtime driver
// (runtime-lifecycle refactor, Phase 1). It is the reference implementation
// of the persistent model: ONE long-lived endpoint process per instance that
// services many logical submits over a stdin control channel and streams
// structured events on stdout. It implements the generic session.Driver
// contract, so the daemon drives it through the session core
// (EnsureActive + Submit + consume normalized events) exactly the way it
// will drive the real vendors in later phases.
//
// It is a REAL process (not a test double with stubs): the
// pagnet-fake-runtime helper is launched in --persistent mode, persists a
// session file, and genuinely resumes it. The PAGNET_FAKE_* env knobs
// (interaction, rate-limit, resume-fail) script its behavior deterministically.
//
// It is registered ONLY in debug mode (like the process-per-turn Fake) and
// is NOT a real agent runtime.
type PersistentFake struct {
	// Binary is the path to the pagnet-fake-runtime helper. When empty it
	// is resolved from PATH / next to the current executable.
	Binary string
	// Env is appended to the inherited environment for the endpoint
	// process (E2E simulation knobs, e.g. PAGNET_FAKE_INTERACTION).
	Env []string
	// PTYSize, when non-nil, makes each endpoint OWN its TUI PTY (Phase 3
	// terminal session unification): the supervisor launches the endpoint
	// with the PTY slave as its controlling terminal (the human plane)
	// while the stdin/stdout pipes remain the machine plane. nil keeps the
	// pre-Phase-3 shape (no PTY; the fake's TUI degrades off).
	PTYSize *pty.Winsize

	life lifecycleState

	mu        sync.Mutex
	endpoints map[string]*persistEndpoint
}

// NewPersistentFake builds a fake persistent driver.
func NewPersistentFake(binary string) *PersistentFake {
	return &PersistentFake{Binary: binary, endpoints: map[string]*persistEndpoint{}}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (f *PersistentFake) SetLifecycle(l proc.Lifecycle) { f.life.SetLifecycle(l) }

// Name is the canonical runtime name.
func (f *PersistentFake) Name() domain.RuntimeName { return domain.RuntimeFakePersistent }

// Capabilities is the probed capability set. The fake persistent runtime
// advertises the full persistent surface it actually implements (honest
// capability advertisement — addendum §15/§17).
func (f *PersistentFake) Capabilities() session.Capabilities {
	return session.Capabilities{
		PersistentEndpoint:          true,
		MultipleSessionsPerEndpoint: false, // one session per endpoint (v1)
		StructuredEvents:            true,
		NativeSubmit:                true,
		NativeQueueWhileBusy:        false, // pagnet owns serialisation
		NativeSteer:                 false,
		Interrupt:                   false,
		NativeInteractionObserve:    true,
		RemoteInteractionResolve:    true,
		// Phase 3 (terminal session unification): the persistent endpoint
		// OWNS a native TUI on its controlling terminal (the fake's
		// deterministic line-mode TUI on /dev/tty). The daemon's terminal
		// plane attaches a human to that PTY instead of spawning a second
		// interactive process.
		NativeTUI:                       true,
		SecondClientTerminalAttach:      false,
		TerminalAttachmentFullAuthority: false,
		LiveExternalAdoption:            false,
		ResumeExternalSession:           false,
		NativeSessionDiscovery:          false,
		DynamicModelChange:              false,
		DynamicMCPInjection:             false,
	}
}

// --- session.Driver implementation -----------------------------------------

// Activate starts (cold) or resumes the endpoint for the session. It is
// idempotent: a live endpoint is returned unchanged. A resume of a
// non-materialised session is refused (ErrNotMaterialised); a resume with no
// usable native session is ErrSessionLost.
func (f *PersistentFake) Activate(ctx context.Context, sess *session.RuntimeSession, events chan<- session.SessionEvent) (*session.RuntimeEndpoint, error) {
	f.mu.Lock()
	if e, ok := f.endpoints[sess.InstanceID]; ok && e.live() {
		f.mu.Unlock()
		return e.endpointInfo(sess), nil
	}
	f.mu.Unlock()

	// Resume gate (mirrors the Manager's gate; defense-in-depth for
	// standalone use).
	if sess.NativeID != "" && !sess.Materialised {
		return nil, session.ErrNotMaterialised
	}

	e, err := f.launchEndpoint(sess)
	if err != nil {
		return nil, err
	}

	// Read the activation event (the process's first output line).
	var actEv session.SessionEvent
	select {
	case actEv = <-e.activationCh:
	case <-ctx.Done():
		f.dropEndpoint(sess.InstanceID)
		return nil, ctx.Err()
	case <-time.After(activationTimeout):
		f.dropEndpoint(sess.InstanceID)
		return nil, errors.New("persistent fake: activation timed out")
	}
	if events != nil {
		events <- actEv
	}
	if actEv.Type == session.EventSessionLost {
		// The resume found no usable session. The endpoint that was just
		// launched for the attempt must be fully stopped AND reaped (not
		// just best-effort dropped) so a lost resume never leaves a stale
		// endpoint in the supervisor's registry: stopEndpoint runs the
		// TERM → grace → KILL sequence (a no-op when the process already
		// exited on its own), waits for the reap, and drops the record.
		f.stopEndpoint(sess.InstanceID)
		return nil, session.ErrSessionLost
	}
	sess.NativeID = actEv.SessionID
	return e.endpointInfo(sess), nil
}

// Submit delivers one logical input (a prompt or an interaction resolution)
// into the session's live endpoint. For a prompt it blocks until the turn
// settles (the reader signals turnDone on the terminal event); for an
// interaction it writes the answer and returns (the in-flight turn's stream
// carries the interaction.resolved + terminal events).
func (f *PersistentFake) Submit(ctx context.Context, sess *session.RuntimeSession, req session.SubmitRequest, events chan<- session.SessionEvent) error {
	f.mu.Lock()
	e := f.endpoints[sess.InstanceID]
	f.mu.Unlock()
	if e == nil || !e.live() {
		// The endpoint is gone (dropped by the reader's EOF path on an
		// unexpected death, or never launched). This is NOT a runtime turn
		// failure: the Manager re-activates and retries the submit.
		return session.ErrEndpointGone
	}
	if req.Kind == session.SubmitInteraction {
		e.mu.Lock()
		turnID := e.currentTurnID
		e.mu.Unlock()
		cmd := persistCmd{
			Type: "interaction", TurnID: turnID,
			InteractionID: req.InteractionID, Decision: req.Decision, Answer: req.Answer,
		}
		if err := e.writeCmd(cmd); err != nil {
			// A write to the stdin pipe fails only when the reader end is
			// closed — the process is dead. Report it as endpoint-gone so
			// the Manager re-activates instead of failing the instance.
			return session.ErrEndpointGone
		}
		return nil
	}
	// Prompt: register the turn (the reader sends its events to `events`).
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
	cmd := persistCmd{Type: "submit", TurnID: req.TurnID, Input: req.Input, InputKind: req.InputKind}
	if err := e.writeCmd(cmd); err != nil {
		e.clearTurn()
		// A write to the stdin pipe fails only when the reader end is
		// closed — the process is dead. Report it as endpoint-gone so the
		// Manager re-activates instead of failing the instance.
		return session.ErrEndpointGone
	}
	select {
	case <-done:
		e.mu.Lock()
		gone := e.turnEndpointGone
		e.mu.Unlock()
		if gone {
			// The process DIED mid-turn (the reader's EOF path woke this
			// turn; no terminal event was produced). Not a settled turn: the
			// Manager re-activates and retries the logical submit once.
			return session.ErrEndpointGone
		}
		return nil
	case <-ctx.Done():
		e.clearTurn()
		return ctx.Err()
	}
}

// Hibernate stops the endpoint, preserving the session (the process saves
// its session file on SIGTERM). It is a no-op when no endpoint is live.
func (f *PersistentFake) Hibernate(ctx context.Context, sess *session.RuntimeSession) error {
	return f.stopEndpoint(sess.InstanceID)
}

// Stop terminates the endpoint unconditionally (daemon shutdown / explicit
// stop).
func (f *PersistentFake) Stop(instanceID string) error {
	return f.stopEndpoint(instanceID)
}

// PID is the endpoint's process id (nil when none).
func (f *PersistentFake) PID(instanceID string) *int {
	f.mu.Lock()
	e := f.endpoints[instanceID]
	f.mu.Unlock()
	if e == nil {
		return nil
	}
	return e.pid()
}

// Live reports whether the instance's endpoint process is still alive. It
// is the liveness probe the Manager consults before trusting a live session
// state: when the endpoint record is absent (dropped by the reader's EOF
// path on an unexpected death) or its reader has hit EOF (the process
// closed its stdout, i.e. exited), the endpoint is gone and the session
// must be re-activated, not wedged.
func (f *PersistentFake) Live(instanceID string) bool {
	f.mu.Lock()
	e := f.endpoints[instanceID]
	f.mu.Unlock()
	return e != nil && e.live()
}

// PTYMaster is the endpoint's TUI PTY master (the human plane) — nil when
// the endpoint is not live or was launched without a PTY (the pre-Phase-3
// shape). It implements the session.PTYOwner interface so the daemon's
// terminal plane can attach a human to the ENDPOINT'S OWN PTY instead of
// spawning a second interactive process. The master is owned by the
// process handle: callers hold it as a VIEW and never close it (the
// handle closes it at cleanup; a closed master is EOF to the view, which
// tears the view down observationally).
func (f *PersistentFake) PTYMaster(instanceID string) *os.File {
	f.mu.Lock()
	e := f.endpoints[instanceID]
	f.mu.Unlock()
	if e == nil || !e.live() || e.h == nil {
		return nil
	}
	return e.h.PTY()
}

// Available reports whether the fake runtime's binary is resolvable (the
// session-core analogue of the Adapter.Available method, used by the daemon
// at launch to fail fast when the helper is missing).
func (f *PersistentFake) Available() bool {
	_, err := f.binary()
	return err == nil
}

// BinaryPath reports the resolved path of the fake runtime's binary (same
// resolution as Available). It is the session-core analogue of the
// Adapter.BinaryPath method: the daemon's inventory reports the persistent
// runtime with the SAME shape as the process-per-turn runtimes.
func (f *PersistentFake) BinaryPath() (string, bool) {
	p, err := f.binary()
	return p, err == nil
}

// --- endpoint lifecycle ------------------------------------------------------

// persistEndpoint is one live fake persistent endpoint process.
type persistEndpoint struct {
	f          *PersistentFake // back-reference (the reader's EOF path drops this record)
	instanceID string
	sessionDir string
	h          *proc.Handle // set once at launch, never nilled (immutable)
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     *bytes.Buffer
	// activationCh carries the process's first (activation) event; closed
	// by the reader after it is delivered.
	activationCh chan session.SessionEvent
	// readerDone is closed when the stdout reader exits (the process has
	// exited — its stdout is closed). It is the liveness signal.
	readerDone chan struct{}

	mu                sync.Mutex
	currentTurnID     string
	currentTurnEvents chan<- session.SessionEvent
	turnDone          chan struct{}
	// turnEndpointGone distinguishes WHY turnDone was closed: false = the
	// turn settled on a NORMAL terminal event (routeTurnEvent), true = the
	// endpoint PROCESS DIED mid-turn (the reader's EOF path). Both close the
	// same channel, so without this flag Submit's `case <-done` cannot tell
	// a completed turn from a cut-off one and would report a mid-turn death
	// as a settled submit — which is what leaves an instance persisted as
	// working with no endpoint. Kept in lockstep with QwenPersistent (see
	// qwen_persistent.go); every persistent driver must carry it.
	turnEndpointGone bool

	stdinMu sync.Mutex
}

// live reports whether the endpoint process is still running. The reader
// closes readerDone when it hits EOF (the process closed its stdout, i.e.
// exited), so a closed readerDone means the process is gone.
func (e *persistEndpoint) live() bool {
	select {
	case <-e.readerDone:
		return false
	default:
		return true
	}
}

func (e *persistEndpoint) pid() *int {
	if e.h == nil {
		return nil
	}
	p := e.h.PID()
	if p == 0 {
		return nil
	}
	return &p
}

func (e *persistEndpoint) endpointInfo(sess *session.RuntimeSession) *session.RuntimeEndpoint {
	e.mu.Lock()
	h := e.h
	e.mu.Unlock()
	ep := &session.RuntimeEndpoint{
		ID:        "ep-" + e.instanceID,
		Runtime:   sess.Runtime,
		Ownership: session.OwnershipPagnet,
		Lease:     session.LeaseClaimed,
		Healthy:   true,
		Transport: "stdio",
		Sessions:  []string{sess.NativeID},
		StartedAt: time.Now(),
	}
	if h != nil {
		ep.PID = h.PID()
		ep.PGID = h.PGID()
	}
	return ep
}

func (e *persistEndpoint) writeCmd(cmd persistCmd) error {
	e.stdinMu.Lock()
	defer e.stdinMu.Unlock()
	b, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = e.stdin.Write(b)
	return err
}

// clearTurn resets the in-flight turn state (on a submit failure or ctx
// cancel). It does not close the events channel (the Manager owns that).
func (e *persistEndpoint) clearTurn() {
	e.mu.Lock()
	e.currentTurnEvents = nil
	e.currentTurnID = ""
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
}

// launchEndpoint starts the persistent process through the supervisor
// (ClassEndpoint: long-lived, process-group isolated, one per instance) and
// wires its stdio. The stdout reader is started; it routes the activation
// event to activationCh and subsequent turn events to the current turn.
func (f *PersistentFake) launchEndpoint(sess *session.RuntimeSession) (*persistEndpoint, error) {
	bin, err := f.binary()
	if err != nil {
		return nil, err
	}
	sessionDir := filepath.Join(f.stateDir(), "sessions", sess.InstanceID)
	if err := os.MkdirAll(sessionDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	args := []string{"--persistent", "--instance-id", sess.InstanceID, "--session-dir", sessionDir}
	if sess.NativeID != "" {
		args = append(args, "--resume", sess.NativeID)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = sess.Workspace
	if cmd.Dir == "" {
		cmd.Dir = "."
	}
	// Launch env (Phase 2 / R8): the endpoint child receives the session's
	// launch environment — the generic spec pairs the daemon injects for
	// the instance (identity vars, MCP bridge config, coordination
	// contract). The env is FIXED AT LAUNCH (session.RuntimeSession.Env):
	// a change restarts the endpoint through the Manager; it is never
	// updated per submit.
	//
	// The ownership marker (R1): the endpoint child's environment carries
	// PAGNET_INSTANCE_ID=<id>, the SAME pair the supervisor stores in the
	// ownership record (LaunchRequest.Marker). Every future persistent
	// driver copies this pattern — the marker is the process-tree ownership
	// proof for restart reconciliation and diagnostics. The daemon's spec
	// env already carries it; it is ensured here so standalone use (no
	// spec env) keeps the marker.
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
	// Phase 3 (terminal session unification): when this driver launches the
	// endpoint WITH a TUI PTY (PTYSize non-nil), it tells the fake to turn
	// its TUI on. The fake gates its TUI on this signal (NOT on "is /dev/tty
	// openable"): an endpoint launched WITHOUT a PTY may still inherit a
	// controlling terminal from its parent's session, and that inherited
	// tty is not the endpoint's own TUI — turning the TUI on there would
	// let the human plane (an undrained inherited terminal) block the
	// machine plane. The TUI is a feature of the PTY-owning topology.
	if f.PTYSize != nil {
		env = append(env, "PAGNET_FAKE_TUI=1")
	}
	cmd.Env = ChildEnv(f.Env, env)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	lif := f.life.get()
	el, ok := lif.(proc.EndpointLifecycle)
	if !ok {
		return nil, errors.New("persistent fake: lifecycle does not support endpoints")
	}
	// The endpoint is LONG-LIVED: it must survive across turns (the whole
	// point of the persistent model — 100 turns, 1 process, stable PID).
	// The supervisor's Launch installs a context watcher that terminates
	// the process when the launch ctx is done, so the launch ctx must NOT
	// be the turn's ctx (which is cancelled at turn end) — it is the
	// driver's own lifetime. The endpoint is terminated explicitly (Stop /
	// Hibernate) or by the supervisor's StopAll on daemon shutdown, never
	// by a turn's cancellation. (The turn's ctx still bounds the
	// activation wait in Activate.)
	h, err := el.Launch(context.Background(), proc.LaunchRequest{
		InstanceID: sess.InstanceID,
		TurnID:     "endpoint",
		Runtime:    string(f.Name()),
		Class:      proc.ClassEndpoint,
		Cmd:        cmd,
		Marker:     "PAGNET_INSTANCE_ID=" + sess.InstanceID,
		// Phase 3: when the driver is configured with a PTYSize, the
		// endpoint OWNS its TUI PTY (the supervisor opens the pair and
		// makes the slave the controlling terminal). nil = pre-Phase-3
		// shape (no PTY).
		PTYSize: f.PTYSize,
	})
	if err != nil {
		return nil, err
	}
	e := &persistEndpoint{
		f:            f,
		instanceID:   sess.InstanceID,
		sessionDir:   sessionDir,
		h:            h,
		stdin:        stdin,
		stdout:       stdout,
		stderr:       stderr,
		activationCh: make(chan session.SessionEvent, 1),
		readerDone:   make(chan struct{}),
	}
	go e.readLoop()
	f.mu.Lock()
	f.endpoints[sess.InstanceID] = e
	f.mu.Unlock()
	return e, nil
}

// readLoop reads the endpoint's stdout (JSONL events) and routes them: the
// first event is the activation event (→ activationCh, then closed);
// subsequent events are turn events (→ the current turn's channel). On EOF
// (process gone) it reaps the process (this goroutine is the single Wait
// owner — it read all of stdout) and signals any waiting turn.
func (e *persistEndpoint) readLoop() {
	defer close(e.readerDone)
	scanner := bufio.NewScanner(e.stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	activated := false
	for scanner.Scan() {
		var ev persistWireEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		norm := normalizePersist(ev)
		if !activated {
			activated = true
			e.activationCh <- norm
			close(e.activationCh)
			continue
		}
		e.routeTurnEvent(norm)
	}
	// EOF: the process exited. Reap it FIRST (single Wait owner: this
	// goroutine read all of stdout). The reap unregisters the endpoint
	// from the supervisor, so a concurrent re-activation's launch does not
	// hit ErrInstanceBusy on the (already dead) old endpoint.
	if e.h != nil {
		e.h.Wait()
	}
	// Drop THIS endpoint's record (D1) so Live() reports it gone and
	// Submit cannot find a dead endpoint. This is what makes an unexpected
	// endpoint death transparent: the Manager's next liveness probe sees
	// the endpoint gone and re-activates (resuming the materialised
	// session or cold-starting) instead of wedging. It runs AFTER the
	// reap (above) so a concurrent re-activation is safe to launch a fresh
	// endpoint, and it drops only this record (a concurrent re-activation
	// that already launched a fresh endpoint is left untouched).
	e.f.dropEndpointRef(e)
	// Signal any in-flight turn so its Submit returns (the Manager settles
	// the session). The turn was CUT OFF by the process death, not settled
	// by a terminal event — mark it endpoint-gone so Submit reports
	// session.ErrEndpointGone and the Manager re-activates + retries the
	// logical submit instead of wedging the instance.
	e.mu.Lock()
	if e.currentTurnEvents != nil {
		e.currentTurnEvents = nil
		e.currentTurnID = ""
		// Set the reason BEFORE closing turnDone so the woken Submit
		// observes it. Guarded by currentTurnEvents: a turn routeTurnEvent
		// already settled must not be reclassified after the fact.
		e.turnEndpointGone = true
	}
	if e.turnDone != nil {
		close(e.turnDone)
		e.turnDone = nil
	}
	e.mu.Unlock()
}

func (e *persistEndpoint) routeTurnEvent(norm session.SessionEvent) {
	e.mu.Lock()
	ch := e.currentTurnEvents
	turnID := e.currentTurnID
	e.mu.Unlock()
	if ch == nil {
		return
	}
	// Phase 3 (terminal session unification): a turn NOT initiated by the
	// current machine submit (the TUI's human turn, dispatched through the
	// same in-process turn queue) carries its own turn id. Its events are
	// rendered to the TUI (the human plane) and are NOT part of this
	// submit's stream — forwarding them would cross the streams (a double
	// turn.completed for one submit, an attribution anomaly). The machine
	// plane only ever sees events for the turn it submitted.
	if norm.TurnID != "" && norm.TurnID != turnID {
		return
	}
	ch <- norm
	if isTerminalSessionEvent(norm.Type) {
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
		// The Manager closes the events channel (it owns its lifecycle);
		// the reader only signals turnDone.
	}
}

// stopEndpoint terminates the instance's endpoint (TERM → grace → KILL via
// the supervisor) and drops its state. The process saves its session file
// on SIGTERM, so the session survives for a later resume.
func (f *PersistentFake) stopEndpoint(instanceID string) error {
	f.mu.Lock()
	e := f.endpoints[instanceID]
	f.mu.Unlock()
	if e == nil {
		return nil
	}
	lif := f.life.get()
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
	f.dropEndpoint(instanceID)
	return nil
}

func (f *PersistentFake) dropEndpoint(instanceID string) {
	f.mu.Lock()
	e := f.endpoints[instanceID]
	delete(f.endpoints, instanceID)
	f.mu.Unlock()
	if e != nil {
		// Best-effort: ensure the process is terminated and reaped.
		if e.h != nil {
			e.h.Close()
		}
	}
}

// dropEndpointRef removes a SPECIFIC endpoint record (the one whose reader
// hit EOF) from the registry, without touching any other endpoint for the
// same instance. A concurrent re-activation may have already launched a
// fresh endpoint for the instance; this must not drop it. It is the
// EOF-path cleanup: the dying endpoint's reader is the single owner of this
// record, and it runs AFTER the reap (so the supervisor is already clean).
func (f *PersistentFake) dropEndpointRef(e *persistEndpoint) {
	f.mu.Lock()
	if f.endpoints[e.instanceID] == e {
		delete(f.endpoints, e.instanceID)
	}
	f.mu.Unlock()
}

// stateDir is where the fake persistent endpoint keeps its session files
// (under the pagnet state dir, never the workspace — addendum §44).
func (f *PersistentFake) stateDir() string {
	if d := os.Getenv("PAGNET_STATE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "pagnet")
}

// binary resolves the pagnet-fake-runtime helper path (same resolution as
// the process-per-turn Fake).
func (f *PersistentFake) binary() (string, error) {
	if f.Binary != "" {
		if _, err := os.Stat(f.Binary); err == nil {
			return f.Binary, nil
		}
	}
	if p, err := exec.LookPath("pagnet-fake-runtime"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "pagnet-fake-runtime")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("pagnet-fake-runtime binary not found")
}

// persistCmd is the stdin control-channel command (matches the helper's
// --persistent protocol).
type persistCmd struct {
	Type          string `json:"type"`
	TurnID        string `json:"turnId"`
	Input         string `json:"input,omitempty"`
	InputKind     string `json:"inputKind,omitempty"`
	InteractionID string `json:"interactionId,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Answer        string `json:"answer,omitempty"`
}

// persistWireEvent is the helper's stdout event (the --persistent
// vocabulary, which carries a turnId for routing).
type persistWireEvent struct {
	Event               string          `json:"event"`
	SessionID           string          `json:"sessionId,omitempty"`
	TurnID              string          `json:"turnId,omitempty"`
	Output              string          `json:"output,omitempty"`
	Model               string          `json:"model,omitempty"`
	Kind                string          `json:"kind,omitempty"`
	Error               string          `json:"error,omitempty"`
	RetryAt             *string         `json:"retryAt,omitempty"`
	NativeInteractionID string          `json:"nativeInteractionId,omitempty"`
	InteractionKind     string          `json:"interactionKind,omitempty"`
	Summary             string          `json:"summary,omitempty"`
	NativePayload       json.RawMessage `json:"nativePayload,omitempty"`
	Decision            string          `json:"decision,omitempty"`
	Answer              string          `json:"answer,omitempty"`
}

// isTerminalSessionEvent reports whether the event ends a turn's stream.
func isTerminalSessionEvent(ty string) bool {
	switch ty {
	case session.EventTurnCompleted, session.EventTurnFailed, session.EventSessionLost:
		return true
	}
	return false
}

// normalizePersist maps a --persistent wire event to the generic
// session.SessionEvent vocabulary.
func normalizePersist(ev persistWireEvent) session.SessionEvent {
	out := session.SessionEvent{
		Type:         ev.Event,
		SessionID:    ev.SessionID,
		TurnID:       ev.TurnID, // the logical turn id the fake echoes back
		Output:       ev.Output,
		Model:        ev.Model,
		InputTokens:  nil,
		OutputTokens: nil,
		CachedTokens: nil,
		Error:        ev.Error,
		RetryAt:      ev.RetryAt,
	}
	switch ev.Event {
	case session.EventSessionStarted, session.EventSessionResumed,
		session.EventSessionLost, session.EventBusy, session.EventIdle,
		session.EventTurnStarted, session.EventTurnOutput,
		session.EventTurnCompleted, session.EventTurnFailed,
		session.EventInteractionStarted, session.EventInteractionResolved:
		// pass through
	default:
		// Unknown event names degrade to output so nothing is silently
		// dropped.
		out.Type = session.EventTurnOutput
	}
	if ev.Event == session.EventTurnFailed {
		out.FailureKind = ev.Kind
		if out.FailureKind == "" {
			out.FailureKind = string(domain.RuntimeFailureUnknown)
		}
	}
	if ev.Event == session.EventInteractionStarted || ev.Event == session.EventInteractionResolved {
		out.Interaction = &session.InteractionEvent{
			NativeInteractionID: ev.NativeInteractionID,
			Kind:                ev.InteractionKind,
			Summary:             ev.Summary,
			NativePayload:       ev.NativePayload,
			Resolved:            ev.Event == session.EventInteractionResolved,
			Decision:            ev.Decision,
			Answer:              ev.Answer,
		}
	}
	return out
}
