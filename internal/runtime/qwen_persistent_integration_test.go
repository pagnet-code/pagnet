//go:build linux || darwin

package runtime

// Qwen Dual Output REAL-qwen integration tests (runtime-lifecycle refactor,
// Phase 4).
//
// These tests drive the QwenPersistent driver against a REAL qwen CLI and a
// REAL model. They are SKIP-guarded: they run ONLY when
// PAGNET_TEST_QWEN_INTEGRATION=1 AND the qwen binary is resolvable. They are
// opt-in (a real model is required) and do NOT run in the CI self-gate.
//
// They prove the persistent model end-to-end:
//   - §41 core proof: many turns, one process, stable PID, hibernate/wake
//     the same session (session.resumed, same native id).
//   - §41 model-level continuity: a turn after wake references context
//     stated before hibernate (the session survived the process boundary).
//   - invariant F (endpoint death): a SIGKILL'd endpoint with a
//     materialised session re-activates and resumes the SAME session (the
//     chat recording made it durable).
//   - materialised honesty (acceptance #4): a bare launch (no exchange) is
//     NOT resumable — session.lost, never a silent fresh session.
//   - interactions (acceptance #3): a shell tool call is observed as a
//     permission interaction and remote-resolved (the tool runs, the turn
//     completes); ask_user_question is HUMAN-ONLY — surfaced, never
//     auto-resolved (R3).
//   - lost session: a resume of a non-existent session is session.lost.
//
// Harness notes — the two traps that make a naive standalone driver test
// hang (both are TEST-HARNESS problems, not driver defects):
//
//  1. PTY DRAIN. In production the daemon creates an endpoint VIEW on the
//     endpoint's PTY at every activation (ensureEndpointView →
//     terminal.attachEndpoint → readLoop), which reads the master
//     continuously (discarding when no WS client is attached) — so the Ink
//     TUI never blocks on tty writes. A standalone driver test has no
//     daemon: nobody reads the master, the TUI fills the ~8KB PTY buffer
//     and BLOCKS on write, and the model call never fires (symptom: the
//     events file carries session_start + user + goal_state, then silence).
//     Every test therefore starts startPTYDrain right after Activate.
//
//  2. THE TURN CHANNEL IS NEVER CLOSED. The driver's per-turn events
//     channel is closed by the Manager, which a standalone test has no
//     instance of. `for ev := range turnEvents` blocks forever after the
//     buffered events are drained — even when the turn completed. The
//     helpers below collect until the terminal event (+deadline) instead.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// requireQwenIntegration returns a QwenPersistent driver for a real qwen
// CLI, or skips the test when the integration is not enabled (the default)
// or the qwen binary is not resolvable.
func requireQwenIntegration(t *testing.T) *QwenPersistent {
	t.Helper()
	if os.Getenv("PAGNET_TEST_QWEN_INTEGRATION") != "1" {
		t.Skip("PAGNET_TEST_QWEN_INTEGRATION != 1 (real-qwen integration tests are opt-in)")
	}
	// Per-test state isolation: the driver persists the handshake session
	// (native id + exact cwd) under the state dir keyed by InstanceID, and
	// the cwd-drift resume guard (R6) refuses a resume whose STORED cwd
	// differs from the workspace. The tests share fixed InstanceIDs and
	// per-test TempDir workspaces, so without isolation a previous test's
	// session.json would make a later test's resume fail with cwd drift
	// instead of the behavior under test.
	t.Setenv("PAGNET_STATE_DIR", t.TempDir())
	q := NewQwenPersistent("")
	if !q.Available() {
		t.Skip("qwen binary not resolvable")
	}
	return q
}

// --- harness helpers -----------------------------------------------------------

// ptyDrainCap bounds the captured TUI output (the TAIL is kept — the recent
// rendering is what a failure needs).
const ptyDrainCap = 512 * 1024

// ptyDrain continuously reads the endpoint's TUI PTY master and discards
// the bytes (appending them to a capped buffer for observability). It is
// the test's stand-in for the daemon's terminal view (see the file header,
// trap 1): without a reader the Ink TUI blocks on tty writes and the model
// call never fires.
type ptyDrain struct {
	t    *testing.T
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	once sync.Once
}

// startPTYDrain starts the drain for the instance's live endpoint. It must
// be called as early as possible after Activate returns. The drain exits
// when the endpoint process dies (the master read errors); stop is
// idempotent and is also registered as a cleanup.
func startPTYDrain(t *testing.T, q *QwenPersistent, instanceID string) *ptyDrain {
	t.Helper()
	master := q.PTYMaster(instanceID)
	if master == nil {
		t.Fatal("PTYMaster is nil after activation (the endpoint must own its TUI PTY)")
	}
	d := &ptyDrain{t: t, done: make(chan struct{})}
	go func() {
		defer close(d.done)
		b := make([]byte, 64*1024)
		for {
			n, err := master.Read(b)
			if n > 0 {
				d.mu.Lock()
				if d.buf.Len()+n > ptyDrainCap {
					// Keep the tail: the recent output is what a failure
					// needs (the TUI's last rendering).
					old := make([]byte, d.buf.Len())
					d.buf.Read(old)
					d.buf.Reset()
					if tail := ptyDrainCap - n; tail < len(old) {
						old = old[len(old)-tail:]
					}
					d.buf.Write(old)
				}
				d.buf.Write(b[:n])
				d.mu.Unlock()
			}
			if err != nil {
				return // the process exited (EIO / closed master)
			}
		}
	}()
	t.Cleanup(d.stop)
	return d
}

// stop waits for the drain goroutine to exit (bounded) and, on test
// failure, dumps the captured TUI output — the observability for "why did
// the model call never fire".
func (d *ptyDrain) stop() {
	d.once.Do(func() {
		select {
		case <-d.done:
		case <-time.After(5 * time.Second):
		}
		if d.t.Failed() {
			d.mu.Lock()
			out := d.buf.String()
			d.mu.Unlock()
			if out != "" {
				d.t.Logf("drained TUI output (%d bytes, tail):\n%s", len(out), out)
			}
		}
	})
}

// drainTurnEvents reads a turn's event channel until a terminal turn event
// (turn.completed / turn.failed / session.lost) or the deadline. The
// driver's per-turn channel is never closed (the Manager owns closing; a
// standalone test has no Manager), so `range` would block forever after
// the buffered events are drained — even when the turn completed. It
// returns the events observed and the terminal event.
func drainTurnEvents(t *testing.T, ch <-chan session.SessionEvent, timeout time.Duration) ([]session.SessionEvent, session.SessionEvent) {
	t.Helper()
	var events []session.SessionEvent
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("turn channel closed without a terminal event (observed: %s)", summarizeEvents(events))
			}
			events = append(events, ev)
			if isTerminalSessionEvent(ev.Type) {
				return events, ev
			}
		case <-deadline:
			t.Fatalf("no terminal turn event within %v (observed: %s)", timeout, summarizeEvents(events))
		}
	}
}

// waitForEvent returns the first event on ch whose Type is one of types,
// or fails the test when the deadline passes. Non-matching events are
// consumed and discarded (the activation channels carry only the
// activation event in these tests).
func waitForEvent(t *testing.T, ch <-chan session.SessionEvent, timeout time.Duration, types ...string) session.SessionEvent {
	t.Helper()
	want := make(map[string]bool, len(types))
	for _, ty := range types {
		want[ty] = true
	}
	deadline := time.After(timeout)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event channel closed before any of %v", types)
			}
			if want[ev.Type] {
				return ev
			}
		case <-deadline:
			t.Fatalf("no event of type %v within %v", types, timeout)
		}
	}
}

// turnCollector consumes a turn's event channel in a background goroutine
// until a terminal event, recording every event. The driver's per-turn
// channel is never closed (the Manager owns closing), so the collector
// stops on the terminal event, not on channel close. It is the pattern for
// interaction tests, where the test must observe mid-turn events
// (interactions) while Submit is still blocked on the turn settling.
type turnCollector struct {
	mu   sync.Mutex
	evs  []session.SessionEvent
	term session.SessionEvent
	done chan struct{}
}

func startTurnCollector(ch <-chan session.SessionEvent) *turnCollector {
	c := &turnCollector{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			ev, ok := <-ch
			if !ok {
				return
			}
			c.mu.Lock()
			c.evs = append(c.evs, ev)
			terminal := isTerminalSessionEvent(ev.Type)
			if terminal {
				c.term = ev
			}
			c.mu.Unlock()
			if terminal {
				return
			}
		}
	}()
	return c
}

// waitTerminal blocks until the terminal event is recorded or the
// deadline passes. It returns (zero, false) on timeout.
func (c *turnCollector) waitTerminal(timeout time.Duration) (session.SessionEvent, bool) {
	deadline := time.After(timeout)
	for {
		if term, ok := c.terminal(); ok {
			return term, true
		}
		select {
		case <-c.done:
			return c.terminal()
		case <-deadline:
			return session.SessionEvent{}, false
		}
	}
}

// find returns the first recorded event matching want, or (zero, false).
func (c *turnCollector) find(want func(session.SessionEvent) bool) (session.SessionEvent, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.evs {
		if want(ev) {
			return ev, true
		}
	}
	return session.SessionEvent{}, false
}

// waitFor polls find until it matches, the collector is done, or the
// deadline passes.
func (c *turnCollector) waitFor(timeout time.Duration, want func(session.SessionEvent) bool) (session.SessionEvent, bool) {
	deadline := time.After(timeout)
	for {
		if ev, ok := c.find(want); ok {
			return ev, true
		}
		select {
		case <-c.done:
			return c.find(want)
		case <-deadline:
			return session.SessionEvent{}, false
		}
	}
}

func (c *turnCollector) terminal() (session.SessionEvent, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.term, c.term.Type != ""
}

func (c *turnCollector) events() []session.SessionEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]session.SessionEvent(nil), c.evs...)
}

// resolvedIDs returns the set of native interaction ids that have a
// recorded resolved event.
func (c *turnCollector) resolvedIDs() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]bool{}
	for _, ev := range c.evs {
		if ev.Type == session.EventInteractionResolved && ev.Interaction != nil {
			out[ev.Interaction.NativeInteractionID] = true
		}
	}
	return out
}

// summarizeEvents renders a compact one-line-per-event summary for failure
// messages.
func summarizeEvents(evs []session.SessionEvent) string {
	var b strings.Builder
	for i, ev := range evs {
		if i >= 40 {
			fmt.Fprintf(&b, "… (+%d more)\n", len(evs)-40)
			break
		}
		line := ev.Type
		if ev.TurnID != "" {
			line += " turn=" + ev.TurnID
		}
		if ev.Error != "" {
			line += " err=" + ev.Error
		}
		if ev.Output != "" {
			s := ev.Output
			if len(s) > 80 {
				s = s[:80] + "…"
			}
			line += " out=" + s
		}
		if ev.Interaction != nil {
			line += " interaction=" + ev.Interaction.NativeInteractionID + "/" + ev.Interaction.Kind
		}
		b.WriteString(line + "\n")
	}
	if b.Len() == 0 {
		return "(no events)"
	}
	return b.String()
}

// turnOutputJoined concatenates a turn's EventTurnOutput chunks WITHOUT
// separators. (The shared turnOutput helper inserts a newline between
// chunks, which breaks cross-chunk substring assertions: a reply like
// "BANANA-42" arrives as "BAN" + "ANA-42" text deltas.)
func turnOutputJoined(evs []session.SessionEvent) string {
	var b strings.Builder
	for _, ev := range evs {
		if ev.Type == session.EventTurnOutput {
			b.WriteString(ev.Output)
		}
	}
	return b.String()
}

// writeProjectApprovalConfig writes a project-level .qwen/settings.json
// into the workspace that forces the DEFAULT approval mode (prompt for
// approval). The gate host's global ~/.qwen/settings.json is yolo
// (auto-approve → can_use_tool never fires); the project-level config
// overrides it (verified empirically against the running qwen build: a
// tool call from a workspace with this config requires approval, the same
// call from a workspace without it runs unattended), so the tool calls
// fire the control_request the interaction tests assert on.
func writeProjectApprovalConfig(t *testing.T, workspace string) {
	t.Helper()
	dir := filepath.Join(workspace, ".qwen")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "{\n  \"tools\": {\n    \"approvalMode\": \"default\"\n  }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- scenarios ------------------------------------------------------------------

// TestQwenPersistent_Integration_CoreProof is the §41 core proof: many
// turns service through ONE process (stable PID), and a hibernate/wake
// resumes the SAME session (session.resumed, same native id).
func TestQwenPersistent_Integration_CoreProof(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cold start.
	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	pid := q.PID("inst-1")
	if pid == nil {
		t.Fatal("PID is nil after activation")
	}
	drain := startPTYDrain(t, q, "inst-1")

	// Many turns through the SAME process (stable PID).
	const turns = 20
	for i := 0; i < turns; i++ {
		turnEvents := make(chan session.SessionEvent, 256)
		req := session.SubmitRequest{
			TurnID: "turn-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Kind:   session.SubmitPrompt,
			Input:  "Reply with exactly one word: OK",
		}
		if err := q.Submit(ctx, sess, req, turnEvents); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
		// Consume the turn events until the terminal event (the channel is
		// never closed — see the file header, trap 2).
		_, terminal := drainTurnEvents(t, turnEvents, 120*time.Second)
		if terminal.Type != session.EventTurnCompleted {
			t.Fatalf("turn %d ended with %q (%s), want %q", i, terminal.Type, terminal.Error, session.EventTurnCompleted)
		}
		// The PID is stable (one process).
		if cur := q.PID("inst-1"); cur == nil || *cur != *pid {
			t.Fatalf("PID changed after turn %d (want %d, got %v)", i, *pid, cur)
		}
	}

	// Hibernate (the session is preserved).
	if err := q.Hibernate(ctx, sess); err != nil {
		t.Fatalf("Hibernate: %v", err)
	}
	if q.Live("inst-1") {
		t.Fatal("endpoint still live after Hibernate")
	}
	drain.stop()

	// Wake (re-activate): the SAME session is resumed.
	sess.Materialised = true
	wakeEvents := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, wakeEvents); err != nil {
		t.Fatalf("wake Activate: %v", err)
	}
	if sess.NativeID != nativeID {
		t.Fatalf("NativeID changed after wake (want %q, got %q)", nativeID, sess.NativeID)
	}
	// The wake activation event is session.resumed (the same session).
	actEv := waitForEvent(t, wakeEvents, 30*time.Second, session.EventSessionResumed)
	if actEv.SessionID != nativeID {
		t.Fatalf("wake session id = %q, want %q", actEv.SessionID, nativeID)
	}
	startPTYDrain(t, q, "inst-1")

	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_Integration_LostSession verifies that a resume of a
// non-existent session (a valid UUID with no saved session) maps to
// session.lost (ErrSessionLost), never a silent fresh session.
func TestQwenPersistent_Integration_LostSession(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID:   "inst-1",
		Runtime:      domain.RuntimeQwenCode,
		Workspace:    workspace,
		NativeID:     "99999999-aaaa-bbbb-cccc-999999999999", // a valid UUID with no saved session
		Materialised: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 8)
	_, err := q.Activate(ctx, sess, events)
	if !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("Activate error = %v, want ErrSessionLost", err)
	}
}

// TestQwenPersistent_Integration_SingleTurnSmoke is the ONE single-turn
// real-qwen smoke (brief: MAY run if a model is resolvable): a cold start
// plus ONE prompt turn through the real qwen TUI + a real model, proving
// the full turn lifecycle end-to-end (submit → model response →
// turn.completed) on the dual-output machine plane.
func TestQwenPersistent_Integration_SingleTurnSmoke(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID: "inst-smoke",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Cold start.
	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	_ = startPTYDrain(t, q, "inst-smoke")

	// ONE prompt turn through the real model.
	turnEvents := make(chan session.SessionEvent, 256)
	req := session.SubmitRequest{
		TurnID: "smoke-1",
		Kind:   session.SubmitPrompt,
		Input:  "Reply with exactly one word: OK",
	}
	if err := q.Submit(ctx, sess, req, turnEvents); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	evs, terminal := drainTurnEvents(t, turnEvents, 120*time.Second)
	if terminal.Type != session.EventTurnCompleted {
		t.Fatalf("turn ended with %q (%s), want %q", terminal.Type, terminal.Error, session.EventTurnCompleted)
	}
	// The model actually responded (the machine plane carried the reply).
	if out := turnOutputJoined(evs); !strings.Contains(out, "OK") {
		t.Fatalf("turn output = %q, want the model's OK reply", out)
	}

	if err := q.Stop("inst-smoke"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_Integration_ModelContinuity is the §41 model-level
// continuity proof: a turn after hibernate/wake references context stated
// before hibernate — the session (not just the id) survived the process
// boundary.
func TestQwenPersistent_Integration_ModelContinuity(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID: "inst-continuity",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cold start.
	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	drain := startPTYDrain(t, q, "inst-continuity")

	// Turn 1: plant the secret.
	turnEvents := make(chan session.SessionEvent, 256)
	if err := q.Submit(ctx, sess, session.SubmitRequest{
		TurnID: "cont-1",
		Kind:   session.SubmitPrompt,
		Input:  "Remember the secret code BANANA-42. Reply with only: OK",
	}, turnEvents); err != nil {
		t.Fatalf("Submit turn 1: %v", err)
	}
	if _, terminal := drainTurnEvents(t, turnEvents, 120*time.Second); terminal.Type != session.EventTurnCompleted {
		t.Fatalf("turn 1 ended with %q (%s), want %q", terminal.Type, terminal.Error, session.EventTurnCompleted)
	}

	// Hibernate → wake (the SAME session is resumed).
	if err := q.Hibernate(ctx, sess); err != nil {
		t.Fatalf("Hibernate: %v", err)
	}
	if q.Live("inst-continuity") {
		t.Fatal("endpoint still live after Hibernate")
	}
	drain.stop()
	sess.Materialised = true
	wakeEvents := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, wakeEvents); err != nil {
		t.Fatalf("wake Activate: %v", err)
	}
	if sess.NativeID != nativeID {
		t.Fatalf("NativeID changed after wake (want %q, got %q)", nativeID, sess.NativeID)
	}
	actEv := waitForEvent(t, wakeEvents, 30*time.Second, session.EventSessionResumed)
	if actEv.SessionID != nativeID {
		t.Fatalf("wake session id = %q, want %q", actEv.SessionID, nativeID)
	}
	startPTYDrain(t, q, "inst-continuity")

	// Turn 2: ask for the secret (model-level continuity across the
	// process boundary).
	turnEvents2 := make(chan session.SessionEvent, 256)
	if err := q.Submit(ctx, sess, session.SubmitRequest{
		TurnID: "cont-2",
		Kind:   session.SubmitPrompt,
		Input:  "What was the secret code I told you earlier? Reply with only the code.",
	}, turnEvents2); err != nil {
		t.Fatalf("Submit turn 2: %v", err)
	}
	evs, terminal := drainTurnEvents(t, turnEvents2, 120*time.Second)
	if terminal.Type != session.EventTurnCompleted {
		t.Fatalf("turn 2 ended with %q (%s), want %q", terminal.Type, terminal.Error, session.EventTurnCompleted)
	}
	if out := turnOutputJoined(evs); !strings.Contains(out, "BANANA-42") {
		t.Fatalf("turn 2 output = %q, want it to contain BANANA-42 (model-level continuity across hibernate/wake)", out)
	}

	if err := q.Stop("inst-continuity"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_Integration_DeathResume is invariant F with a REAL
// crash: cold start + one completed turn (the session is now materialised
// and the chat recording is on disk) → SIGKILL the endpoint → re-activate
// → the SAME session is resumed (session.resumed, same native id) and a
// further turn completes. The endpoint death lost nothing: the chat
// recording made the session durable.
func TestQwenPersistent_Integration_DeathResume(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID: "inst-death",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Cold start.
	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	drain := startPTYDrain(t, q, "inst-death")

	// ONE completed turn: the session is now materialised (the chat
	// recording exists on disk).
	turnEvents := make(chan session.SessionEvent, 256)
	if err := q.Submit(ctx, sess, session.SubmitRequest{
		TurnID: "death-1",
		Kind:   session.SubmitPrompt,
		Input:  "Reply with exactly one word: OK",
	}, turnEvents); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, terminal := drainTurnEvents(t, turnEvents, 120*time.Second); terminal.Type != session.EventTurnCompleted {
		t.Fatalf("turn ended with %q (%s), want %q", terminal.Type, terminal.Error, session.EventTurnCompleted)
	}

	// Kill the endpoint process (a crash, not a clean hibernate).
	pid := q.PID("inst-death")
	if pid == nil {
		t.Fatal("PID is nil after the completed turn")
	}
	if err := syscall.Kill(*pid, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL %d: %v", *pid, err)
	}
	// The reader detects the death (processGone), reaps, and drops the
	// endpoint record: Live goes false.
	deadline := time.Now().Add(30 * time.Second)
	for q.Live("inst-death") {
		if time.Now().After(deadline) {
			t.Fatal("endpoint still live 30s after SIGKILL")
		}
		time.Sleep(100 * time.Millisecond)
	}
	drain.stop()

	// Re-activate: the SAME session is resumed (materialised + the
	// recording is on disk).
	sess.Materialised = true
	wakeEvents := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, wakeEvents); err != nil {
		t.Fatalf("re-Activate after death: %v", err)
	}
	if sess.NativeID != nativeID {
		t.Fatalf("NativeID changed after death+re-activation (want %q, got %q)", nativeID, sess.NativeID)
	}
	actEv := waitForEvent(t, wakeEvents, 30*time.Second, session.EventSessionResumed)
	if actEv.SessionID != nativeID {
		t.Fatalf("resumed session id = %q, want %q", actEv.SessionID, nativeID)
	}
	startPTYDrain(t, q, "inst-death")

	// One more turn completes on the resumed session.
	turnEvents2 := make(chan session.SessionEvent, 256)
	if err := q.Submit(ctx, sess, session.SubmitRequest{
		TurnID: "death-2",
		Kind:   session.SubmitPrompt,
		Input:  "Reply with exactly one word: OK",
	}, turnEvents2); err != nil {
		t.Fatalf("Submit after resume: %v", err)
	}
	if _, terminal := drainTurnEvents(t, turnEvents2, 120*time.Second); terminal.Type != session.EventTurnCompleted {
		t.Fatalf("post-resume turn ended with %q (%s), want %q", terminal.Type, terminal.Error, session.EventTurnCompleted)
	}

	if err := q.Stop("inst-death"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_Integration_MaterialisedHonesty is acceptance #4: a
// cold start with NO completed exchange leaves nothing resumable (a bare
// launch writes no chat recording). A resume attempt of the bare-launch id
// is session.lost (ErrSessionLost) — never a silent fresh session.
func TestQwenPersistent_Integration_MaterialisedHonesty(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	sess := &session.RuntimeSession{
		InstanceID: "inst-honest",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Cold start: the handshake mints a NativeID, but NO exchange happens.
	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	nativeID := sess.NativeID
	if nativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	drain := startPTYDrain(t, q, "inst-honest")
	if err := q.Stop("inst-honest"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	drain.stop()

	// A FRESH driver instance (a fresh daemon process): resuming the
	// bare-launch id must be session.lost (real qwen exits 1 "No saved
	// session found" — the bare launch wrote no chat recording), never a
	// silent fresh session.
	q2 := NewQwenPersistent("")
	if !q2.Available() {
		t.Skip("qwen binary not resolvable")
	}
	sess2 := &session.RuntimeSession{
		InstanceID:   "inst-honest",
		Runtime:      domain.RuntimeQwenCode,
		Workspace:    workspace,
		NativeID:     nativeID,
		Materialised: true,
	}
	events2 := make(chan session.SessionEvent, 8)
	_, err := q2.Activate(ctx, sess2, events2)
	if !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("Activate of a never-exchanged session: err = %v, want ErrSessionLost (never a silent fresh session)", err)
	}
}

// TestQwenPersistent_Integration_ToolApproval is acceptance #3a: a shell
// tool call is observed as a permission interaction (control_request
// can_use_tool → EventInteractionStarted, kind "permission", native id =
// the request_id), remote-resolved (confirmation_response allowed:true →
// EventInteractionResolved), the tool actually runs, and the turn
// completes.
func TestQwenPersistent_Integration_ToolApproval(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	// The project-level approval config forces the approval prompt (the
	// host's global config is yolo — see writeProjectApprovalConfig).
	writeProjectApprovalConfig(t, workspace)
	sess := &session.RuntimeSession{
		InstanceID: "inst-approval",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	_ = startPTYDrain(t, q, "inst-approval")

	// A prompt that forces a shell tool call. The command is NOT on the
	// host's global permissions.allow list (echo/curl/... are), so it
	// requires approval and the control_request fires.
	turnEvents := make(chan session.SessionEvent, 256)
	col := startTurnCollector(turnEvents)

	// The remote resolver: observe the permission interaction(s) and
	// resolve them (proceed — the ONLY two expressible outcomes are
	// proceed_once / cancel, R10). It loops because the model may call a
	// tool more than once; it exits when the turn terminates.
	go func() {
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			for _, ev := range col.events() {
				if ev.Type != session.EventInteractionStarted || ev.Interaction == nil ||
					ev.Interaction.Kind != "permission" {
					continue
				}
				id := ev.Interaction.NativeInteractionID
				if col.resolvedIDs()[id] {
					continue
				}
				if err := q.Submit(ctx, sess, session.SubmitRequest{
					TurnID:        "approval-1",
					Kind:          session.SubmitInteraction,
					InteractionID: id,
					Decision:      "resolved",
				}, turnEvents); err != nil && !errors.Is(err, session.ErrEndpointGone) {
					t.Errorf("Submit interaction resolution for %s: %v", id, err)
				}
			}
			if _, done := col.waitTerminal(2 * time.Second); done {
				return
			}
		}
	}()

	// The command's output is UNPREDICTABLE (a timestamp the model cannot
	// know without running it): a model that skips the tool and answers
	// from its own knowledge cannot produce the output, so the tool call
	// (and the approval it triggers) is forced. (Observed: with a
	// predictable command like `printf pagnet-approval-proof`, the model
	// answers the reply directly and never calls the tool.)
	if err := q.Submit(ctx, sess, session.SubmitRequest{
		TurnID: "approval-1",
		Kind:   session.SubmitPrompt,
		Input:  "Use the run_shell_command tool to run exactly this shell command: printf 'pagnet-proof-%s' \"$(date +%s)\". When it finishes reply with only the command's exact output.",
	}, turnEvents); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	terminal, ok := col.waitTerminal(5 * time.Minute)
	if !ok || terminal.Type != session.EventTurnCompleted {
		t.Fatalf("turn ended with %q (%s), want %q (events: %s)", terminal.Type, terminal.Error, session.EventTurnCompleted, summarizeEvents(col.events()))
	}

	evs := col.events()
	// The permission interaction was observed (native id = the request_id).
	started, ok := col.find(func(ev session.SessionEvent) bool {
		return ev.Type == session.EventInteractionStarted && ev.Interaction != nil &&
			ev.Interaction.Kind == "permission"
	})
	if !ok {
		t.Fatalf("no permission interaction started (the control_request was never observed; events: %s)", summarizeEvents(evs))
	}
	if started.Interaction.NativeInteractionID == "" {
		t.Fatal("permission interaction carries no native id (the request_id)")
	}
	// The resolution was observed (the control_response mirror).
	resolved, ok := col.find(func(ev session.SessionEvent) bool {
		return ev.Type == session.EventInteractionResolved && ev.Interaction != nil &&
			ev.Interaction.NativeInteractionID == started.Interaction.NativeInteractionID
	})
	if !ok {
		t.Fatalf("no interaction.resolved for %s (events: %s)", started.Interaction.NativeInteractionID, summarizeEvents(evs))
	}
	if resolved.Interaction.Decision != "resolved" {
		t.Fatalf("interaction resolved with decision %q, want resolved", resolved.Interaction.Decision)
	}
	// The tool actually ran: the model saw the command's output (the
	// timestamp the model could only learn by running it) and replied with
	// it.
	if out := turnOutputJoined(evs); !strings.Contains(out, "pagnet-proof-") {
		t.Fatalf("turn output = %q, want the command's output (the tool ran after the approval)", out)
	}

	if err := q.Stop("inst-approval"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_Integration_AskUserQuestionHumanOnly is acceptance
// #3b: an ask_user_question tool call is surfaced as a HUMAN-ONLY
// interaction (kind "question"). The driver must NEVER auto-resolve it
// (R3: a generic allowed:true yields the phantom "No valid answers were
// provided." answer — worse than a hang); the human answers in the PTY.
// The test asserts the capability policy (SupportsRemoteResolve("question")
// == false) and that no resolved event arrives while the turn is parked.
func TestQwenPersistent_Integration_AskUserQuestionHumanOnly(t *testing.T) {
	q := requireQwenIntegration(t)
	workspace := t.TempDir()
	writeProjectApprovalConfig(t, workspace)
	sess := &session.RuntimeSession{
		InstanceID: "inst-question",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	events := make(chan session.SessionEvent, 16)
	if _, err := q.Activate(ctx, sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	_ = startPTYDrain(t, q, "inst-question")

	// The capability policy: questions are NOT remotely resolvable.
	if q.SupportsRemoteResolve("question") {
		t.Fatal("SupportsRemoteResolve(question) = true, want false (human-only, R3)")
	}

	// A prompt that forces an ask_user_question tool call. The turn parks
	// on the interaction (human-only), so the prompt Submit runs in a
	// goroutine: it blocks until the turn settles, and the Stop below cuts
	// it off (the parked turn is not a failure).
	//
	// Bounded retry on "the model did not call the tool": the compliance is
	// not guaranteed per turn with a non-thinking model, so a turn that
	// SETTLES without the interaction is a precondition failure — retry
	// with a fresh turn on the same session. A turn that DOES carry the
	// interaction is asserted exactly once (a retry must never mask a real
	// R3 auto-resolve violation), and a turn still active at the deadline
	// is a genuine anomaly (fail, do not retry a stuck state).
	const maxAttempts = 3
	var (
		question session.SessionEvent
		found    bool
		col      *turnCollector
	)
	submitDone := make(chan struct{})
	summaries := make([]string, 0, maxAttempts)
	for attempt := 1; attempt <= maxAttempts && !found; attempt++ {
		turnEvents := make(chan session.SessionEvent, 256)
		col = startTurnCollector(turnEvents)
		submitDone = make(chan struct{})
		go func() {
			defer close(submitDone)
			_ = q.Submit(ctx, sess, session.SubmitRequest{
				TurnID: fmt.Sprintf("question-%d", attempt),
				Kind:   session.SubmitPrompt,
				Input:  "Use the ask_user_question tool to ask me which of these I prefer: option A or option B. Wait for my answer.",
			}, turnEvents)
		}()

		// The question interaction is observed (kind "question", native
		// id = the request_id) — or the turn settles without one.
		deadline := time.Now().Add(3 * time.Minute)
		for time.Now().Before(deadline) {
			if ev, ok := col.find(func(ev session.SessionEvent) bool {
				return ev.Type == session.EventInteractionStarted && ev.Interaction != nil &&
					ev.Interaction.Kind == "question"
			}); ok {
				question, found = ev, true
				break
			}
			if _, done := col.terminal(); done {
				break // settled without the tool: retry (logged below)
			}
			time.Sleep(500 * time.Millisecond)
		}
		summaries = append(summaries, summarizeEvents(col.events()))
		if found {
			break
		}
		if _, done := col.terminal(); !done {
			t.Fatalf("attempt %d/%d: the turn was still active after 3m without an interaction (stuck; events: %s)",
				attempt, maxAttempts, summaries[len(summaries)-1])
		}
		t.Logf("attempt %d/%d: the turn settled without an ask_user_question interaction — the model did not call the tool (events: %s)",
			attempt, maxAttempts, summaries[len(summaries)-1])
		// The settled turn's Submit must return before the next attempt
		// starts (one in-flight turn per endpoint).
		select {
		case <-submitDone:
		case <-time.After(30 * time.Second):
			t.Fatalf("attempt %d: Submit did not return after the turn settled", attempt)
		}
	}
	if !found {
		t.Fatalf("no question interaction in %d attempts (the model never called ask_user_question; events: %s)",
			maxAttempts, strings.Join(summaries, " | "))
	}
	if question.Interaction.NativeInteractionID == "" {
		t.Fatal("question interaction carries no native id (the request_id)")
	}

	// The driver did NOT auto-resolve it: no resolved event for this
	// request_id within a bounded wait (the turn stays parked for the
	// human, who answers in the PTY).
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range col.events() {
			if ev.Type == session.EventInteractionResolved && ev.Interaction != nil &&
				ev.Interaction.NativeInteractionID == question.Interaction.NativeInteractionID {
				t.Fatalf("the driver auto-resolved a human-only question (decision %q) — R3 violation", ev.Interaction.Decision)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Stop the endpoint (the parked turn is cut off; the session is
	// preserved for a later human answer / resume).
	if err := q.Stop("inst-question"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-submitDone:
	case <-time.After(30 * time.Second):
		t.Fatal("Submit did not return after Stop")
	}
}
