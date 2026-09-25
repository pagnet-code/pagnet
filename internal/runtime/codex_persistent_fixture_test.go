package runtime

// Codex persistent driver fixture tests (runtime-lifecycle rework, Wave 4).
//
// These drive the REAL CodexPersistent driver (JSON-RPC over stdio, the
// full session core: Manager + Driver + supervisor) against a
// deterministic fake Codex app-server — the pagnet-fake-runtime helper in
// Codex app-server mode: a REAL process with real stdio and real JSON-RPC,
// scripted through PAGNET_FAKE_CODEX_* env knobs. No real codex binary, no
// model, CI-safe.
//
// The ten fixtures (the Wave 4 acceptance list):
//
//  1. handshake          — initialize + thread/start; NativeID = the
//                          thread id; a failed/timeout handshake is a
//                          clean launch error (no hang, no stale endpoint);
//                          a re-based / failed resume is a lost session.
//  2. correlation        — responses are matched by id, notifications by
//                          method/thread: unrelated noise interleaved with
//                          the handshake and the turn must not break the
//                          exchange or leak into the turn stream.
//  3. turn loop          — N turns on ONE endpoint process (stable PID,
//                          one thread, N turn/start — the persistent model).
//  4. materialisation    — a started-but-unexchanged session is not
//                          resumable (ErrNotMaterialised), at the driver
//                          gate and through the Manager.
//  5. crash→interrupted  — the endpoint dies AFTER accepting the turn:
//                          ErrTurnInterrupted, no terminal event, the
//                          session is preserved but not materialised.
//  6. resume-fresh       — a never-materialised session cold-starts a
//                          FRESH thread after the crash (thread/start, not
//                          thread/resume — no brick).
//  7. standing document  — delivered as developerInstructions on
//                          thread/start AND thread/resume (the native
//                          standing surface), never as turn input.
//  8. MCP config         — the -c mcp_servers overrides reach the process
//                          argv; missing/invalid config is a visible
//                          launch failure (fail closed).
//  9. event mapping      — the Codex streaming events map onto the
//                          normalized session event stream (deltas, item
//                          notes, per-turn usage, terminal status, error
//                          classification).
//  10. interaction        — native approval/input requests surface as
//                          generic interactions; the resolution travels
//                          back as the exact JSON-RPC response (pagnet
//                          never auto-approves; an inexpressible decision
//                          is a JSON-RPC error, never a guessed approval).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// codexFixtureThreadID is the fake app-server's default thread id.
const codexFixtureThreadID = "01900000-0000-7000-8000-000000000001"

// newCodexFixture builds the full fixture: a real supervisor, the
// CodexPersistent driver wired to it (pointed at the fake app-server
// binary), and a session Manager with the driver registered. driverEnv
// carries the PAGNET_FAKE_CODEX_* scripting knobs.
func newCodexFixture(t *testing.T, driverEnv ...string) (*proc.Supervisor, *session.Manager, *CodexPersistent) {
	t.Helper()
	bin := p0FakeBinary(t)
	cfg := proc.DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.MonitorInterval = 50 * time.Millisecond
	sup := proc.NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { sup.StopAll(5 * time.Second) })
	cp := NewCodexPersistent(bin)
	cp.Env = driverEnv
	cp.SetLifecycle(sup)
	m := session.NewManager()
	m.RegisterDriver(cp)
	return sup, m, cp
}

// codexMCPEnv is the session launch env with a valid daemon-shaped
// PAGNET_MCP_CONFIG (the codex driver is fail-closed on it).
func codexMCPEnv(instanceID string) []string {
	return []string{
		"PAGNET_INSTANCE_ID=" + instanceID,
		"PAGNET_AGENT_NAME=test-agent",
		"PAGNET_NETWORK_ID=net-1",
		`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"command":"/opt/pagnet/pagnet","args":["mcp","worker","--socket","/tmp/pagnetd.sock"],"env":{"PAGNET_INSTANCE_ID":"` + instanceID + `","PAGNET_NETWORK_ID":"net-1"}}}}`,
	}
}

// codexSubmitTurn drives one prompt turn through the Manager and drains
// the event stream. It returns the settled result, the observed events,
// and the submit error (nil when delivered; ErrTurnInterrupted when the
// accepted turn's endpoint died).
func codexSubmitTurn(t *testing.T, m *session.Manager, sess *session.RuntimeSession, turnID, input string) (*session.TurnResult, []session.SessionEvent, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	events := make(chan session.SessionEvent, 64)
	var result *session.TurnResult
	var submitErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, submitErr = m.Submit(ctx, sess, session.SubmitRequest{
			TurnID: turnID, Kind: session.SubmitPrompt, Input: input, InputKind: "task",
		}, events)
	}()
	var evs []session.SessionEvent
	for ev := range events {
		evs = append(evs, ev)
	}
	<-done
	return result, evs, submitErr
}

// codexEventTypes extracts the event types (for sequence assertions).
func codexEventTypes(evs []session.SessionEvent) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Type
	}
	return out
}

// assertCodexEventTypes asserts the normalized events have exactly the
// given types, in order.
func assertCodexEventTypes(t *testing.T, got []session.SessionEvent, want ...string) {
	t.Helper()
	gotTypes := codexEventTypes(got)
	if len(gotTypes) != len(want) {
		t.Fatalf("event types = %v (len %d), want %v (len %d)", gotTypes, len(gotTypes), want, len(want))
	}
	for i := range want {
		if gotTypes[i] != want[i] {
			t.Fatalf("event types = %v, want %v", gotTypes, want)
		}
	}
}

// readCodexLines reads the observation-point file (one value per line).
func readCodexLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// --- 1. handshake -----------------------------------------------------------

func TestCodexPersistent_Handshake(t *testing.T) {
	t.Run("initializeAndThreadStart", func(t *testing.T) {
		_, m, cp := newCodexFixture(t)
		workspace := t.TempDir()
		sess := m.Session("inst-hs", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-hs"))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs := make(chan session.SessionEvent, 16)
		ep, err := m.EnsureActive(ctx, sess, evs)
		close(evs)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		// NativeID is the thread.id from thread/start (spec item 5).
		if sess.NativeID != codexFixtureThreadID {
			t.Fatalf("NativeID = %q, want the thread id %q", sess.NativeID, codexFixtureThreadID)
		}
		if ep == nil || ep.PID == 0 {
			t.Fatalf("no live endpoint after the handshake: %+v", ep)
		}
		if !cp.Live("inst-hs") {
			t.Fatal("Live() is false after a successful handshake")
		}
	})

	t.Run("timeoutIsACleanLaunchError", func(t *testing.T) {
		sup, m, cp := newCodexFixture(t, "PAGNET_FAKE_CODEX_NO_INITIALIZE_RESPONSE=1")
		workspace := t.TempDir()
		sess := m.Session("inst-hs-timeout", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-hs-timeout"))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		evs := make(chan session.SessionEvent, 16)
		start := time.Now()
		_, err := m.EnsureActive(ctx, sess, evs)
		close(evs)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("want a launch error when initialize is never answered")
		}
		if !strings.Contains(err.Error(), "initialize") {
			t.Fatalf("error = %q, want the initialize handshake failure", err)
		}
		// Bounded by the activation timeout (a clean failure, not a hang).
		if elapsed > 30*time.Second {
			t.Fatalf("handshake failure took %s (want bounded by the activation timeout)", elapsed)
		}
		// The failed activation left NO stale endpoint behind.
		if n := sup.Stats().ActiveEndpoints; n != 0 {
			t.Fatalf("%d active endpoints after a failed handshake, want 0", n)
		}
		if cp.Live("inst-hs-timeout") {
			t.Fatal("Live() is true after a failed handshake")
		}
	})

	t.Run("resumeRebaseIsALostSession", func(t *testing.T) {
		// A resume that re-bases onto a different thread is a lost
		// session, never a silent fresh one (driver-level: the session is
		// materialised with a stored native id).
		_, _, cp := newCodexFixture(t, "PAGNET_FAKE_CODEX_RESUME_REBASE=1")
		workspace := t.TempDir()
		sess := &session.RuntimeSession{
			InstanceID:           "inst-rebase",
			Runtime:              domain.RuntimeCodex,
			Workspace:            workspace,
			NativeID:             codexFixtureThreadID,
			Materialised:         true,
			Env:                  codexMCPEnv("inst-rebase"),
			StandingInstructions: "",
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs := make(chan session.SessionEvent, 16)
		_, err := cp.Activate(ctx, sess, evs)
		close(evs)
		if !errors.Is(err, session.ErrSessionLost) {
			t.Fatalf("Activate = %v, want ErrSessionLost (a re-based resume)", err)
		}
	})

	t.Run("resumeFailIsALostSession", func(t *testing.T) {
		_, _, cp := newCodexFixture(t, "PAGNET_FAKE_CODEX_RESUME_FAIL=1")
		workspace := t.TempDir()
		sess := &session.RuntimeSession{
			InstanceID:   "inst-resume-fail",
			Runtime:      domain.RuntimeCodex,
			Workspace:    workspace,
			NativeID:     codexFixtureThreadID,
			Materialised: true,
			Env:          codexMCPEnv("inst-resume-fail"),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs := make(chan session.SessionEvent, 16)
		_, err := cp.Activate(ctx, sess, evs)
		close(evs)
		if !errors.Is(err, session.ErrSessionLost) {
			t.Fatalf("Activate = %v, want ErrSessionLost (a failed thread/resume)", err)
		}
	})
}

// --- 2. correlation ----------------------------------------------------------

// TestCodexPersistent_CorrelationByID proves the reader dispatches by
// id/method, not by arrival order: the fake emits unrelated noise BEFORE
// the initialize response (a different thread's turn/started) and between
// the turn/start response and the turn events (another thread's
// turn/started). The handshake must still correlate initialize →
// thread/start, the turn must complete, and no noise may leak into the
// turn stream.
func TestCodexPersistent_CorrelationByID(t *testing.T) {
	_, m, _ := newCodexFixture(t, "PAGNET_FAKE_CODEX_NOISE=1")
	workspace := t.TempDir()
	sess := m.Session("inst-corr", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-corr"))

	res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "hello")
	if submitErr != nil {
		t.Fatalf("submit: %v", submitErr)
	}
	if res == nil || !res.Completed {
		t.Fatalf("turn did not complete through the noise: %+v", res)
	}
	if res.SessionID != codexFixtureThreadID {
		t.Fatalf("session id = %q, want %q", res.SessionID, codexFixtureThreadID)
	}
	// The stream is exactly the machine turn's own events (the noise —
	// a different thread's turn — never leaks in).
	assertCodexEventTypes(t, evs,
		session.EventSessionStarted,
		session.EventTurnStarted,
		session.EventTurnOutput,
		session.EventTurnCompleted,
	)
	// Every event is attributed to OUR thread.
	for _, ev := range evs {
		if ev.SessionID != "" && ev.SessionID != codexFixtureThreadID {
			t.Fatalf("event %s attributed to foreign thread %q", ev.Type, ev.SessionID)
		}
	}
}

// --- 3. turn loop -------------------------------------------------------------

// TestCodexPersistent_TurnLoopPresentsOneProcess proves the persistent
// model: N turns on ONE endpoint process (stable PID), ONE thread (a
// single thread/start), N turn/start — the process is alive across turns.
func TestCodexPersistent_TurnLoopOneProcess(t *testing.T) {
	methodsFile := filepath.Join(t.TempDir(), "methods.log")
	sup, m, _ := newCodexFixture(t, "PAGNET_FAKE_CODEX_METHODS_FILE="+methodsFile)
	workspace := t.TempDir()
	sess := m.Session("inst-loop", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-loop"))

	var firstPID *int
	for i := 0; i < 3; i++ {
		res, evs, submitErr := codexSubmitTurn(t, m, sess, fmt.Sprintf("t%d", i), fmt.Sprintf("turn %d", i))
		if submitErr != nil {
			t.Fatalf("turn %d submit: %v", i, submitErr)
		}
		if res == nil || !res.Completed {
			t.Fatalf("turn %d did not complete: %+v", i, res)
		}
		if i > 0 && !hasSessionEvent(evs, session.EventTurnStarted) {
			t.Fatalf("turn %d did not start on the live endpoint: %+v", i, evs)
		}
		pid := sup.EndpointPID("inst-loop")
		if pid == nil {
			t.Fatalf("turn %d: no live endpoint PID", i)
		}
		if firstPID == nil {
			firstPID = pid
			continue
		}
		if *pid != *firstPID {
			t.Fatalf("PID changed at turn %d: first=%d now=%d (the endpoint must be one process across turns)", i, *firstPID, *pid)
		}
	}
	if sess.NativeID != codexFixtureThreadID {
		t.Fatalf("NativeID = %q, want the stable thread id %q", sess.NativeID, codexFixtureThreadID)
	}
	// The wire: ONE initialize, ONE thread/start, THREE turn/start.
	methods := readCodexLines(t, methodsFile)
	count := func(m string) int {
		n := 0
		for _, x := range methods {
			if x == m {
				n++
			}
		}
		return n
	}
	if count("initialize") != 1 || count("thread/start") != 1 || count("turn/start") != 3 {
		t.Fatalf("wire methods = %v, want 1 initialize + 1 thread/start + 3 turn/start", methods)
	}
	t.Logf("3 turns served by 1 endpoint (pid %d), 1 thread", *firstPID)
}

// --- 4. materialisation gating -------------------------------------------------

func TestCodexPersistent_MaterialisationGating(t *testing.T) {
	t.Run("driverGate", func(t *testing.T) {
		// A stored native id with no real exchange is not resumable: the
		// driver refuses honestly (defense-in-depth; the Manager enforces
		// the same gate).
		_, _, cp := newCodexFixture(t)
		workspace := t.TempDir()
		sess := &session.RuntimeSession{
			InstanceID:   "inst-mat-driver",
			Runtime:      domain.RuntimeCodex,
			Workspace:    workspace,
			NativeID:     codexFixtureThreadID,
			Materialised: false,
			Env:          codexMCPEnv("inst-mat-driver"),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := cp.Activate(ctx, sess, nil)
		if !errors.Is(err, session.ErrNotMaterialised) {
			t.Fatalf("Activate = %v, want ErrNotMaterialised", err)
		}
	})

	t.Run("managerGate", func(t *testing.T) {
		_, m, _ := newCodexFixture(t)
		workspace := t.TempDir()
		sess := m.Session("inst-mat-mgr", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-mat-mgr"))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Cold start: mints the native id, but the session is NOT
		// materialised (no exchange yet).
		evA := make(chan session.SessionEvent, 16)
		if _, err := m.EnsureActive(ctx, sess, evA); err != nil {
			close(evA)
			t.Fatalf("cold start: %v", err)
		}
		close(evA)
		if sess.NativeID == "" {
			t.Fatal("cold start did not mint a native id")
		}
		if sess.Materialised {
			t.Fatal("session must not be materialised before an exchange")
		}
		// Hibernate (the endpoint goes away; the session is preserved).
		if err := m.Hibernate(ctx, sess); err != nil {
			t.Fatalf("hibernate: %v", err)
		}
		// Wake: the stored id with no exchange is NOT resumable.
		evB := make(chan session.SessionEvent, 16)
		if _, err := m.EnsureActive(ctx, sess, evB); !errors.Is(err, session.ErrNotMaterialised) {
			close(evB)
			t.Fatalf("EnsureActive = %v, want ErrNotMaterialised before the first exchange", err)
		}
		close(evB)
	})
}

// --- 5. crash → interrupted ----------------------------------------------------

// TestCodexPersistent_CrashAfterAcceptIsInterrupted proves the crash
// contract: the endpoint dies AFTER accepting the turn (the turn/start
// response + turn/started are out) and BEFORE any terminal result. The
// turn settles as INTERRUPTED (ErrTurnInterrupted — never auto-retried),
// no terminal event is fabricated, the session is preserved but NOT
// materialised, and the dead process does not wedge the instance.
func TestCodexPersistent_CrashAfterAcceptIsInterrupted(t *testing.T) {
	sup, m, cp := newCodexFixture(t, "PAGNET_FAKE_CODEX_CRASH_AFTER_ACCEPT=1")
	workspace := t.TempDir()
	sess := m.Session("inst-crash", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-crash"))

	res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "crash me")
	if !errors.Is(submitErr, session.ErrTurnInterrupted) {
		t.Fatalf("submit error = %v, want ErrTurnInterrupted (the turn was accepted before the death)", submitErr)
	}
	// The stream carries the turn start but NO terminal event (the death
	// cut the turn off — a fabricated completion would be a lie).
	if !hasSessionEvent(evs, session.EventTurnStarted) {
		t.Fatalf("turn.started not observed before the crash: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Type == session.EventTurnCompleted || ev.Type == session.EventTurnFailed {
			t.Fatalf("a terminal event was fabricated for the crashed turn: %+v", ev)
		}
	}
	// The session is preserved (not lost) but NOT materialised (the
	// Manager cannot know the dying runtime persisted its state).
	if res != nil && res.SessionLost {
		t.Fatalf("the crash was reported as a session loss: %+v", res)
	}
	if sess.Materialised {
		t.Fatal("the session must not be materialised after an interrupted first turn")
	}
	// The dead process is fully reaped: no stale endpoint, no wedge.
	if n := sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("%d active endpoints after the crash, want 0", n)
	}
	if cp.Live("inst-crash") {
		t.Fatal("Live() is true after the crash")
	}
}

// --- 6. resume fresh when never materialised -----------------------------------

// TestCodexPersistent_UnmaterialisedCrashColdStartsFresh proves the no-
// brick path: a crash on the FIRST turn (nothing materialised) clears the
// stale minted id, and the next turn COLD-STARTS a fresh thread
// (thread/start — never thread/resume) and completes.
func TestCodexPersistent_UnmaterialisedCrashColdStartsFresh(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "crashed")
	methodsFile := filepath.Join(t.TempDir(), "methods.log")
	_, m, _ := newCodexFixture(t,
		"PAGNET_FAKE_CODEX_CRASH_AFTER_ACCEPT=1",
		"PAGNET_FAKE_CODEX_CRASH_MARKER="+marker,
		"PAGNET_FAKE_CODEX_METHODS_FILE="+methodsFile)
	workspace := t.TempDir()
	sess := m.Session("inst-cold", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-cold"))

	// Turn 1: accepted, then the endpoint dies (the marker records the
	// crash so the re-activated endpoint does not crash again).
	_, _, submitErr := codexSubmitTurn(t, m, sess, "t1", "crash me")
	if !errors.Is(submitErr, session.ErrTurnInterrupted) {
		t.Fatalf("turn 1 error = %v, want ErrTurnInterrupted", submitErr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the crash marker was not written (the fixture did not crash): %v", err)
	}
	if sess.NativeID != "" {
		t.Fatalf("the unmaterialised session kept native id %q after the interruption; want it cleared", sess.NativeID)
	}

	// Turn 2: a FRESH cold start (thread/start, not thread/resume) that
	// completes.
	res2, evs2, submitErr2 := codexSubmitTurn(t, m, sess, "t2", "retry")
	if submitErr2 != nil {
		t.Fatalf("turn 2 submit: %v", submitErr2)
	}
	if res2 == nil || !res2.Completed {
		t.Fatalf("turn 2 did not complete after the unmaterialised crash: %+v", res2)
	}
	if res2.SessionLost {
		t.Fatalf("turn 2 reported the session lost (a crash must not lose the session): %+v", res2)
	}
	if !hasSessionEvent(evs2, session.EventSessionStarted) {
		t.Fatalf("want a fresh session.started (cold start) after the unmaterialised crash: %+v", evs2)
	}
	if hasSessionEvent(evs2, session.EventSessionResumed) {
		t.Fatalf("an unmaterialised session must never be resumed: %+v", evs2)
	}
	// The wire: the re-activation used thread/start (fresh), not
	// thread/resume.
	methods := readCodexLines(t, methodsFile)
	resumes := 0
	for _, x := range methods {
		if x == "thread/resume" {
			resumes++
		}
	}
	if resumes != 0 {
		t.Fatalf("the re-activation resumed a never-materialised thread (methods = %v); want a fresh thread/start", methods)
	}
	starts := 0
	for _, x := range methods {
		if x == "thread/start" {
			starts++
		}
	}
	if starts != 2 {
		t.Fatalf("thread/start count = %d (methods = %v), want 2 (one per activation)", starts, methods)
	}
}

// --- 7. standing document -------------------------------------------------------

// TestCodexPersistent_StandingDocumentDelivery proves the standing
// document rides the thread's developerInstructions (Codex's native
// standing surface) on BOTH thread/start (cold) and thread/resume
// (resume) — and is NEVER part of the turn input.
func TestCodexPersistent_StandingDocumentDelivery(t *testing.T) {
	standingFile := filepath.Join(t.TempDir(), "standing.txt")
	turnInputFile := filepath.Join(t.TempDir(), "turn-input.txt")
	_, m, _ := newCodexFixture(t,
		"PAGNET_FAKE_CODEX_STANDING_FILE="+standingFile,
		"PAGNET_FAKE_CODEX_TURN_INPUT_FILE="+turnInputFile)
	workspace := t.TempDir()
	sess := m.Session("inst-std", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-std"))
	const standing = "YOU ARE A PAGNET AGENT. Standing document v1."
	sess.StandingInstructions = standing

	// Cold start: the standing document is delivered on thread/start.
	res1, _, submitErr1 := codexSubmitTurn(t, m, sess, "t1", "first turn")
	if submitErr1 != nil {
		t.Fatalf("turn 1 submit: %v", submitErr1)
	}
	if res1 == nil || !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	if b, err := os.ReadFile(standingFile); err != nil || string(b) != standing {
		t.Fatalf("standing document not delivered on thread/start (file = %q, err = %v)", b, err)
	}
	// The turn input is EXACTLY the daemon's input — the standing
	// document is not a chat message.
	if b, err := os.ReadFile(turnInputFile); err != nil || string(b) != "first turn" {
		t.Fatalf("turn input = %q (err = %v), want the daemon's input verbatim (never the standing document)", b, err)
	}

	// Hibernate + wake: the resume path (thread/resume) carries it too.
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if err := os.Remove(standingFile); err != nil {
		t.Fatalf("remove standing file: %v", err)
	}
	res2, evs2, submitErr2 := codexSubmitTurn(t, m, sess, "t2", "second turn")
	if submitErr2 != nil {
		t.Fatalf("turn 2 submit: %v", submitErr2)
	}
	if res2 == nil || !res2.Completed {
		t.Fatalf("turn 2 did not complete after the wake: %+v", res2)
	}
	if !hasSessionEvent(evs2, session.EventSessionResumed) {
		t.Fatalf("want session.resumed after the wake: %+v", evs2)
	}
	if b, err := os.ReadFile(standingFile); err != nil || string(b) != standing {
		t.Fatalf("standing document not delivered on thread/resume (file = %q, err = %v)", b, err)
	}
	if b, err := os.ReadFile(turnInputFile); err != nil || string(b) != "second turn" {
		t.Fatalf("turn 2 input = %q (err = %v), want the daemon's input verbatim", b, err)
	}
}

// --- 8. MCP config ----------------------------------------------------------------

func TestCodexPersistent_MCPConfig(t *testing.T) {
	const mcpJSON = `{"mcpServers":{"pagnet":{"command":"/opt/pagnet/pagnet","args":["mcp","worker","--socket","/tmp/pagnetd.sock"],"env":{"PAGNET_INSTANCE_ID":"inst-1","PAGNET_NETWORK_ID":"net-1"}}}}`

	t.Run("argv", func(t *testing.T) {
		args, err := codexMCPConfigArgs([]string{"PAGNET_MCP_CONFIG=" + mcpJSON})
		if err != nil {
			t.Fatalf("codexMCPConfigArgs: %v", err)
		}
		want := []string{
			"-c",
			`mcp_servers.pagnet={command="/opt/pagnet/pagnet",args=["mcp","worker","--socket","/tmp/pagnetd.sock"],env={PAGNET_INSTANCE_ID="inst-1",PAGNET_NETWORK_ID="net-1"}}`,
		}
		if len(args) != len(want) {
			t.Fatalf("args = %v, want %v", args, want)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})

	t.Run("missingConfigIsAFailure", func(t *testing.T) {
		if _, err := codexMCPConfigArgs([]string{"PAGNET_INSTANCE_ID=inst-1"}); err == nil {
			t.Fatal("want an error when PAGNET_MCP_CONFIG is missing (fail closed)")
		}
	})

	t.Run("invalidConfigIsAFailure", func(t *testing.T) {
		if _, err := codexMCPConfigArgs([]string{"PAGNET_MCP_CONFIG={not json"}); err == nil {
			t.Fatal("want an error for an invalid PAGNET_MCP_CONFIG")
		}
	})

	t.Run("noServersIsAFailure", func(t *testing.T) {
		if _, err := codexMCPConfigArgs([]string{`PAGNET_MCP_CONFIG={"mcpServers":{}}`}); err == nil {
			t.Fatal("want an error when the config has no mcpServers")
		}
	})

	t.Run("serverWithoutCommandIsAFailure", func(t *testing.T) {
		if _, err := codexMCPConfigArgs([]string{`PAGNET_MCP_CONFIG={"mcpServers":{"pagnet":{"args":["x"]}}}`}); err == nil {
			t.Fatal("want an error when a server has no command")
		}
	})

	t.Run("tomlEscaping", func(t *testing.T) {
		// A non-bare server name (a dot) is quoted; a command with quotes
		// and a backslash is escaped as a TOML basic string.
		cfg := `{"mcpServers":{"pagnet.control":{"command":"C:\\tools\\pagnet \"v2\"","args":["a\"b"],"env":{"K":"v\\w"}}}}`
		args, err := codexMCPConfigArgs([]string{"PAGNET_MCP_CONFIG=" + cfg})
		if err != nil {
			t.Fatalf("codexMCPConfigArgs: %v", err)
		}
		want := []string{
			"-c",
			`mcp_servers."pagnet.control"={command="C:\\tools\\pagnet \"v2\"",args=["a\"b"],env={K="v\\w"}}`,
		}
		if len(args) != 2 || args[0] != "-c" || args[1] != want[1] {
			t.Fatalf("args = %v, want %v", args, want)
		}
	})

	t.Run("overridesReachTheProcess", func(t *testing.T) {
		argvFile := filepath.Join(t.TempDir(), "argv.json")
		_, m, _ := newCodexFixture(t, "PAGNET_FAKE_CODEX_ARGV_FILE="+argvFile)
		workspace := t.TempDir()
		sess := m.Session("inst-mcp", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-mcp"))
		res, _, submitErr := codexSubmitTurn(t, m, sess, "t1", "first")
		if submitErr != nil {
			t.Fatalf("submit: %v", submitErr)
		}
		if res == nil || !res.Completed {
			t.Fatalf("turn did not complete: %+v", res)
		}
		b, err := os.ReadFile(argvFile)
		if err != nil {
			t.Fatalf("read argv file: %v", err)
		}
		var argv []string
		if err := json.Unmarshal(b, &argv); err != nil {
			t.Fatalf("parse argv: %v", err)
		}
		joined := strings.Join(argv, " ")
		for _, want := range []string{"app-server", "--stdio", "-c", "mcp_servers.pagnet="} {
			if !strings.Contains(joined, want) {
				t.Fatalf("argv %v missing %q", argv, want)
			}
		}
		// The full inline table (command + args + env) is present.
		if !strings.Contains(joined, `mcp_servers.pagnet={command="/opt/pagnet/pagnet",args=["mcp","worker","--socket","/tmp/pagnetd.sock"],env={PAGNET_INSTANCE_ID="inst-mcp",PAGNET_NETWORK_ID="net-1"}}`) {
			t.Fatalf("argv %v missing the full mcp_servers.pagnet inline table", argv)
		}
	})

	t.Run("missingConfigFailsTheLaunchVisibly", func(t *testing.T) {
		// No PAGNET_MCP_CONFIG in the session env: the endpoint must NOT
		// come up silently without its network tools.
		_, m, cp := newCodexFixture(t)
		workspace := t.TempDir()
		sess := m.Session("inst-mcp-missing", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, []string{"PAGNET_INSTANCE_ID=inst-mcp-missing"})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		evs := make(chan session.SessionEvent, 16)
		_, err := m.EnsureActive(ctx, sess, evs)
		close(evs)
		if err == nil {
			t.Fatal("want a visible launch failure when the MCP config is missing")
		}
		if !strings.Contains(err.Error(), "PAGNET_MCP_CONFIG") {
			t.Fatalf("error = %q, want the missing-MCP-config failure", err)
		}
		if cp.Live("inst-mcp-missing") {
			t.Fatal("the endpoint is live despite the missing MCP config")
		}
	})
}

// --- 9. event mapping -------------------------------------------------------------

func TestCodexPersistent_EventMapping(t *testing.T) {
	t.Run("fullTurnStream", func(t *testing.T) {
		_, m, _ := newCodexFixture(t,
			"PAGNET_FAKE_CODEX_DELTA=hello from codex",
			"PAGNET_FAKE_CODEX_ITEM=commandExecution",
			"PAGNET_FAKE_CODEX_TOKENS=10,20,5")
		workspace := t.TempDir()
		sess := m.Session("inst-ev", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-ev"))
		sess.Model = "fake-model-x"

		res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "map me")
		if submitErr != nil {
			t.Fatalf("submit: %v", submitErr)
		}
		if res == nil || !res.Completed {
			t.Fatalf("turn did not complete: %+v", res)
		}
		assertCodexEventTypes(t, evs,
			session.EventSessionStarted,
			session.EventTurnStarted,
			session.EventTurnOutput, // the agent-message delta
			session.EventTurnOutput, // item/started: the command note
			session.EventTurnOutput, // item/completed: the command note
			session.EventTurnCompleted,
		)
		if evs[2].Output != "hello from codex" {
			t.Fatalf("delta output = %q, want the scripted delta", evs[2].Output)
		}
		if evs[3].Output != "[codex] command: ls -la" {
			t.Fatalf("item started note = %q", evs[3].Output)
		}
		if evs[4].Output != "[codex] command completed: ls -la" {
			t.Fatalf("item completed note = %q", evs[4].Output)
		}
		// The terminal event carries the model + the per-turn usage
		// (accumulated from thread/tokenUsage/updated "last").
		done := evs[5]
		if done.Model != "fake-model-x" {
			t.Fatalf("model = %q, want fake-model-x", done.Model)
		}
		if done.InputTokens == nil || *done.InputTokens != 10 {
			t.Fatalf("input tokens = %v, want 10", done.InputTokens)
		}
		if done.OutputTokens == nil || *done.OutputTokens != 20 {
			t.Fatalf("output tokens = %v, want 20", done.OutputTokens)
		}
		if done.CachedTokens == nil || *done.CachedTokens != 5 {
			t.Fatalf("cached tokens = %v, want 5", done.CachedTokens)
		}
	})

	t.Run("failedTurnIsClassified", func(t *testing.T) {
		_, m, _ := newCodexFixture(t,
			"PAGNET_FAKE_CODEX_TURN_STATUS=failed",
			`PAGNET_FAKE_CODEX_TURN_ERROR={"message":"rate limited","codexErrorInfo":"rateLimitExceeded"}`)
		workspace := t.TempDir()
		sess := m.Session("inst-ev-fail", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-ev-fail"))

		res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "fail me")
		if submitErr != nil {
			t.Fatalf("submit: %v", submitErr)
		}
		if res == nil || !res.Failed {
			t.Fatalf("turn did not fail: %+v", res)
		}
		last := evs[len(evs)-1]
		if last.Type != session.EventTurnFailed {
			t.Fatalf("terminal event = %s, want turn.failed", last.Type)
		}
		if last.FailureKind != string(domain.RuntimeFailureRateLimited) {
			t.Fatalf("failure kind = %q, want rate_limited (from codexErrorInfo)", last.FailureKind)
		}
		if last.Error != "rate limited" {
			t.Fatalf("failure error = %q, want the provider message", last.Error)
		}
	})

	t.Run("interruptedStatusIsTurnFailed", func(t *testing.T) {
		_, m, _ := newCodexFixture(t, "PAGNET_FAKE_CODEX_TURN_STATUS=interrupted")
		workspace := t.TempDir()
		sess := m.Session("inst-ev-int", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-ev-int"))

		res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "interrupt me")
		if submitErr != nil {
			t.Fatalf("submit: %v", submitErr)
		}
		if res == nil || !res.Failed {
			t.Fatalf("turn did not fail: %+v", res)
		}
		last := evs[len(evs)-1]
		if last.Type != session.EventTurnFailed {
			t.Fatalf("terminal event = %s, want turn.failed", last.Type)
		}
		if last.FailureKind != string(domain.RuntimeFailureInterrupted) {
			t.Fatalf("failure kind = %q, want interrupted", last.FailureKind)
		}
	})

	t.Run("rejectedTurnStartFailsTheTurn", func(t *testing.T) {
		// A JSON-RPC error on turn/start is a TURN failure (the server
		// rejected it) — the endpoint stays alive and the next turn works.
		_, m, cp := newCodexFixture(t, "PAGNET_FAKE_CODEX_TURN_START_FAIL=1")
		workspace := t.TempDir()
		sess := m.Session("inst-ev-rej", domain.RuntimeCodex, workspace)
		m.SetLaunchEnv(sess, codexMCPEnv("inst-ev-rej"))

		res, evs, submitErr := codexSubmitTurn(t, m, sess, "t1", "reject me")
		if submitErr != nil {
			t.Fatalf("submit: %v", submitErr)
		}
		if res == nil || !res.Failed {
			t.Fatalf("turn did not fail: %+v", res)
		}
		last := evs[len(evs)-1]
		if last.Type != session.EventTurnFailed {
			t.Fatalf("terminal event = %s, want turn.failed", last.Type)
		}
		// The endpoint survived the rejection.
		if !cp.Live("inst-ev-rej") {
			t.Fatal("the endpoint died on a rejected turn/start")
		}
	})
}

// --- 10. interaction surfacing ------------------------------------------------------

// codexInteractionCase runs one scripted native interaction end to end:
// the turn blocks on the server request, the interaction surfaces as a
// generic interaction.started, the resolution travels back as the exact
// JSON-RPC response, and the turn then completes. wantResult / wantError
// select the expected response shape (a result object, or a JSON-RPC
// error when the decision is inexpressible — never a guessed approval).
func codexInteractionCase(t *testing.T, method, decision, answer, kind string, wantResult, wantError string) {
	t.Helper()
	responseFile := filepath.Join(t.TempDir(), "response.json")
	_, m, _ := newCodexFixture(t,
		"PAGNET_FAKE_CODEX_INTERACTION="+method,
		"PAGNET_FAKE_CODEX_RESPONSE_FILE="+responseFile)
	workspace := t.TempDir()
	sess := m.Session("inst-int", domain.RuntimeCodex, workspace)
	m.SetLaunchEnv(sess, codexMCPEnv("inst-int"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start the prompt turn (it parks on the scripted interaction).
	events := make(chan session.SessionEvent, 64)
	done := make(chan struct{})
	var result *session.TurnResult
	var submitErr error
	go func() {
		defer close(done)
		result, submitErr = m.Submit(ctx, sess, session.SubmitRequest{
			TurnID: "t-int", Kind: session.SubmitPrompt, Input: "needs an answer", InputKind: "task",
		}, events)
	}()

	// Wait for the interaction to surface.
	var nativeID string
	sawStarted := false
	for ev := range events {
		if ev.Type == session.EventInteractionStarted && ev.Interaction != nil {
			if ev.Interaction.Kind != kind {
				t.Fatalf("interaction kind = %q, want %q", ev.Interaction.Kind, kind)
			}
			nativeID = ev.Interaction.NativeInteractionID
			sawStarted = true
			break
		}
	}
	if !sawStarted {
		t.Fatal("the native interaction did not surface as interaction.started")
	}
	if nativeID == "" {
		t.Fatal("the interaction carried no native id")
	}

	// Resolve it via the submit path (pagnet never auto-approves).
	ievents := make(chan session.SessionEvent, 16)
	idone := make(chan struct{})
	var ierr error
	go func() {
		defer close(idone)
		_, ierr = m.Submit(ctx, sess, session.SubmitRequest{
			Kind: session.SubmitInteraction, InteractionID: nativeID, Decision: decision, Answer: answer,
		}, ievents)
	}()
	for range ievents {
	}
	<-idone
	if ierr != nil {
		t.Fatalf("interaction submit: %v", ierr)
	}

	// The turn stream carries the resolution, then the terminal event.
	sawResolved := false
	for ev := range events {
		if ev.Type == session.EventInteractionResolved {
			sawResolved = true
		}
	}
	<-done
	if submitErr != nil {
		t.Fatalf("prompt submit: %v", submitErr)
	}
	if result == nil || !result.Completed {
		t.Fatalf("the turn did not complete after the interaction was resolved: %+v", result)
	}
	if !sawResolved {
		t.Fatal("interaction.resolved was not observed on the turn stream")
	}

	// The exact JSON-RPC response the fake (the runtime) received.
	b, err := os.ReadFile(responseFile)
	if err != nil {
		t.Fatalf("the runtime never received the resolution: %v", err)
	}
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("parse the runtime's response line %q: %v", b, err)
	}
	if wantError != "" {
		if resp.Error == nil {
			t.Fatalf("want a JSON-RPC error response (never a guessed approval), got %s", b)
		}
		if resp.Error.Message != wantError {
			t.Fatalf("error message = %q, want %q", resp.Error.Message, wantError)
		}
		if len(resp.Result) > 0 {
			t.Fatalf("an error response must carry no result: %s", b)
		}
		return
	}
	if resp.Error != nil {
		t.Fatalf("want a result response, got error %s", b)
	}
	if string(resp.Result) != wantResult {
		t.Fatalf("result = %s, want %s", resp.Result, wantResult)
	}
}

func TestCodexPersistent_InteractionSurfacing(t *testing.T) {
	t.Run("commandApprovalResolved", func(t *testing.T) {
		codexInteractionCase(t, "item/commandExecution/requestApproval", "resolved", "",
			"permission", `{"decision":"accept"}`, "")
	})
	t.Run("commandApprovalDeclined", func(t *testing.T) {
		codexInteractionCase(t, "item/commandExecution/requestApproval", "declined", "",
			"permission", `{"decision":"decline"}`, "")
	})
	t.Run("commandApprovalCancelled", func(t *testing.T) {
		codexInteractionCase(t, "item/commandExecution/requestApproval", "cancelled", "",
			"permission", `{"decision":"cancel"}`, "")
	})
	t.Run("fileChangeApprovalResolved", func(t *testing.T) {
		codexInteractionCase(t, "item/fileChange/requestApproval", "resolved", "",
			"permission", `{"decision":"accept"}`, "")
	})
	t.Run("userInputResolved", func(t *testing.T) {
		codexInteractionCase(t, "item/tool/requestUserInput", "resolved", "option B",
			"question", `{"answers":{"q1":{"answers":["option B"]}}}`, "")
	})
	t.Run("userInputDeclinedIsAnErrorNotAGuessedAnswer", func(t *testing.T) {
		codexInteractionCase(t, "item/tool/requestUserInput", "declined", "",
			"question", "", "pagnet: the decision cannot be expressed for this request")
	})
	t.Run("elicitationResolved", func(t *testing.T) {
		codexInteractionCase(t, "mcpServer/elicitation/request", "resolved", "",
			"question", `{"action":"accept"}`, "")
	})
	t.Run("elicitationDeclined", func(t *testing.T) {
		codexInteractionCase(t, "openai/form", "declined", "",
			"question", `{"action":"decline"}`, "")
	})
}
