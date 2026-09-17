package runtime

// Phase 1 acceptance tests for the generic persistent-session core driven
// by the deterministic FAKE PERSISTENT runtime (runtime-lifecycle refactor).
//
// These prove the acceptance criteria at the session-core + driver level
// (the unit that the daemon will drive in Phase 2):
//
//  1. 100 logical turns -> exactly 1 active endpoint process.
//  2. PID stable across 20 turns on one session.
//  3. hibernate -> wake resumes the SAME session (id + in-session state).
//  4. busy/idle + interaction request round-trip (answered via Submit).
//  5. materialised semantics (resume refused before the first exchange,
//     succeeds after).
//
// The fake runtime is a REAL deterministic process (pagnet-fake-runtime in
// --persistent mode) launched through the central supervisor's ClassEndpoint
// path — not a test double with stubs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// newPersistentFixture builds the full Phase-1 fixture: a real supervisor,
// the PersistentFake driver wired to it, a session Manager with the driver
// registered, and the state dir the fake uses for its session files.
func newPersistentFixture(t *testing.T) (*proc.Supervisor, *session.Manager, *PersistentFake, string) {
	t.Helper()
	bin := p0FakeBinary(t)
	stateDir := t.TempDir()
	t.Setenv("PAGNET_STATE_DIR", stateDir)
	cfg := proc.DefaultConfig()
	cfg.StateDir = t.TempDir() // supervisor ownership records (separate from the fake's session dir)
	cfg.MonitorInterval = 50 * time.Millisecond
	sup := proc.NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { sup.StopAll(5 * time.Second) })
	pf := NewPersistentFake(bin)
	pf.SetLifecycle(sup)
	m := session.NewManager()
	m.RegisterDriver(pf)
	return sup, m, pf, stateDir
}

// submitTurn drives one prompt turn through the Manager and drains the
// event stream. It returns the settled TurnResult and the events observed.
func submitTurn(t *testing.T, m *session.Manager, sess *session.RuntimeSession, turnID, input string) (*session.TurnResult, []session.SessionEvent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	if submitErr != nil {
		t.Fatalf("submit %s: %v", turnID, submitErr)
	}
	return result, evs
}

// hasSessionEvent reports whether an event of the given type is present.
func hasSessionEvent(evs []session.SessionEvent, ty string) bool {
	for _, ev := range evs {
		if ev.Type == ty {
			return true
		}
	}
	return false
}

// fakeSessionFile is the shape of the fake runtime's on-disk session file
// (the in-session state that must survive hibernation).
type fakeSessionFile struct {
	SessionID string `json:"sessionId"`
	Turns     int    `json:"turns"`
}

func readFakeSession(t *testing.T, stateDir, instanceID string) fakeSessionFile {
	t.Helper()
	path := filepath.Join(stateDir, "sessions", instanceID, "session.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var s fakeSessionFile
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse session file: %v", err)
	}
	return s
}

// Acceptance 1: 100 logical turns -> exactly 1 active endpoint process.
// The persistent endpoint is launched once and reused for every turn; the
// supervisor's endpoint registry must hold exactly one entry.
func TestPersistentFake_100TurnsOneProcess(t *testing.T) {
	sup, m, _, _ := newPersistentFixture(t)
	workspace := t.TempDir()
	sess := m.Session("inst-100", domain.RuntimeFakePersistent, workspace)
	for i := 0; i < 100; i++ {
		res, _ := submitTurn(t, m, sess, fmt.Sprintf("t%d", i), fmt.Sprintf("turn %d", i))
		if !res.Completed {
			t.Fatalf("turn %d did not complete: %+v", i, res)
		}
	}
	if n := sup.Stats().ActiveEndpoints; n != 1 {
		t.Fatalf("expected exactly 1 active endpoint after 100 turns, got %d", n)
	}
	pid := sup.EndpointPID("inst-100")
	if pid == nil {
		t.Fatal("expected a live endpoint PID after 100 turns")
	}
	t.Logf("100 turns served by 1 endpoint (pid %d)", *pid)
}

// Acceptance 2: PID stability across 20 turns on one session. The endpoint
// process must be the SAME process for every turn (not relaunched).
func TestPersistentFake_PIDStableAcross20Turns(t *testing.T) {
	sup, m, _, _ := newPersistentFixture(t)
	workspace := t.TempDir()
	sess := m.Session("inst-pid", domain.RuntimeFakePersistent, workspace)
	var firstPID *int
	for i := 0; i < 20; i++ {
		res, _ := submitTurn(t, m, sess, fmt.Sprintf("t%d", i), fmt.Sprintf("turn %d", i))
		if !res.Completed {
			t.Fatalf("turn %d did not complete: %+v", i, res)
		}
		pid := sup.EndpointPID("inst-pid")
		if pid == nil {
			t.Fatalf("turn %d: no live endpoint PID", i)
		}
		if firstPID == nil {
			firstPID = pid
			continue
		}
		if *pid != *firstPID {
			t.Fatalf("PID changed at turn %d: first=%d now=%d", i, *firstPID, *pid)
		}
	}
	t.Logf("PID %d stable across 20 turns", *firstPID)
}

// Acceptance 3: hibernate -> wake resumes the SAME session. The session id
// and the in-session state (the fake's turn count) must survive; a fresh
// session would have a different id and a reset turn count.
func TestPersistentFake_HibernateWakeResumesSameSession(t *testing.T) {
	sup, m, _, stateDir := newPersistentFixture(t)
	workspace := t.TempDir()
	sess := m.Session("inst-hib", domain.RuntimeFakePersistent, workspace)

	// Turn 1: cold start + exchange (materialises the session).
	res1, _ := submitTurn(t, m, sess, "t1", "first")
	if !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	sessionID1 := res1.SessionID
	if sessionID1 == "" {
		t.Fatal("turn 1 did not report a session id")
	}

	// Hibernate: stop the endpoint, preserve the session.
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after hibernate, got %d", n)
	}

	// Wake: turn 2 resumes the SAME session.
	res2, evs2 := submitTurn(t, m, sess, "t2", "second")
	if !res2.Completed {
		t.Fatalf("turn 2 did not complete: %+v", res2)
	}
	if res2.SessionID != sessionID1 {
		t.Fatalf("session id changed after hibernate/wake: before=%q after=%q", sessionID1, res2.SessionID)
	}
	if !hasSessionEvent(evs2, session.EventSessionResumed) {
		t.Fatalf("expected session.resumed after wake (not a fresh start): %+v", evs2)
	}
	// In-session state survives: the fake's turn count is now 2 (not reset).
	sf := readFakeSession(t, stateDir, "inst-hib")
	if sf.SessionID != sessionID1 {
		t.Fatalf("session file id mismatch: file=%q expected=%q", sf.SessionID, sessionID1)
	}
	if sf.Turns < 2 {
		t.Fatalf("in-session state did not survive hibernate/wake: turns=%d (expected >=2)", sf.Turns)
	}
	t.Logf("session %q resumed after hibernate; in-session turns=%d", sessionID1, sf.Turns)
}

// Acceptance 4: busy/idle + interaction request round-trip. A turn that
// blocks on a scripted native interaction is answered EXTERNALLY via the
// submit path (SubmitInteraction), and the turn then completes.
func TestPersistentFake_InteractionRoundTrip(t *testing.T) {
	_, m, pf, _ := newPersistentFixture(t)
	pf.Env = []string{"PAGNET_FAKE_INTERACTION=question"}
	workspace := t.TempDir()
	sess := m.Session("inst-int", domain.RuntimeFakePersistent, workspace)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Start the prompt turn (it blocks on the scripted interaction).
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

	// Wait for the interaction to start (the turn is busy, parked on it).
	var nativeID string
	sawBusy, sawStarted := false, false
	for ev := range events {
		if ev.Type == session.EventBusy {
			sawBusy = true
		}
		if ev.Type == session.EventInteractionStarted && ev.Interaction != nil {
			nativeID = ev.Interaction.NativeInteractionID
			sawStarted = true
			break
		}
	}
	if !sawBusy {
		t.Fatal("turn did not report busy before parking on the interaction")
	}
	if !sawStarted {
		t.Fatal("interaction did not start")
	}

	// Answer the interaction via the submit path (NOT the blocked turn).
	ievents := make(chan session.SessionEvent, 16)
	idone := make(chan struct{})
	var iresult *session.TurnResult
	var ierr error
	go func() {
		defer close(idone)
		iresult, ierr = m.Submit(ctx, sess, session.SubmitRequest{
			Kind: session.SubmitInteraction, InteractionID: nativeID, Decision: "resolved", Answer: "yes",
		}, ievents)
	}()
	for range ievents {
	}
	<-idone
	if ierr != nil {
		t.Fatalf("interaction submit: %v", ierr)
	}

	// The prompt turn now completes; drain its remaining events. The turn
	// settles on its terminal event (turn.completed); the post-terminal
	// runtime.idle is not part of the turn stream (the Manager returns the
	// session to idle in settlePrompt).
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
		t.Fatalf("prompt turn did not complete after the interaction was answered: %+v", result)
	}
	if !sawResolved {
		t.Fatal("did not observe interaction.resolved on the turn stream")
	}
	if iresult != nil && (iresult.Completed || iresult.Failed) {
		t.Fatalf("interaction submit must not settle a turn: %+v", iresult)
	}
}

// Acceptance 5: materialised semantics. A started-but-unexchanged session is
// NOT resumable (honest refusal, never a silent fresh session); after a real
// exchange the session IS resumable.
func TestPersistentFake_MaterialisedSemantics(t *testing.T) {
	_, m, _, _ := newPersistentFixture(t)
	workspace := t.TempDir()
	ctx := context.Background()

	// Part A: a started-but-unexchanged session is not resumable.
	sessA := m.Session("inst-mat-a", domain.RuntimeFakePersistent, workspace)
	actEvents := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, sessA, actEvents); err != nil {
		close(actEvents)
		t.Fatalf("cold start: %v", err)
	}
	close(actEvents)
	if sessA.NativeID == "" {
		t.Fatal("cold start did not mint a native id")
	}
	if sessA.Materialised {
		t.Fatal("session must not be materialised before an exchange")
	}
	if err := m.Hibernate(ctx, sessA); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	evA := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, sessA, evA); !errors.Is(err, session.ErrNotMaterialised) {
		close(evA)
		t.Fatalf("expected ErrNotMaterialised before the first exchange, got %v", err)
	}
	close(evA)

	// Part B: after a real exchange the session is resumable.
	sessB := m.Session("inst-mat-b", domain.RuntimeFakePersistent, workspace)
	res, _ := submitTurn(t, m, sessB, "t-b", "first exchange")
	if !res.Completed {
		t.Fatalf("exchange turn did not complete: %+v", res)
	}
	if !sessB.Materialised {
		t.Fatal("session should be materialised after an exchange")
	}
	if err := m.Hibernate(ctx, sessB); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	evB := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, sessB, evB); err != nil {
		close(evB)
		t.Fatalf("resume after the first exchange: %v", err)
	}
	close(evB)
}

// D1: an UNEXPECTED endpoint death (SIGKILL — no chance to save) must NOT
// wedge the session. On the next turn the SAME session is transparently
// resumed (same native id, on-disk state preserved) — the turn completes,
// the session is never reported lost, and the in-session state (the fake's
// turn count) continues rather than resetting. Before the fix, every
// subsequent turn failed with "no live endpoint" and the session wedged
// until a daemon restart.
func TestPersistentFake_EndpointDeathResumesSameSession(t *testing.T) {
	sup, m, pf, stateDir := newPersistentFixture(t)
	workspace := t.TempDir()
	sess := m.Session("inst-death", domain.RuntimeFakePersistent, workspace)

	// Turn 1: cold start + exchange (materialises the session; the session
	// file is saved on disk, which is what survives the death).
	res1, _ := submitTurn(t, m, sess, "t1", "first")
	if !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	sessionID1 := res1.SessionID
	if sessionID1 == "" {
		t.Fatal("turn 1 did not report a session id")
	}
	if !sess.Materialised {
		t.Fatal("session should be materialised after turn 1")
	}

	// Get the endpoint PID and KILL it (an unexpected death: SIGKILL).
	pid := sup.EndpointPID("inst-death")
	if pid == nil {
		t.Fatal("no live endpoint PID after turn 1")
	}
	if err := syscall.Kill(*pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill endpoint: %v", err)
	}

	// Wait for the endpoint to be reaped and its record dropped (the
	// reader's EOF path). The supervisor shows 0 active endpoints once the
	// reap unregisters it, and Live() reports the endpoint gone.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sup.Stats().ActiveEndpoints == 0 && !pf.Live("inst-death") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("endpoint not reaped after SIGKILL: %d active", n)
	}
	if pf.Live("inst-death") {
		t.Fatal("Live() still reports the endpoint after SIGKILL")
	}

	// Turn 2: the SAME session is transparently resumed (the on-disk state
	// survives — the session file was saved on turn 1).
	res2, evs2 := submitTurn(t, m, sess, "t2", "second")
	if !res2.Completed {
		t.Fatalf("turn 2 did not complete after endpoint death: %+v", res2)
	}
	if res2.SessionLost {
		t.Fatalf("turn 2 reported the session lost (an endpoint death must not lose the session): %+v", res2)
	}
	if res2.SessionID != sessionID1 {
		t.Fatalf("session id changed after endpoint death: before=%q after=%q", sessionID1, res2.SessionID)
	}
	if !hasSessionEvent(evs2, session.EventSessionResumed) {
		t.Fatalf("expected session.resumed after endpoint death (not a fresh start): %+v", evs2)
	}
	// In-session state survives: the fake's turn count is now 2 (continued,
	// not reset by the death).
	sf := readFakeSession(t, stateDir, "inst-death")
	if sf.SessionID != sessionID1 {
		t.Fatalf("session file id mismatch: file=%q expected=%q", sf.SessionID, sessionID1)
	}
	if sf.Turns < 2 {
		t.Fatalf("in-session state did not survive endpoint death: turns=%d (expected >=2)", sf.Turns)
	}
	t.Logf("session %q resumed after endpoint death; in-session turns=%d", sessionID1, sf.Turns)
}

// D1 (unmaterialised case): an endpoint death BEFORE the first exchange
// must cold-start the session on the next turn (there is no durable state
// to resume — a started-but-unexchanged session is not materialised). The
// turn still completes; it is never a failure.
func TestPersistentFake_EndpointDeathUnmaterialisedColdStarts(t *testing.T) {
	sup, m, pf, _ := newPersistentFixture(t)
	workspace := t.TempDir()
	sess := m.Session("inst-death-cold", domain.RuntimeFakePersistent, workspace)

	// Activate (cold start, mints the native id) but do NOT run an exchange
	// (the session is not materialised — nothing durable to resume).
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	actEvents := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, sess, actEvents); err != nil {
		close(actEvents)
		t.Fatalf("cold start: %v", err)
	}
	close(actEvents)
	if sess.Materialised {
		t.Fatal("session must not be materialised before an exchange")
	}

	// Kill the endpoint (an unexpected death before any exchange).
	pid := sup.EndpointPID("inst-death-cold")
	if pid == nil {
		t.Fatal("no live endpoint PID after cold start")
	}
	if err := syscall.Kill(*pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill endpoint: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sup.Stats().ActiveEndpoints == 0 && !pf.Live("inst-death-cold") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The next turn COLD-STARTS (no durable state to resume) and completes.
	res, evs := submitTurn(t, m, sess, "t1", "first")
	if !res.Completed {
		t.Fatalf("turn did not complete after unmaterialised endpoint death: %+v", res)
	}
	if res.SessionLost {
		t.Fatalf("turn reported the session lost (an endpoint death must not lose the session): %+v", res)
	}
	if !hasSessionEvent(evs, session.EventSessionStarted) {
		t.Fatalf("expected a fresh session.started (cold start) after an unmaterialised death: %+v", evs)
	}
}
