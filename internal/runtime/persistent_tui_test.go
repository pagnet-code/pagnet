package runtime

// Phase 3 (terminal session unification) driver-level tests: the fake
// persistent endpoint OWNS its TUI PTY (launched with a PTYSize), and the
// human plane (the PTY) and the machine plane (the JSONL pipes) are two
// views of the SAME endpoint process and the SAME session.
//
// These prove, at the session-core + driver level:
//
//  1. a human line typed on the PTY drives a turn on the SAME session as
//     the machine submits (the TUI dispatches through the same turn queue);
//  2. `let`/`print` session memory is shared across the human and machine
//     planes (a value set on the PTY is read back on the machine plane);
//  3. the session memory survives hibernate/wake (invariant F);
//  4. the master is exposed on the driver (PTYOwner) and is nil when the
//     endpoint is launched without a PTY (the TUI degrades off — the
//     pre-Phase-3 shape, which the existing tests cover unmodified).
//
// The endpoint is a REAL deterministic process (pagnet-fake-runtime in
// --persistent mode) launched through the supervisor's PTY-owning
// ClassEndpoint path — not a test double.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// fakeSessionFileVars is the shape of the fake runtime's on-disk session
// file including the Phase 3 session memory (vars).
type fakeSessionFileVars struct {
	SessionID string            `json:"sessionId"`
	Turns     int               `json:"turns"`
	Vars      map[string]string `json:"vars,omitempty"`
}

func readFakeSessionVars(t *testing.T, stateDir, instanceID string) fakeSessionFileVars {
	t.Helper()
	path := filepath.Join(stateDir, "sessions", instanceID, "session.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var s fakeSessionFileVars
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse session file: %v", err)
	}
	return s
}

// readFakeSessionVarsPoll is the non-fatal variant for polling: it returns
// a zero value when the file is not (yet) present or parseable, so a caller
// can poll until the turn's save lands.
func readFakeSessionVarsPoll(t *testing.T, stateDir, instanceID string) fakeSessionFileVars {
	t.Helper()
	path := filepath.Join(stateDir, "sessions", instanceID, "session.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return fakeSessionFileVars{}
	}
	var s fakeSessionFileVars
	if err := json.Unmarshal(b, &s); err != nil {
		return fakeSessionFileVars{}
	}
	return s
}

// turnOutput concatenates the transcript chunks (turn.output) of a turn's
// event stream.
func turnOutput(evs []session.SessionEvent) string {
	var sb strings.Builder
	for _, ev := range evs {
		if ev.Type == session.EventTurnOutput {
			sb.WriteString(ev.Output)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// readMaster collects text from the PTY master until every want substring
// has been seen (or the deadline elapses). It returns everything read. The
// PTY line discipline echoes typed input, so the collected text includes
// both the echo and the TUI's own rendering — the assertions look for the
// TUI's specific markers, not the raw echo.
func readMaster(t *testing.T, master *os.File, want []string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		_ = master.SetReadDeadline(deadline)
		n, err := master.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if hasAll(sb.String(), want) {
			return sb.String()
		}
		if err != nil {
			// Deadline or EOF: stop collecting (the caller asserts on what
			// was read; a missing marker is a test failure, not a hang).
			break
		}
	}
	return sb.String()
}

func hasAll(s string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

// TestPersistentFake_TUIHumanLineDrivesTurn: a human line typed on the
// endpoint's OWN PTY drives a turn on the SAME session as the machine
// submits. The `let` set on the human plane is read back on the machine
// plane — proof that both planes are one process and one session.
func TestPersistentFake_TUIHumanLineDrivesTurn(t *testing.T) {
	_, m, pf, stateDir := newPersistentFixture(t)
	pf.PTYSize = &pty.Winsize{Rows: 24, Cols: 80}
	workspace := t.TempDir()
	sess := m.Session("inst-tui", domain.RuntimeFakePersistent, workspace)

	// Turn 1 (machine plane): cold start + exchange (materialises the
	// session, mints the native id).
	res1, _ := submitTurn(t, m, sess, "t1", "first")
	if !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	sessionID1 := res1.SessionID
	if sessionID1 == "" {
		t.Fatal("turn 1 did not report a session id")
	}

	// The endpoint OWNS its TUI PTY: the master is exposed on the driver.
	master := pf.PTYMaster("inst-tui")
	if master == nil {
		t.Fatal("PTYMaster is nil on a PTY-owning endpoint")
	}

	// Human plane: type `let color blue` on the PTY. The TUI dispatches it
	// through the same turn queue as machine submits.
	if _, err := master.Write([]byte("let color blue\n")); err != nil {
		t.Fatalf("write human line to PTY: %v", err)
	}
	// The TUI renders the line and the turn's output. (The markers are
	// unique to the let turn — turn 1's machine output and its "done" are
	// already in the master buffer, so "done" is not a reliable completion
	// marker here.)
	got := readMaster(t, master, []string{"you> let color blue", "let color = blue"}, 15*time.Second)
	if !strings.Contains(got, "you> let color blue") {
		t.Fatalf("TUI did not echo the human line; master saw: %q", got)
	}
	if !strings.Contains(got, "let color = blue") {
		t.Fatalf("TUI did not render the let turn's output; master saw: %q", got)
	}

	// The value is persisted in the session file (the same session the
	// machine plane uses). Poll the file — the authoritative check that the
	// let turn settled and saved (the TUI rendering of the output precedes
	// the save, so the render alone is not proof the turn completed).
	deadline := time.Now().Add(15 * time.Second)
	var sf fakeSessionFileVars
	for {
		sf = readFakeSessionVarsPoll(t, stateDir, "inst-tui")
		if sf.Vars["color"] == "blue" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session memory did not record the human-plane let: vars=%v", sf.Vars)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sf.SessionID != sessionID1 {
		t.Fatalf("session file id mismatch: file=%q expected=%q", sf.SessionID, sessionID1)
	}

	// Machine plane: `print color` reads back the value set on the human
	// plane (same session state across planes).
	res2, evs2 := submitTurn(t, m, sess, "t2", "print color")
	if !res2.Completed {
		t.Fatalf("print turn did not complete: %+v", res2)
	}
	if res2.SessionID != sessionID1 {
		t.Fatalf("print turn used a different session: before=%q after=%q", sessionID1, res2.SessionID)
	}
	if !strings.Contains(turnOutput(evs2), "blue") {
		t.Fatalf("machine-plane print did not read back the human-plane value: output=%q", turnOutput(evs2))
	}
}

// TestPersistentFake_TUIMemorySurvivesHibernate: session memory set on the
// human plane survives hibernate/wake (invariant F) and is still readable
// on the machine plane after the wake.
func TestPersistentFake_TUIMemorySurvivesHibernate(t *testing.T) {
	sup, m, pf, _ := newPersistentFixture(t)
	pf.PTYSize = &pty.Winsize{Rows: 24, Cols: 80}
	workspace := t.TempDir()
	sess := m.Session("inst-tui-hib", domain.RuntimeFakePersistent, workspace)

	// Materialise the session (machine plane).
	res1, _ := submitTurn(t, m, sess, "t1", "first")
	if !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	sessionID1 := res1.SessionID

	// Human plane: set a value.
	master := pf.PTYMaster("inst-tui-hib")
	if master == nil {
		t.Fatal("PTYMaster is nil on a PTY-owning endpoint")
	}
	if _, err := master.Write([]byte("let e2ekey e2ev\n")); err != nil {
		t.Fatalf("write human line to PTY: %v", err)
	}
	readMaster(t, master, []string{"let e2ekey = e2ev", "done"}, 15*time.Second)

	// Hibernate: stop the endpoint, preserve the session (and its memory).
	if err := m.Hibernate(context.Background(), sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after hibernate, got %d", n)
	}

	// Wake: `print e2ekey` on the machine plane still reads the value.
	res2, evs2 := submitTurn(t, m, sess, "t2", "print e2ekey")
	if !res2.Completed {
		t.Fatalf("print turn did not complete after wake: %+v", res2)
	}
	if res2.SessionID != sessionID1 {
		t.Fatalf("session id changed after hibernate/wake: before=%q after=%q", sessionID1, res2.SessionID)
	}
	if !hasSessionEvent(evs2, session.EventSessionResumed) {
		t.Fatalf("expected session.resumed after wake: %+v", evs2)
	}
	if !strings.Contains(turnOutput(evs2), "e2ev") {
		t.Fatalf("session memory did not survive hibernate/wake: output=%q", turnOutput(evs2))
	}
}

// TestPersistentFake_PTYMasterNilWithoutPTY: an endpoint launched WITHOUT a
// PTYSize (the pre-Phase-3 shape) exposes no master — the TUI degrades off
// and the machine plane alone carries everything (the existing tests run in
// exactly this shape and pass unmodified).
func TestPersistentFake_PTYMasterNilWithoutPTY(t *testing.T) {
	_, m, pf, _ := newPersistentFixture(t)
	// PTYSize left nil (the default).
	workspace := t.TempDir()
	sess := m.Session("inst-nopTY", domain.RuntimeFakePersistent, workspace)
	res, _ := submitTurn(t, m, sess, "t1", "first")
	if !res.Completed {
		t.Fatalf("turn did not complete: %+v", res)
	}
	if master := pf.PTYMaster("inst-nopTY"); master != nil {
		t.Fatal("PTYMaster is non-nil on a PTY-less endpoint (the TUI must degrade off)")
	}
}

// I1 proof: a persistent endpoint launched WITHOUT a PTY (PTYSize nil — the
// shape all existing tests use) is FULLY active and usable: Activate →
// Submit → normalized events → Hibernate → re-Activate → Submit all work,
// and Manager.PTYMaster(id) is nil throughout (the no-PTY topology is
// first-class, not a degenerate afterthought). The daemon-level half of
// this proof (an attach attempt on a PTY-less endpoint is a clean defined
// refusal) lives in the daemon tests.
func TestPersistentFake_PTYlessEndpointFullyUsable(t *testing.T) {
	sup, m, pf, _ := newPersistentFixture(t)
	// PTYSize left nil (the default — the pre-Phase-3 / no-PTY shape).
	workspace := t.TempDir()
	sess := m.Session("inst-ptyless", domain.RuntimeFakePersistent, workspace)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Activate (cold start).
	actEvents := make(chan session.SessionEvent, 16)
	if _, err := m.EnsureActive(ctx, sess, actEvents); err != nil {
		close(actEvents)
		t.Fatalf("cold start: %v", err)
	}
	close(actEvents)
	if sess.NativeID == "" {
		t.Fatal("cold start did not mint a native id")
	}
	if master := m.PTYMaster("inst-ptyless"); master != nil {
		t.Fatalf("PTYMaster non-nil after cold start of a PTY-less endpoint: %v", master)
	}

	// Submit (turn 1) → normalized events.
	res1, evs1 := submitTurn(t, m, sess, "t1", "first")
	if !res1.Completed {
		t.Fatalf("turn 1 did not complete: %+v", res1)
	}
	if !hasSessionEvent(evs1, session.EventTurnCompleted) {
		t.Fatalf("turn 1 did not emit a normalized turn.completed: %+v", evs1)
	}
	if master := m.PTYMaster("inst-ptyless"); master != nil {
		t.Fatalf("PTYMaster non-nil after turn 1 of a PTY-less endpoint: %v", master)
	}

	// Hibernate (session preserved).
	if err := m.Hibernate(ctx, sess); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	if n := sup.Stats().ActiveEndpoints; n != 0 {
		t.Fatalf("expected 0 active endpoints after hibernate, got %d", n)
	}
	if master := m.PTYMaster("inst-ptyless"); master != nil {
		t.Fatalf("PTYMaster non-nil after hibernate: %v", master)
	}

	// Re-activate (resume the same session) + Submit (turn 2).
	res2, evs2 := submitTurn(t, m, sess, "t2", "second")
	if !res2.Completed {
		t.Fatalf("turn 2 did not complete after re-activation: %+v", res2)
	}
	if res2.SessionID != res1.SessionID {
		t.Fatalf("session id changed across hibernate/wake: before=%q after=%q", res1.SessionID, res2.SessionID)
	}
	if !hasSessionEvent(evs2, session.EventTurnCompleted) {
		t.Fatalf("turn 2 did not emit a normalized turn.completed: %+v", evs2)
	}
	if master := m.PTYMaster("inst-ptyless"); master != nil {
		t.Fatalf("PTYMaster non-nil after turn 2 of a PTY-less endpoint: %v", master)
	}
	// The driver itself also reports no master (the seam and the driver
	// agree).
	if master := pf.PTYMaster("inst-ptyless"); master != nil {
		t.Fatalf("driver PTYMaster non-nil on a PTY-less endpoint: %v", master)
	}
}
