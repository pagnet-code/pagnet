//go:build linux || darwin

package runtime

// Qwen Dual Output lifecycle regression tests (B7 lifecycle fix).
//
// These drive the QwenPersistent driver against a REAL process supervisor
// (wired via SetLifecycle) and a STUB qwen CLI. They prove the B7
// lifecycle contract: "no session_start within the startup deadline is an
// activation failure, NOT a hang", with the REQUEST-TERMINATION / REAP
// split:
//
//   - A. ACTIVATION CANCEL: the activation context is cancelled before any
//     activation event; Activate returns within a bounded time (the
//     cancel, NOT a wait on the process's reap), detaches the endpoint
//     record, and requests termination through the supervisor.
//   - B. STARTUP DEADLINE: the process stays alive and the events file
//     never appears; the startup deadline is an activation failure, not a
//     hang — Activate returns within the deadline + bounded termination
//     overhead, and the reader requests termination BEFORE its owner Wait
//     (PATH B: the Wait must never block on a process that was never
//     stopped).
//   - C. STOP PATH / SINGLE WAIT OWNER: q.Stop REQUESTS termination and
//     returns bounded; the reader goroutine is the only path that performs
//     the (unbounded-observe) Wait and the endpoint is reaped by it.
//   - D. RETRY SAFETY: while the supervisor still owns a live old endpoint
//     (the logical record was retired but the OS process outlived it — the
//     unkillable case), a new activation must NOT create a second process
//     (the ClassEndpoint exclusivity refuses the launch).
//   - E. NORMAL PATH: a normal qwen endpoint (session_start, stop, reap)
//     still works unchanged.
//
// How the contract is observed (all through the supervisor's exported
// surface — the driver and the supervisor are separate packages):
//
//   - REQUEST-TERMINATION vs ABORT: the stub is a plain bash script that
//     honors SIGTERM. A termination requested via StopEndpoint (TERM →
//     grace → KILL) therefore completes on the initial TERM and leaves
//     Stats().ForceKillTotal at 0. A Close/Abort (the pre-fix bug: the
//     activation/stop paths called Handle.Close, which force-SIGKILLs the
//     group) increments ForceKillTotal. Asserting ForceKillTotal == 0
//     deterministically discriminates the fixed path from the buggy one
//     without reading the process's published Exit (the reader's owner
//     Wait consumes the exit channel, and the unkillable-process seam is
//     private to the proc package).
//   - READER-OWNED REAP: the reaper unregisters the endpoint BEFORE
//     publishing the exit, so sup.WaitForStop observes the reader's
//     completed reap.
//
// The truly-unkillable edge (SIGKILL → EPERM, the live macOS condition)
// is covered by the proc package's supervisor_unkillable_test.go, which
// drives the same StopEndpoint path this driver now relies on; the driver
// fix's contribution there is that NO activation/stop path ever blocks on
// the reap, so the honest bounded StopEndpoint failure is surfaced, the
// supervisor keeps tracking the process, and the activation lock is
// released.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/session"
)

// newQwenLifecycleFixture builds a QwenPersistent driver wired to a REAL
// process supervisor (so the tests can observe the supervisor's registry
// and stats), pointed at the stub qwen CLI. extraEnv carries the
// QWEN_FAKE_* scripting knobs for the stub (child environment).
func newQwenLifecycleFixture(t *testing.T, extraEnv ...string) (*proc.Supervisor, *QwenPersistent, string, []string) {
	t.Helper()
	dir := t.TempDir()
	workspace := t.TempDir()
	stateDir := t.TempDir()
	script := filepath.Join(dir, "qwen")
	if err := os.WriteFile(script, []byte(fakeQwenPersistentScript), 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	// The state dir is read by the DRIVER (the test process), so t.Setenv
	// works for it.
	t.Setenv("PAGNET_STATE_DIR", stateDir)
	// The stub env vars are read by the CHILD (the stub script), so they
	// must be in the child's environment (sess.Env).
	stubEnv := []string{"QWEN_FAKE_ARGS=" + argsPath}
	stubEnv = append(stubEnv, extraEnv...)
	q := NewQwenPersistent(script)
	cfg := proc.DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.MonitorInterval = 50 * time.Millisecond
	cfg.TermGrace = 2 * time.Second
	sup := proc.NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { sup.StopAll(5 * time.Second) })
	q.SetLifecycle(sup)
	return sup, q, workspace, stubEnv
}

// newLifecycleSession builds a qwen RuntimeSession in workspace with the
// stub's environment.
func newLifecycleSession(workspace string, stubEnv []string) *session.RuntimeSession {
	return &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
		Env:        stubEnv,
	}
}

// waitReaped asserts that the endpoint was fully reaped and unregistered
// by the supervisor within timeout. The reaper unregisters the endpoint
// before publishing the exit, so this observes the READER's completed
// reap (the reader is the single Wait owner; a path that never reaped —
// or abandoned a still-tracked process — would time out here).
func waitReaped(t *testing.T, sup *proc.Supervisor, instanceID string, timeout time.Duration) {
	t.Helper()
	if !sup.WaitForStop(instanceID, timeout) {
		t.Fatalf("%s: the endpoint was not reaped and unregistered within %v (the reader must own the reap; the process was not stopped or abandoned)", instanceID, timeout)
	}
}

// assertTerminationRequested asserts that the endpoint's process group was
// stopped via the REQUEST-TERMINATION path (StopEndpoint: TERM → grace →
// KILL), not via an abort (Handle.Close/Abort: immediate forced SIGKILL —
// the pre-fix B7 bug, where the activation/stop paths Close'd the
// handle). The stub honors SIGTERM, so a StopEndpoint-driven termination
// completes on the initial TERM and forces no kill; any forced kill can
// only come from the abort path.
func assertTerminationRequested(t *testing.T, sup *proc.Supervisor, path string) {
	t.Helper()
	if n := sup.Stats().ForceKillTotal; n != 0 {
		t.Fatalf("%s: ForceKillTotal = %d, want 0 — termination must be REQUESTED (StopEndpoint's TERM → grace), not a Close/Abort forced SIGKILL (the pre-fix B7 bug)", path, n)
	}
}

// TestQwenPersistent_ActivationCancelBounded is scenario A: the endpoint
// is launched, no activation event is produced, and the activation context
// is cancelled. Activate must return within a bounded time (the cancel —
// NOT a wait on the process's reap, which is what wedged the Manager's
// activation lock forever on an unkillable process before the fix), the
// endpoint record must be detached, and the process must be terminated
// by the STOP path (requested, not aborted) and reaped by the reader.
func TestQwenPersistent_ActivationCancelBounded(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_NO_START=1")
	sess := newLifecycleSession(workspace, stubEnv)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := q.Activate(ctx, sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)

	// A: Activate returns the cancel error.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Activate = %v, want context.DeadlineExceeded", err)
	}
	// A: bounded — the cancel + the bounded termination request, NOT a
	// wait on the process's reap.
	if elapsed > 10*time.Second {
		t.Fatalf("Activate took %v, want bounded (the cancel must not block on the reap)", elapsed)
	}
	// The failed activation detached ITS endpoint (pointer-specific
	// retire — the Manager's activation lock is released with the record
	// gone).
	if q.Live("inst-1") {
		t.Fatal("endpoint still registered after the cancel (the failed activation must detach its endpoint)")
	}
	// The reader owns the reap and completes it: the process was stopped
	// (not abandoned), and the supervisor no longer tracks it.
	waitReaped(t, sup, "inst-1", 30*time.Second)
	// The termination was REQUESTED (TERM → grace via StopEndpoint), not
	// a Close/Abort forced KILL — the pre-fix B7 bug.
	assertTerminationRequested(t, sup, "activation cancel")
}

// TestQwenPersistent_StartupDeadlineBounded is scenario B: the process
// stays alive and the events file NEVER appears, so the reader's
// waitForEventsFile hits the startup deadline while the process is still
// alive (PATH B). Activate must return the activation failure within the
// deadline + bounded termination overhead (NOT the deadline + infinity),
// the endpoint must be detached, the process must be TERMINATED FIRST and
// reaped by the reader (the reader's owner Wait must never block on a
// process that was never stopped), and the termination must be requested,
// not aborted.
func TestQwenPersistent_StartupDeadlineBounded(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_NO_FILE=1")
	sess := newLifecycleSession(workspace, stubEnv)

	// B: the startup deadline (no events file within 15s while the process
	// is alive) is an activation failure, not a hang. The activation
	// returns within the deadline + bounded termination overhead.
	start := time.Now()
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)
	t.Logf("startup deadline: Activate failed after %v: %v", elapsed, err)

	if err == nil {
		t.Fatal("Activate succeeded, want an activation failure (no session_start within the startup deadline)")
	}
	// Bounded: the 15s deadline + bounded termination overhead, NOT
	// infinity (the pre-fix PATH B blocked the reader's owner Wait on a
	// live process that was never stopped).
	if elapsed > 30*time.Second {
		t.Fatalf("Activate took %v, want bounded (15s deadline + termination overhead, not a hang)", elapsed)
	}
	// The endpoint record is detached (pointer-specific retire).
	if q.Live("inst-1") {
		t.Fatal("endpoint still registered after the startup deadline (it must be detached)")
	}
	// PATH B: the reader requested termination BEFORE its owner Wait, so
	// the process is stopped and the reader's reap completes — the
	// supervisor no longer tracks it (an abandoned live process would
	// stay tracked and this would time out).
	waitReaped(t, sup, "inst-1", 30*time.Second)
	// The termination was REQUESTED (TERM → grace via StopEndpoint), not
	// a Close/Abort forced KILL.
	assertTerminationRequested(t, sup, "startup deadline")
}

// TestQwenPersistent_StopPathSingleWaitOwner is scenario C: the endpoint
// reader is the ONLY path that performs the Wait. The stop path (q.Stop)
// REQUESTS termination (StopEndpoint: TERM → grace → KILL) and returns
// bounded; it never aborts (Close/Abort) and never reaps. The reader
// reaps the process and unregisters it.
func TestQwenPersistent_StopPathSingleWaitOwner(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t)
	sess := newLifecycleSession(workspace, stubEnv)

	// Cold start (the stub writes a session_start).
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !q.Live("inst-1") {
		t.Fatal("endpoint not live after activation")
	}

	// C: the stop path requests termination and returns bounded (the
	// watchdog catches a regression to a stop path that reaps/blocks).
	stopErr := make(chan error, 1)
	go func() { stopErr <- q.Stop("inst-1") }()
	select {
	case err := <-stopErr:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Stop did not return within 30s (the stop path must be bounded and must not reap)")
	}
	// The reader reaped the process (the stop path only requested the
	// termination).
	waitReaped(t, sup, "inst-1", 30*time.Second)
	// The termination was REQUESTED (TERM → grace), not a Close/Abort
	// forced KILL.
	assertTerminationRequested(t, sup, "stop path")
	if q.Live("inst-1") {
		t.Fatal("endpoint still live after Stop")
	}
}

// TestQwenPersistent_RetrySafetyNoSecondProcess is scenario D: after an
// endpoint is logically retired while its OS process is STILL alive (the
// window that persists indefinitely when the process cannot be killed), a
// retry activation must NOT create a second process. The test isolates
// that safety mechanism: it retires the logical record WITHOUT requesting
// termination (simulating the unkillable case, where the process outlives
// every stop request), so the supervisor still tracks a live endpoint when
// the retry arrives.
//
// The supervisor's launch path is keyed (instance, turn-id) and the qwen
// driver always launches with the fixed endpoint turn id, so a second
// launch for the same instance RECONCILES to the existing managed turn
// (dedup — it starts no second process). The retry therefore settles into
// the honest bounded failure ("activation failed; the old endpoint could
// not be terminated"): the reconciled endpoint's events file is gone and
// the stuck old process never recreates it, so the activation times out
// within the startup deadline. The assertions: the retry was bounded (not
// a hang), no second process was launched (LaunchTotal stays 1), and the
// old supervisor record is removed ONLY by the supervisor's own reap
// cleanup (in this killable simulation, the retry's PATH-B stop request
// terminates the old process and a reader reaps it; in the unkillable
// case the record survives and stays tracked — covered by the
// proc-level unkillable tests).
func TestQwenPersistent_RetrySafetyNoSecondProcess(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t)
	sess := newLifecycleSession(workspace, stubEnv)

	// Cold start (the stub writes a session_start; the endpoint is live).
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	// The supervisor owns the live endpoint.
	if sup.EndpointPID("inst-1") == nil {
		t.Fatal("supervisor does not own the endpoint after launch")
	}
	if n := sup.Stats().LaunchTotal; n != 1 {
		t.Fatalf("LaunchTotal = %d after the first launch, want 1", n)
	}
	// Retire the logical record WITHOUT stopping the process (the pointer-
	// specific detach the activation/stop paths use, minus the termination
	// request — the unkillable window, where the OS process outlives the
	// logical endpoint).
	q.mu.Lock()
	e := q.endpoints["inst-1"]
	q.mu.Unlock()
	if e == nil {
		t.Fatal("endpoint not in the registry")
	}
	q.dropEndpointRef(e)
	// The supervisor still owns the live endpoint (the record is the
	// safety mechanism; only the reader's reap removes it).
	if sup.EndpointPID("inst-1") == nil {
		t.Fatal("supervisor no longer owns the endpoint (it must keep tracking the live process)")
	}
	// D: a retry activation of the (materialised) session must NOT create
	// a second process. Materialised is true: the Manager holds the
	// session state and re-activates — it passes the resume gate and
	// reaches the supervisor's launch path.
	sess.Materialised = true
	start := time.Now()
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a retry activation succeeded while the old endpoint is still owned, want the honest bounded failure")
	}
	// Bounded: the startup deadline + bounded termination overhead, not a
	// hang (the reconciled endpoint's events file is gone; the stuck old
	// process never recreates it).
	if elapsed > 30*time.Second {
		t.Fatalf("retry Activate took %v, want bounded (not a hang)", elapsed)
	}
	// No second process was created (the launch reconciled to the existing
	// managed turn; it did not spawn).
	if n := sup.Stats().LaunchTotal; n != 1 {
		t.Fatalf("LaunchTotal = %d after the retry, want 1 (no second process)", n)
	}
	// The killable old endpoint was terminated by the retry's PATH-B stop
	// request — the retry's reader found the old process alive but
	// unresponsive (its events file was gone) and requested termination
	// BEFORE its owner Wait — and then reaped by a reader. Wait for that
	// legitimate reap (bounded): the record is removed by the supervisor's
	// own cleanup, never manually. (In the unkillable case the record
	// survives the failed termination and stays tracked — that edge is
	// covered by the proc-level unkillable tests.)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && sup.EndpointCount() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := sup.EndpointCount(); n != 0 {
		t.Fatalf("supervisor has %d endpoints at the end, want 0 (the killable old endpoint must be reaped after the PATH-B stop request; a record surviving termination is the unkillable case)", n)
	}
}

// TestQwenPersistent_NormalPathUnchanged is scenario E: a normal qwen
// endpoint (session_start, stop, reap) still works unchanged through the
// wired supervisor: activation succeeds, the stop path requests
// termination (TERM → grace), the reader reaps the process, and the
// endpoint is cleanly gone.
func TestQwenPersistent_NormalPathUnchanged(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t)
	sess := newLifecycleSession(workspace, stubEnv)

	events := make(chan session.SessionEvent, 8)
	if _, err := q.Activate(context.Background(), sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	if !q.Live("inst-1") {
		t.Fatal("endpoint not live after activation")
	}
	// Stop: the stop path requests termination; the reader reaps.
	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitReaped(t, sup, "inst-1", 30*time.Second)
	assertTerminationRequested(t, sup, "normal path stop")
	if q.Live("inst-1") {
		t.Fatal("endpoint still live after Stop")
	}
}
