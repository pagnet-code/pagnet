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
	"strconv"
	"strings"
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
	// S2: the argv record is WRITTEN by the sandboxed child, so it must
	// live in a granted RW location — the workspace (the stub's own dir
	// is RO: the binary support grant).
	argsPath := filepath.Join(workspace, "args.txt")
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
//
// The startup budget is the DRIVER-OWNED field (the driver's production
// default is 60s); the test sets a short one so the scenario stays
// deterministic and the suite stays fast.
func TestQwenPersistent_StartupDeadlineBounded(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_NO_FILE=1")
	const budget = 600 * time.Millisecond
	q.StartupTimeout = budget
	sess := newLifecycleSession(workspace, stubEnv)

	// B: the startup deadline (no events file within the budget while the
	// process is alive) is an activation failure, not a hang. The activation
	// returns within the deadline + bounded termination overhead.
	events := make(chan session.SessionEvent, 8)
	start := time.Now()
	_, err := q.Activate(context.Background(), sess, events)
	elapsed := time.Since(start)
	t.Logf("startup deadline: Activate failed after %v: %v", elapsed, err)

	if err == nil {
		t.Fatal("Activate succeeded, want an activation failure (no session_start within the startup budget)")
	}
	// The deadline is honored, not shortened: the failure may not arrive
	// before the budget the driver granted the startup.
	if elapsed < budget {
		t.Fatalf("Activate failed after %v, before the %v startup budget it granted", elapsed, budget)
	}
	// Bounded: the deadline + bounded termination overhead, NOT infinity (the
	// pre-fix PATH B blocked the reader's owner Wait on a live process that
	// was never stopped). The one-budget-per-attempt invariant is pinned by
	// TestQwenPersistent_StartupBudgetIsOneBudgetPerActivation, not by this
	// (deliberately generous) overhead bound.
	if elapsed > 4*time.Second {
		t.Fatalf("Activate took %v, want ~the %v deadline + bounded termination overhead (not a hang)", elapsed, budget)
	}
	// The process-state diagnostic rides the failure surface. In this
	// scenario the file NEVER appears, and the two stages that watch the ONE
	// shared deadline (the reader's file deadline and Activate's own timer)
	// race for who reports it first:
	//   - the reader's file deadline: Activate returns ErrSessionLost and
	//     the lost activation event carries the file-deadline message with
	//     the process=alive suffix;
	//   - Activate's own timer: the returned error carries the full
	//     startup diagnostic (events_file=absent; process=alive).
	// Both are the deadline failure with the diagnostic attached, and both
	// name the effective budget — assert it on the surface that fired.
	budgetText := startupBudgetText(budget)
	if errors.Is(err, session.ErrSessionLost) {
		var actEv session.SessionEvent
		select {
		case actEv = <-events:
		case <-time.After(2 * time.Second):
			t.Fatal("no activation event on the reader-deadline path")
		}
		if actEv.Type != session.EventSessionLost {
			t.Fatalf("activation event = %q, want %q", actEv.Type, session.EventSessionLost)
		}
		if !strings.Contains(actEv.Error, "qwen event file did not appear within the "+budgetText+" startup budget; process=alive") {
			t.Fatalf("lost event error = %q, want the file-deadline message naming the %s budget with the process=alive diagnostic", actEv.Error, budgetText)
		}
	} else {
		if !strings.Contains(err.Error(), "events_file=absent") || !strings.Contains(err.Error(), "process=alive") {
			t.Fatalf("error = %q, want the startup diagnostic (events_file=absent; process=alive)", err.Error())
		}
		if !strings.Contains(err.Error(), budgetText+" startup budget") {
			t.Fatalf("error = %q, want it to name the effective %s startup budget", err.Error(), budgetText)
		}
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

// TestQwenPersistent_StartupDeadlineDiagCarriesEventsTail is scenario F:
// the events file APPEARS (with pre-session, non-session_start lines) and
// the process stays alive, but the handshake never arrives — the TUI is up
// in a pre-session state (first-run onboarding / auth). This is the
// hibernated-instance black box: the generic timeout error used to be the
// only evidence. Here the reader is happily polling the existing file (it
// has no deadline of its own in this scenario), so Activate's OWN startup
// timer deterministically fires and the returned error must carry the
// startup diagnostic: the events-file size + a bounded tail with the file's
// own content, and process=alive (the state at the deadline moment, computed
// before the retirement requests termination).
func TestQwenPersistent_StartupDeadlineDiagCarriesEventsTail(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_PRE_SESSION=1")
	const budget = 800 * time.Millisecond
	q.StartupTimeout = budget
	sess := newLifecycleSession(workspace, stubEnv)

	start := time.Now()
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)
	t.Logf("startup deadline (file appeared, no session_start): Activate failed after %v: %v", elapsed, err)

	if err == nil {
		t.Fatal("Activate succeeded, want an activation failure (no session_start within the startup budget)")
	}
	// Bounded: the deadline + bounded termination overhead, NOT a hang.
	if elapsed > 15*time.Second {
		t.Fatalf("Activate took %v, want bounded (%v deadline + termination overhead, not a hang)", elapsed, budget)
	}
	// The message keeps its shape and now names the effective budget the
	// operator can act on...
	prefix := "qwen persistent: activation timed out (no session_start within the " + startupBudgetText(budget) + " startup budget)"
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("error = %q, want the prefix %q", err.Error(), prefix)
	}
	// ...and the diagnostic now rides the error: the events file existed
	// (its size + a bounded tail carrying the file's own content — the
	// pre-session probe lines the stub wrote), and the process was alive
	// at the deadline moment.
	if !strings.Contains(err.Error(), "process=alive") {
		t.Fatalf("error = %q, want the process=alive diagnostic", err.Error())
	}
	if strings.Contains(err.Error(), "events_file=absent") || !strings.Contains(err.Error(), "bytes, tail=") {
		t.Fatalf("error = %q, want the events_file=<N bytes, tail=...> diagnostic (the file existed)", err.Error())
	}
	if !strings.Contains(err.Error(), "onboarding-pending-42") {
		t.Fatalf("error = %q, want the events-file tail content (the file's own pre-session line)", err.Error())
	}
	// The endpoint record is detached (pointer-specific retire).
	if q.Live("inst-1") {
		t.Fatal("endpoint still registered after the startup deadline (it must be detached)")
	}
	// The process was terminated by the retirement (requested, not
	// aborted) and reaped by the reader.
	waitReaped(t, sup, "inst-1", 30*time.Second)
	assertTerminationRequested(t, sup, "startup deadline diag")
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
	// The retry's failure is bounded by the startup budget (the reconciled
	// endpoint's events file is gone and the stuck old process never
	// recreates it); the budget's LENGTH is not what this test is about, so
	// it is set short to keep the scenario fast and deterministic.
	q.StartupTimeout = 600 * time.Millisecond
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

// --- driver-owned startup budget -------------------------------------------
//
// The scenarios below pin the STARTUP budget contract of the production
// driver: the budget is the driver's own (never the fake runtime driver's
// test deadline), it is the MAXIMUM for a live process whose handshake has
// not completed yet, and one activation attempt gets exactly ONE budget.

// TestQwenPersistent_DelayedStartupWithinBudgetSucceeds is the production
// incident as a test: a HEALTHY qwen cold start that is merely slow — the
// process is alive, the machine channel is fine, and session_start only
// arrives after a delay. The same stubbed delay is run against a budget that
// covers it (activation SUCCEEDS — the acceptance proof: a startup inside
// the budget is never killed) and against a budget it exceeds (activation
// FAILS, at the budget, with the diagnostic). Nothing about the process
// differs between the two runs: only the driver's budget.
func TestQwenPersistent_DelayedStartupWithinBudgetSucceeds(t *testing.T) {
	const delayMS = 1200

	t.Run("withinBudgetSucceeds", func(t *testing.T) {
		sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_START_DELAY_MS="+strconv.Itoa(delayMS))
		const budget = 15 * time.Second
		q.StartupTimeout = budget
		sess := newLifecycleSession(workspace, stubEnv)

		start := time.Now()
		_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
		elapsed := time.Since(start)
		t.Logf("delayed startup: Activate returned after %v (err=%v)", elapsed, err)

		// THE PROOF: the delayed-but-healthy startup is activated, not
		// killed.
		if err != nil {
			t.Fatalf("Activate = %v, want success — a healthy startup that finishes within the %v budget must not be terminated", err, budget)
		}
		// The handshake really was delayed (an instant stub would prove
		// nothing): the activation could not have completed before the stub
		// emitted session_start.
		if elapsed < time.Duration(delayMS)*time.Millisecond/2 {
			t.Fatalf("Activate returned after %v, faster than the %dms startup delay — the stub did not delay the handshake", elapsed, delayMS)
		}
		if elapsed >= budget {
			t.Fatalf("Activate returned after %v, at or past the %v budget", elapsed, budget)
		}
		if sess.NativeID == "" {
			t.Fatal("NativeID not set after the delayed activation (the handshake was not consumed)")
		}
		if !q.Live("inst-1") {
			t.Fatal("endpoint not live after the delayed activation")
		}
		if err := q.Stop("inst-1"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		waitReaped(t, sup, "inst-1", 30*time.Second)
		assertTerminationRequested(t, sup, "delayed startup")
	})

	t.Run("beyondBudgetFailsAtTheBudget", func(t *testing.T) {
		// The identical slow startup, a budget it cannot finish inside.
		sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_START_DELAY_MS="+strconv.Itoa(delayMS))
		const budget = 250 * time.Millisecond
		q.StartupTimeout = budget
		sess := newLifecycleSession(workspace, stubEnv)

		events := make(chan session.SessionEvent, 8)
		start := time.Now()
		_, err := q.Activate(context.Background(), sess, events)
		elapsed := time.Since(start)
		t.Logf("startup beyond the budget: Activate failed after %v: %v", elapsed, err)

		if err == nil {
			t.Fatalf("Activate succeeded, want the startup-budget failure (session_start at %dms > the %v budget)", delayMS, budget)
		}
		if elapsed < budget {
			t.Fatalf("Activate failed after %v, before the %v budget it granted", elapsed, budget)
		}
		if elapsed > 10*time.Second {
			t.Fatalf("Activate took %v, want the %v budget + bounded termination overhead", elapsed, budget)
		}
		// Whichever stage reports the expired shared deadline, the surfaced
		// text names the effective budget and the process liveness.
		text := err.Error()
		if errors.Is(err, session.ErrSessionLost) {
			// The reader's file-deadline surface: the reason rides the lost
			// activation event it published.
			var actEv session.SessionEvent
			select {
			case actEv = <-events:
			case <-time.After(2 * time.Second):
				t.Fatal("no activation event on the reader-deadline path")
			}
			if actEv.Type != session.EventSessionLost {
				t.Fatalf("activation event = %q, want %q", actEv.Type, session.EventSessionLost)
			}
			text = actEv.Error
		}
		if !strings.Contains(text, "process=alive") {
			t.Fatalf("text = %q, want the process=alive diagnostic (the process was alive, merely slow)", text)
		}
		if !strings.Contains(text, startupBudgetText(budget)+" startup budget") {
			t.Fatalf("text = %q, want it to name the effective %s startup budget", text, startupBudgetText(budget))
		}
		if q.Live("inst-1") {
			t.Fatal("endpoint still registered after the startup-budget failure")
		}
		waitReaped(t, sup, "inst-1", 30*time.Second)
		assertTerminationRequested(t, sup, "startup beyond the budget")
	})
}

// TestQwenPersistent_EarlyProcessExitFailsFast pins that the startup budget
// is only the MAXIMUM for a live process. The endpoint exits on its own
// before the handshake ("No saved session found" — exit 1, doc §5.2), and
// the activation must settle in milliseconds — the full production default
// (60s here, left at its zero value) must NOT be paid for a dead process.
func TestQwenPersistent_EarlyProcessExitFailsFast(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_NO_SESSION=1")
	// The field is deliberately left at its zero value: this is the
	// production default budget (60s), and it must not slow the early exit.
	if got := q.startupTimeout(); got != 60*time.Second {
		t.Fatalf("default startupTimeout = %v, want the 60s production default", got)
	}
	sess := newLifecycleSession(workspace, stubEnv)

	start := time.Now()
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)
	t.Logf("early exit: Activate failed after %v: %v", elapsed, err)

	if !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("Activate = %v, want ErrSessionLost (the process exited before the handshake)", err)
	}
	// Fast: an order of magnitude inside the 60s budget. The failure is the
	// process exit, not the deadline.
	if elapsed > 10*time.Second {
		t.Fatalf("Activate took %v for a process that exited immediately, want a fast failure (the %v startup budget must not be paid)", elapsed, q.startupTimeout())
	}
	if q.Live("inst-1") {
		t.Fatal("endpoint still registered after the early exit")
	}
	waitReaped(t, sup, "inst-1", 30*time.Second)
	assertTerminationRequested(t, sup, "early exit")
}

// TestQwenPersistent_StartupBudgetIsOneBudgetPerActivation pins the
// one-budget-per-attempt invariant. The handshake is awaited by TWO stages —
// the reader's events-file wait and Activate's activation-event wait — and
// they must observe ONE deadline fixed at launch, not a fresh budget each (a
// second budget would double the real limit and make the surfaced error text
// lie about it). Observed through the file-wait stage directly: it returns
// its failure at the launch deadline, leaving NOTHING pending for the other
// stage.
func TestQwenPersistent_StartupBudgetIsOneBudgetPerActivation(t *testing.T) {
	sup, q, workspace, stubEnv := newQwenLifecycleFixture(t, "QWEN_FAKE_NO_FILE=1")
	const budget = 1500 * time.Millisecond
	q.StartupTimeout = budget
	sess := newLifecycleSession(workspace, stubEnv)

	launchAt := time.Now()
	e, err := q.launchEndpoint(sess)
	if err != nil {
		t.Fatalf("launchEndpoint: %v", err)
	}
	// The endpoint carries the driver's resolved budget and the absolute
	// instant it expires — one budget, measured from the launch.
	if e.startupBudget != budget {
		t.Fatalf("endpoint startupBudget = %v, want the driver's %v", e.startupBudget, budget)
	}
	if remaining := time.Until(e.startupDeadline); remaining > budget || remaining <= 0 {
		t.Fatalf("startup deadline is %v away at launch, want within the %v budget", remaining, budget)
	}
	// The file never appears (QWEN_FAKE_NO_FILE): this stage returns its
	// failure AT the launch deadline — about one budget after launch, never
	// two. The bound is deliberately below 2x the budget.
	_, werr := e.waitForEventsFile()
	waited := time.Since(launchAt)
	t.Logf("file wait returned after %v: %v", waited, werr)
	if werr == nil {
		t.Fatal("waitForEventsFile succeeded, want the file-absent deadline failure")
	}
	if waited < budget {
		t.Fatalf("the file wait returned after %v, before the %v deadline", waited, budget)
	}
	if waited > budget+900*time.Millisecond {
		t.Fatalf("the file wait returned after %v, past one budget + poll slack (2x the budget would be %v — a second, independent budget)", waited, 2*budget)
	}
	// The other consumer of the same deadline (Activate's timer, computed as
	// the time remaining to it) has nothing left to wait on.
	if time.Now().Before(e.startupDeadline) {
		t.Fatalf("the startup deadline is still %v away after the file wait — the stages would get one budget EACH", time.Until(e.startupDeadline))
	}
	q.retireEndpoint(e)
	waitReaped(t, sup, "inst-1", 30*time.Second)
	assertTerminationRequested(t, sup, "one startup budget")
}
