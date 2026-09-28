//go:build linux || darwin

package runtime

// Codex persistent lifecycle regression tests (B7 lifecycle fix).
//
// These drive the CodexPersistent driver against a REAL process supervisor
// (wired via SetLifecycle) and a STUB codex app-server (a bash script that
// speaks the JSON-RPC 2.0 handshake over stdio — the same wire protocol as
// the fake app-server in cmd/pagnet-fake-runtime, reduced to the
// handshake). They prove the B7 lifecycle contract with the
// REQUEST-TERMINATION / REAP split:
//
//   - A. ACTIVATION FAILURE: a failed activation (context cancel during
//     the handshake, or a refused resume — session lost) returns within a
//     bounded time, detaches the endpoint record, and requests termination
//     through the supervisor's TERM path (no forced SIGKILL, no Close/Wait
//     on the activation goroutine); the reader reaps.
//   - B. HANDSHAKE TIMEOUT (PATH B): the process stays alive and never
//     completes the handshake; the activation deadline is a failure, not a
//     hang — Activate returns within the deadline + bounded termination
//     overhead, termination is requested BEFORE the owner Wait, and the
//     reader reaps. A process that closes its stdout without exiting is
//     terminated by the reader BEFORE its owner Wait (the Wait must never
//     block on a process that was never stopped).
//   - C. STOP PATH / SINGLE WAIT OWNER: the stop path (c.Stop) REQUESTS
//     termination and returns bounded; the reader goroutine is the only
//     path that performs the Wait and the endpoint is reaped by it.
//   - D. RETRY SAFETY: while the supervisor still owns a live old endpoint
//     (the logical record was retired but the OS process outlived it — the
//     unkillable case), a retry activation must NOT create a second
//     process (the launch dedup reconciles to the existing managed turn;
//     the ClassEndpoint exclusivity refuses a second endpoint). The old
//     record is removed only by the supervisor's own reap cleanup.
//   - E. NORMAL PATH: a normal handshake → stop → reap is unchanged.
//
// How the contract is observed (all through the supervisor's exported
// surface — the driver and the supervisor are separate packages):
//
//   - REQUEST-TERMINATION vs ABORT: the stub is a plain bash process that
//     honors SIGTERM. A termination requested via StopEndpoint (TERM →
//     grace → KILL) therefore completes on the initial TERM and leaves
//     Stats().ForceKillTotal at 0. A Close/Abort (the pre-fix bug: the
//     activation/stop paths called Handle.Close, which force-SIGKILLs the
//     group) increments ForceKillTotal. Asserting ForceKillTotal == 0
//     deterministically discriminates the fixed path from the buggy one.
//   - READER-OWNED REAP: the reaper unregisters the endpoint BEFORE
//     publishing the exit, so polling EndpointPID == nil observes the
//     reader's completed reap (a path that never reaped — or abandoned a
//     still-tracked process — would time out here).
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

// fakeCodexPersistentScript is a stub codex app-server for the lifecycle
// tests (JSON-RPC 2.0 over stdio, one JSON object per line — the same wire
// protocol as the fake app-server's app-server mode, reduced to the
// handshake). It answers initialize / thread/start / thread/resume and
// stays alive. Modes (env, read by the CHILD):
//
//   - FAKE_CODEX_HANG_HANDSHAKE=1: read the initialize request, then block
//     forever WITHOUT answering (the handshake-timeout fixture: the process
//     stays alive and honors SIGTERM).
//   - FAKE_CODEX_RESUME_FAIL=1: answer thread/resume with a JSON-RPC error
//     (the lost-session fixture).
//   - FAKE_CODEX_CLOSE_STDOUT=1: complete the handshake, then close stdout
//     and stay alive (the reader's PATH-B fixture: the reader gets EOF
//     while the process is still alive).
//
// The stub is a plain bash process: a termination requested through the
// supervisor (TERM → grace → KILL) completes on the initial TERM and
// forces no kill. A forced kill can only come from the abort path
// (Handle.Close/Abort — the pre-fix B7 bug).
const fakeCodexPersistentScript = `#!/usr/bin/env bash
id_of() {
  printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'
}
reply_result() {
  printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$1" "$2"
}
reply_error() {
  printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"fake: %s"}}\n' "$1" "$2"
}
if [ -n "$FAKE_CODEX_HANG_HANDSHAKE" ]; then
  # Read the initialize request, then block forever without answering:
  # the driver's handshake must time out (a clean launch error, not a
  # hang). The process stays alive (sleep) so the driver must terminate
  # it, not wait on it.
  read -r _ || exit 0
  sleep 3600
  exit 0
fi
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      reply_result "$(id_of "$line")" '{"serverInfo":{"name":"fake-codex","version":"0.0.0"}}'
      ;;
    *'"method":"thread/start"'*)
      reply_result "$(id_of "$line")" '{"thread":{"id":"01900000-0000-7000-8000-000000000001","model":"fake-codex-model"}}'
      ;;
    *'"method":"thread/resume"'*)
      if [ -n "$FAKE_CODEX_RESUME_FAIL" ]; then
        reply_error "$(id_of "$line")" "thread/resume refused"
      else
        reply_result "$(id_of "$line")" '{"thread":{"id":"01900000-0000-7000-8000-000000000001","model":"fake-codex-model"}}'
      fi
      ;;
  esac
  if [ -n "$FAKE_CODEX_CLOSE_STDOUT" ] && printf '%s' "$line" | grep -q '"method":"thread/start"'; then
    # Handshake complete: close stdout (the driver's reader gets EOF) and
    # stay alive (the reader must terminate it before its owner Wait —
    # the B7 PATH-B scenario).
    exec 1>&-
    sleep 3600
    exit 0
  fi
done
`

// newCodexLifecycleFixture builds a CodexPersistent driver wired to a REAL
// process supervisor (so the tests can observe the supervisor's registry
// and stats), pointed at the stub codex app-server. extraEnv carries the
// FAKE_CODEX_* scripting knobs for the stub (child environment).
func newCodexLifecycleFixture(t *testing.T, extraEnv ...string) (*proc.Supervisor, *CodexPersistent, string, []string) {
	t.Helper()
	dir := t.TempDir()
	workspace := t.TempDir()
	script := filepath.Join(dir, "codex")
	if err := os.WriteFile(script, []byte(fakeCodexPersistentScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// The stub env vars are read by the CHILD (the stub script), so they
	// must be in the child's environment (sess.Env). The codex driver is
	// fail-closed on the MCP config, so the session env always carries a
	// valid PAGNET_MCP_CONFIG (same shape as the fixture tests).
	stubEnv := codexMCPEnv("inst-1")
	stubEnv = append(stubEnv, extraEnv...)
	cp := NewCodexPersistent(script)
	cfg := proc.DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.MonitorInterval = 50 * time.Millisecond
	cfg.TermGrace = 2 * time.Second
	sup := proc.NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { sup.StopAll(5 * time.Second) })
	cp.SetLifecycle(sup)
	return sup, cp, workspace, stubEnv
}

// newCodexLifecycleSession builds a codex RuntimeSession in workspace with
// the stub's environment.
func newCodexLifecycleSession(workspace string, stubEnv []string) *session.RuntimeSession {
	return &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeCodex,
		Workspace:  workspace,
		Env:        stubEnv,
	}
}

// waitCodexEndpointReaped asserts that the endpoint was fully reaped and
// unregistered by the supervisor within timeout. The reaper unregisters
// the endpoint before publishing the exit, so this observes the READER's
// completed reap (the reader is the single Wait owner; a path that never
// reaped — or abandoned a still-tracked process — would time out here).
func waitCodexEndpointReaped(t *testing.T, sup *proc.Supervisor, instanceID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sup.EndpointPID(instanceID) == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: the endpoint was not reaped and unregistered within %v (the reader must own the reap; the process was not stopped or abandoned)", instanceID, timeout)
}

// assertCodexTerminationRequested asserts that the endpoint's process group
// was stopped via the REQUEST-TERMINATION path (StopEndpoint: TERM → grace
// → KILL), not via an abort (Handle.Close/Abort: immediate forced SIGKILL —
// the pre-fix B7 bug, where the activation/stop paths Close'd the handle).
// The stub honors SIGTERM, so a StopEndpoint-driven termination completes
// on the initial TERM and forces no kill; any forced kill can only come
// from the abort path.
func assertCodexTerminationRequested(t *testing.T, sup *proc.Supervisor, path string) {
	t.Helper()
	if n := sup.Stats().ForceKillTotal; n != 0 {
		t.Fatalf("%s: ForceKillTotal = %d, want 0 — termination must be REQUESTED (StopEndpoint's TERM → grace), not a Close/Abort forced SIGKILL (the pre-fix B7 bug)", path, n)
	}
}

// TestCodexPersistent_ActivationFailureBounded is scenario A: a failed
// activation (context cancel during the handshake, or a refused resume —
// session lost) must return within a bounded time (NOT a wait on the
// process's reap, which is what wedged the Manager's activation lock
// forever on an unkillable process before the fix), detach the endpoint
// record, and terminate the process by the STOP path (requested, not
// aborted); the reader reaps.
func TestCodexPersistent_ActivationFailureBounded(t *testing.T) {
	t.Run("ctxCancel", func(t *testing.T) {
		// The stub never answers initialize: the activation context is
		// cancelled while the handshake is in flight.
		sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t, "FAKE_CODEX_HANG_HANDSHAKE=1")
		sess := newCodexLifecycleSession(workspace, stubEnv)

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := cp.Activate(ctx, sess, make(chan session.SessionEvent, 8))
		elapsed := time.Since(start)

		// A: Activate returns the cancel error.
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Activate = %v, want context.DeadlineExceeded", err)
		}
		// A: bounded — the cancel + the bounded termination request, NOT
		// a wait on the process's reap.
		if elapsed > 10*time.Second {
			t.Fatalf("Activate took %v, want bounded (the cancel must not block on the reap)", elapsed)
		}
		// The failed activation detached ITS endpoint (pointer-specific
		// retire — the Manager's activation lock is released with the
		// record gone).
		if cp.Live("inst-1") {
			t.Fatal("endpoint still registered after the cancel (the failed activation must detach its endpoint)")
		}
		// The reader owns the reap and completes it: the process was
		// stopped (not abandoned), and the supervisor no longer tracks it.
		waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
		// The termination was REQUESTED (TERM → grace via StopEndpoint),
		// not a Close/Abort forced KILL — the pre-fix B7 bug.
		assertCodexTerminationRequested(t, sup, "activation cancel")
	})

	t.Run("sessionLost", func(t *testing.T) {
		// The stub refuses the resume (JSON-RPC error on thread/resume):
		// a lost session, never a silent fresh one.
		sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t, "FAKE_CODEX_RESUME_FAIL=1")
		sess := newCodexLifecycleSession(workspace, stubEnv)
		sess.NativeID = "01900000-0000-7000-8000-000000000001"
		sess.Materialised = true

		start := time.Now()
		_, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
		elapsed := time.Since(start)

		// A: Activate returns the lost-session error.
		if !errors.Is(err, session.ErrSessionLost) {
			t.Fatalf("Activate = %v, want ErrSessionLost", err)
		}
		// A: bounded — a refused resume fails fast (no 15s deadline
		// involved), and the retire must not block on the reap.
		if elapsed > 10*time.Second {
			t.Fatalf("Activate took %v, want bounded (a lost session must not block on the reap)", elapsed)
		}
		if cp.Live("inst-1") {
			t.Fatal("endpoint still registered after the lost session (the failed activation must detach its endpoint)")
		}
		waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
		assertCodexTerminationRequested(t, sup, "session lost")
	})
}

// TestCodexPersistent_HandshakeTimeoutBounded is scenario B (PATH B): the
// process stays alive and never completes the handshake, so the handshake
// deadline is an activation failure, not a hang. Activate must return
// within the deadline + bounded termination overhead (NOT the deadline +
// infinity), the endpoint must be detached, the process must be
// TERMINATED FIRST and reaped by the reader (the reader's owner Wait must
// never block on a process that was never stopped), and the termination
// must be requested, not aborted.
func TestCodexPersistent_HandshakeTimeoutBounded(t *testing.T) {
	t.Run("handshakeTimeout", func(t *testing.T) {
		// The stub never answers initialize: the 15s handshake deadline is
		// an activation failure while the process is alive.
		sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t, "FAKE_CODEX_HANG_HANDSHAKE=1")
		sess := newCodexLifecycleSession(workspace, stubEnv)

		start := time.Now()
		_, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
		elapsed := time.Since(start)
		t.Logf("handshake timeout: Activate failed after %v: %v", elapsed, err)

		if err == nil {
			t.Fatal("Activate succeeded, want an activation failure (no handshake within the activation deadline)")
		}
		// Bounded: the 15s deadline + bounded termination overhead, NOT
		// infinity (the pre-fix PATH B blocked on a live process that was
		// never stopped).
		if elapsed > 30*time.Second {
			t.Fatalf("Activate took %v, want bounded (15s deadline + termination overhead, not a hang)", elapsed)
		}
		// The endpoint record is detached (pointer-specific retire).
		if cp.Live("inst-1") {
			t.Fatal("endpoint still registered after the handshake timeout (it must be detached)")
		}
		// PATH B: the failure path requested termination BEFORE the
		// reader's owner Wait, so the process is stopped and the reader's
		// reap completes — the supervisor no longer tracks it (an
		// abandoned live process would stay tracked and this would time
		// out).
		waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
		// The termination was REQUESTED (TERM → grace via StopEndpoint),
		// not a Close/Abort forced KILL.
		assertCodexTerminationRequested(t, sup, "handshake timeout")
	})

	t.Run("stdoutClosedProcessAlive", func(t *testing.T) {
		// The stub completes the handshake, then closes its stdout without
		// exiting: the reader gets EOF while the process is still alive
		// (PATH B at the reader). The reader must request bounded
		// termination BEFORE its owner Wait — the pre-fix code waited on a
		// live process that was never stopped and hung the reader forever.
		sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t, "FAKE_CODEX_CLOSE_STDOUT=1")
		sess := newCodexLifecycleSession(workspace, stubEnv)

		// The handshake completes: Activate succeeds.
		if _, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		if !cp.Live("inst-1") {
			t.Fatal("endpoint not live after activation")
		}
		// The reader hit EOF with the process still alive: it must have
		// terminated the process and reaped it — the endpoint is gone and
		// the supervisor no longer tracks it, bounded, not a hang.
		start := time.Now()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if !cp.Live("inst-1") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if cp.Live("inst-1") {
			t.Fatalf("endpoint still live %v after the process closed its stdout (the reader must terminate it before its owner Wait — the pre-fix PATH B blocked there)", time.Since(start))
		}
		waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
		assertCodexTerminationRequested(t, sup, "stdout-closed reader path")
	})
}

// TestCodexPersistent_StopPathSingleWaitOwner is scenario C: the endpoint
// reader is the ONLY path that performs the Wait. The stop path (c.Stop)
// REQUESTS termination (StopEndpoint: TERM → grace → KILL) and returns
// bounded; it never aborts (Close/Abort) and never reaps. The reader
// reaps the process and unregisters it.
func TestCodexPersistent_StopPathSingleWaitOwner(t *testing.T) {
	sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t)
	sess := newCodexLifecycleSession(workspace, stubEnv)

	// Cold start (the stub completes the handshake).
	if _, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !cp.Live("inst-1") {
		t.Fatal("endpoint not live after activation")
	}

	// C: the stop path requests termination and returns bounded (the
	// watchdog catches a regression to a stop path that reaps/blocks).
	stopErr := make(chan error, 1)
	go func() { stopErr <- cp.Stop("inst-1") }()
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
	waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
	// The termination was REQUESTED (TERM → grace), not a Close/Abort
	// forced KILL.
	assertCodexTerminationRequested(t, sup, "stop path")
	if cp.Live("inst-1") {
		t.Fatal("endpoint still live after Stop")
	}
}

// TestCodexPersistent_RetrySafetyNoSecondProcess is scenario D: after an
// endpoint is logically retired while its OS process is STILL alive (the
// window that persists indefinitely when the process cannot be killed), a
// retry activation must NOT create a second process. The test isolates
// that safety mechanism: it retires the logical record WITHOUT requesting
// termination (simulating the unkillable case, where the process outlives
// every stop request), so the supervisor still tracks a live endpoint when
// the retry arrives.
//
// The supervisor's launch path is keyed (instance, turn-id) and the codex
// driver always launches with the fixed endpoint turn id, so a second
// launch for the same instance RECONCILES to the existing managed turn
// (dedup — it starts no second process). The retry therefore settles into
// the honest bounded failure: the reconciled endpoint's stdin/stdout are
// fresh pipes the old process never reads, so its handshake can never
// succeed — it fails on the fresh pipe's closure or times out within the
// activation deadline, whichever comes first. The assertions: the retry
// was bounded (not a hang), no second process was launched (LaunchTotal
// stays 1), and the old supervisor record is removed ONLY by the
// supervisor's own reap cleanup (in this killable simulation, the retry's
// stop request terminates the old process and the old reader reaps it; in
// the unkillable case the record survives and stays tracked — covered by
// the proc-level unkillable tests).
func TestCodexPersistent_RetrySafetyNoSecondProcess(t *testing.T) {
	sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t)
	sess := newCodexLifecycleSession(workspace, stubEnv)

	// Cold start (the stub completes the handshake; the endpoint is live).
	if _, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
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
	cp.mu.Lock()
	e := cp.endpoints["inst-1"]
	cp.mu.Unlock()
	if e == nil {
		t.Fatal("endpoint not in the registry")
	}
	cp.dropEndpointRef(e)
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
	_, err := cp.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	elapsed := time.Since(start)
	t.Logf("retry: Activate failed after %v: %v", elapsed, err)
	if err == nil {
		t.Fatal("a retry activation succeeded while the old endpoint is still owned, want the honest bounded failure")
	}
	// Bounded: the handshake deadline + bounded termination overhead at
	// most, not a hang (the reconciled endpoint's pipes are never
	// serviced by the old process, so its handshake fails within the
	// deadline — or earlier, on the fresh pipe's closure).
	if elapsed > 30*time.Second {
		t.Fatalf("retry Activate took %v, want bounded (not a hang)", elapsed)
	}
	// No second process was created (the launch reconciled to the existing
	// managed turn; it did not spawn).
	if n := sup.Stats().LaunchTotal; n != 1 {
		t.Fatalf("LaunchTotal = %d after the retry, want 1 (no second process)", n)
	}
	// The killable old endpoint was terminated by the retry's stop request
	// — the retry's retire requested termination on the instance, and the
	// OLD reader reaped it. Wait for that legitimate reap (bounded): the
	// record is removed by the supervisor's own cleanup, never manually.
	// (In the unkillable case the record survives the failed termination
	// and stays tracked — that edge is covered by the proc-level
	// unkillable tests.)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && sup.EndpointCount() != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := sup.EndpointCount(); n != 0 {
		t.Fatalf("supervisor has %d endpoints at the end, want 0 (the killable old endpoint must be reaped after the stop request; a record surviving termination is the unkillable case)", n)
	}
}

// TestCodexPersistent_NormalPathUnchanged is scenario E: a normal codex
// endpoint (handshake, stop, reap) still works unchanged through the wired
// supervisor: activation succeeds, the stop path requests termination
// (TERM → grace), the reader reaps the process, and the endpoint is
// cleanly gone.
func TestCodexPersistent_NormalPathUnchanged(t *testing.T) {
	sup, cp, workspace, stubEnv := newCodexLifecycleFixture(t)
	sess := newCodexLifecycleSession(workspace, stubEnv)

	events := make(chan session.SessionEvent, 8)
	if _, err := cp.Activate(context.Background(), sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}
	if !cp.Live("inst-1") {
		t.Fatal("endpoint not live after activation")
	}
	// Stop: the stop path requests termination; the reader reaps.
	if err := cp.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitCodexEndpointReaped(t, sup, "inst-1", 30*time.Second)
	assertCodexTerminationRequested(t, sup, "normal path stop")
	if cp.Live("inst-1") {
		t.Fatal("endpoint still live after Stop")
	}
}
