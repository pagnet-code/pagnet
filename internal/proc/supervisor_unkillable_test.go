//go:build unix

// Unkillable-process tests (the live macOS EPERM condition): prove the
// supervisor's termination is BOUNDED and HONEST when the OS refuses to
// kill the group (SIGKILL → EPERM), and that the supervisor-owned reap
// keeps the lifecycle correct.
//
// The EPERM condition is simulated deterministically through the
// Config.signalGroupFn test seam (nil = the platform SignalGroup): while
// a flag is set the seam returns syscall.EPERM for every signal, exactly
// as the OS does for a process that cannot be killed. No privileges and
// no broken host required.
//
// Invariants under test (A1–A4):
//
//   - A1 SINGLE-OWNER WAIT: the dedicated reaper is the only cmd.Wait
//     owner; callers observe the published exit. A stuck child wedges the
//     reaper (a background goroutine holding no lock), never a lifecycle
//     caller.
//   - A3 BOUNDED TERMINATION: TERM → grace → KILL; on KILL → EPERM the
//     caller gets an honest ErrProcessUnkillable WITHIN the grace window
//     (not a wedge, not a silent success), and the supervisor KEEPS
//     TRACKING the process (it does not unregister).
//   - A4 ALL CLASSES: the same contract holds for ClassTurn, ClassPTY,
//     and ClassEndpoint (one shared supervisor, not three copies).
//
// The normal path (a killable / normally-exiting child) is regression-
// guarded: reaped, published, and cleaned up exactly once; a second Wait
// or Close after the reap is an idempotent no-op.
package proc

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// unkillableSupervisor builds a supervisor whose group-kill seam returns
// EPERM while killBlocked is set (simulating an unkillable process group)
// and delegates to the real SignalGroup otherwise. killBlocked is
// returned so the test can release the block (the recovery phase).
func unkillableSupervisor(t *testing.T, killBlocked *atomic.Bool) *Supervisor {
	t.Helper()
	return newTestSupervisor(t, Config{
		MaxActiveTurns:  4,
		TermGrace:       2 * time.Second,
		ReapWaitBound:   1 * time.Second,
		MonitorInterval: time.Hour,
		signalGroupFn: func(pgid int, sig syscall.Signal) error {
			if killBlocked.Load() {
				return syscall.EPERM
			}
			return SignalGroup(pgid, sig)
		},
	})
}

// TestTerminateUnkillableProcessBoundedHonest (ClassTurn): a child the OS
// cannot kill (SIGKILL → EPERM). Termination must return a BOUNDED,
// HONEST failure (ErrProcessUnkillable) within the grace window — not a
// wedge and not a silent success — and the supervisor must KEEP TRACKING
// the process. A bounded wait (WaitDeadline) must return within its
// deadline, and Close must return within the ReapWaitBound. Once the
// group can be killed, the reaper completes the lifecycle exactly once.
func TestTerminateUnkillableProcessBoundedHonest(t *testing.T) {
	var killBlocked atomic.Bool
	killBlocked.Store(true)
	s := unkillableSupervisor(t, &killBlocked)
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-unkill", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	// The test's own cleanup must kill the REAL process (the supervisor
	// cannot — the seam blocks it). Registered AFTER newTestSupervisor's
	// StopAll cleanup, so it runs FIRST (LIFO).
	t.Cleanup(func() {
		killBlocked.Store(false)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	})

	// A3: termination is BOUNDED (within the grace window, not a wedge)
	// and HONEST (ErrProcessUnkillable, not a silent success). The grace
	// window actually ran (the group is alive, so the sequence must poll
	// to the deadline before escalating to KILL).
	start := time.Now()
	err = h.Terminate("test-stop")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrProcessUnkillable) {
		t.Fatalf("Terminate = %v, want ErrProcessUnkillable (honest failure)", err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("Terminate returned in %v, want the full grace window (the group is alive, so the sequence must poll to the deadline)", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("Terminate took %v, want bounded by the grace window (no wedge)", elapsed)
	}

	// A3: the supervisor KEEPS TRACKING the unkillable process (it does
	// NOT unregister — the reaper is still blocked in cmd.Wait).
	s.mu.Lock()
	_, tracked := s.turns[Key{InstanceID: "inst-unkill", TurnID: "t"}]
	s.mu.Unlock()
	if !tracked {
		t.Fatal("supervisor unregistered an unkillable process (it must keep tracking it)")
	}
	if n := s.Stats().ActiveTurns; n != 1 {
		t.Fatalf("ActiveTurns = %d, want 1 (the unkillable process stays tracked)", n)
	}

	// A1: a bounded wait returns within its deadline (no unbounded block
	// on the reaper). The process is still alive, so the exit is not
	// observed and the honest ErrExitNotObserved is returned.
	start = time.Now()
	exit, err := h.WaitDeadline(500 * time.Millisecond)
	elapsed = time.Since(start)
	if !errors.Is(err, ErrExitNotObserved) {
		t.Fatalf("WaitDeadline = (%+v, %v), want ErrExitNotObserved", exit, err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("WaitDeadline took %v, want ~500ms (bounded)", elapsed)
	}

	// A1/A3: Close is BOUNDED too — it aborts (the KILL fails, logged)
	// and returns within the ReapWaitBound (1s) instead of wedging. The
	// process is still alive, so it stays tracked.
	start = time.Now()
	h.Close()
	elapsed = time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Close took %v, want bounded by ReapWaitBound (1s)", elapsed)
	}
	s.mu.Lock()
	_, tracked = s.turns[Key{InstanceID: "inst-unkill", TurnID: "t"}]
	s.mu.Unlock()
	if !tracked {
		t.Fatal("supervisor unregistered an unkillable process after Close (it must keep tracking it)")
	}

	// Recovery: once the group can be killed, the reaper completes the
	// lifecycle exactly once — the exit is published and the turn is
	// unregistered (cleanup ran exactly once).
	killBlocked.Store(false)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	exit, err = h.WaitDeadline(10 * time.Second)
	if err != nil {
		t.Fatalf("WaitDeadline after recovery = (%+v, %v), want the exit (the reaper must complete the lifecycle)", exit, err)
	}
	if !s.WaitForStop("inst-unkill", 5*time.Second) {
		t.Fatal("turn not unregistered after the reaper completed the lifecycle (cleanup must run exactly once)")
	}
}

// TestStopEndpointUnkillableBoundedHonest (ClassEndpoint): the same
// bounded, honest contract for a persistent endpoint. StopEndpoint
// returns ErrProcessUnkillable within the grace window, and the endpoint
// STAYS TRACKED (the record is what refuses a second endpoint for the
// instance). A bounded wait returns within its deadline.
func TestStopEndpointUnkillableBoundedHonest(t *testing.T) {
	var killBlocked atomic.Bool
	killBlocked.Store(true)
	s := unkillableSupervisor(t, &killBlocked)
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "ep-unkill", TurnID: "endpoint",
		Runtime: "test", Class: ClassEndpoint, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	t.Cleanup(func() {
		killBlocked.Store(false)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	})

	start := time.Now()
	err = s.StopEndpoint("ep-unkill")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrProcessUnkillable) {
		t.Fatalf("StopEndpoint = %v, want ErrProcessUnkillable (honest failure)", err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("StopEndpoint returned in %v, want the full grace window", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("StopEndpoint took %v, want bounded by the grace window (no wedge)", elapsed)
	}

	// The unkillable endpoint STAYS TRACKED (the record is the safety
	// mechanism that refuses a second endpoint for the instance).
	if n := s.EndpointCount(); n != 1 {
		t.Fatalf("EndpointCount = %d, want 1 (the unkillable endpoint stays tracked)", n)
	}
	if s.EndpointPID("ep-unkill") == nil {
		t.Fatal("EndpointPID = nil, want the live (unkillable) endpoint pid")
	}

	// A bounded wait returns within its deadline (no unbounded block).
	if _, err := h.WaitDeadline(500 * time.Millisecond); !errors.Is(err, ErrExitNotObserved) {
		t.Fatalf("WaitDeadline = %v, want ErrExitNotObserved (the process is still alive)", err)
	}
}

// TestStopPTYUnkillableBoundedHonest (ClassPTY): the same bounded, honest
// contract for a PTY session. StopPTY returns ErrProcessUnkillable within
// the grace window, the session STAYS TRACKED, and the PTY master stays
// OPEN (the reap that closes it has not happened). Once the group can be
// killed, the reaper reaps, closes the master, and unregisters.
func TestStopPTYUnkillableBoundedHonest(t *testing.T) {
	var killBlocked atomic.Bool
	killBlocked.Store(true)
	s := unkillableSupervisor(t, &killBlocked)
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "pty-unkill", TurnID: PTYTurnID,
		Runtime: "test", Class: ClassPTY, Cmd: exec.Command("sleep", "3600"),
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80}})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	t.Cleanup(func() {
		killBlocked.Store(false)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	})

	start := time.Now()
	err = s.StopPTY("pty-unkill")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrProcessUnkillable) {
		t.Fatalf("StopPTY = %v, want ErrProcessUnkillable (honest failure)", err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("StopPTY returned in %v, want the full grace window", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("StopPTY took %v, want bounded by the grace window (no wedge)", elapsed)
	}

	// The unkillable session STAYS TRACKED, and the PTY master is still
	// OPEN (the reap — which closes it — has not happened).
	s.mu.Lock()
	_, tracked := s.ptyByInst["pty-unkill"]
	s.mu.Unlock()
	if !tracked {
		t.Fatal("supervisor unregistered an unkillable PTY session (it must keep tracking it)")
	}
	if h.PTY() == nil {
		t.Fatal("PTY master closed before the reap (it must stay open while the process is tracked)")
	}

	// Recovery: once the group can be killed, the reaper reaps, closes
	// the master, and unregisters (cleanup ran exactly once).
	killBlocked.Store(false)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if _, err := h.WaitDeadline(10 * time.Second); err != nil {
		t.Fatalf("WaitDeadline after recovery = %v, want the exit (the reaper must complete the lifecycle)", err)
	}
	// Wait for the cleanup (registry removal); it runs after the ptyMaster
	// swap, so by then the master is closed too.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, tracked = s.ptyByInst["pty-unkill"]
		s.mu.Unlock()
		if !tracked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	_, tracked = s.ptyByInst["pty-unkill"]
	s.mu.Unlock()
	if tracked {
		t.Fatal("PTY session still tracked after the reap (cleanup must run exactly once)")
	}
	if h.PTY() != nil {
		t.Fatal("PTY master still open after the reap (finish must close it)")
	}
}

// TestNormalExitReapedOnce (regression guard): a normally-exiting child
// is reaped, published, and cleaned up EXACTLY ONCE (A1 single-owner). A
// second Wait and a Close after the reap are idempotent no-ops, and the
// released slot allows a new turn on the same instance.
func TestNormalExitReapedOnce(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-normal", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sh", "-c", "exit 0")})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, h)

	// The reaper reaps the normally-exiting child; Wait observes the
	// published exit (nil = clean exit 0).
	if err := h.Wait(); err != nil {
		t.Fatalf("Wait = %v, want nil (clean exit)", err)
	}

	// Reaped exactly once: the registry entry is gone and cleanup ran
	// exactly once.
	s.mu.Lock()
	_, tracked := s.turns[Key{InstanceID: "inst-normal", TurnID: "t"}]
	s.mu.Unlock()
	if tracked {
		t.Fatal("turn still registered after the reap (cleanup must run exactly once)")
	}
	if n := s.Stats().CleanupTotal; n != 1 {
		t.Fatalf("CleanupTotal = %d, want 1 (exactly one cleanup)", n)
	}

	// Single-owner idempotency: a second Wait and a Close after the reap
	// are no-ops (no double-reap, no panic).
	if err := h.Wait(); err != nil {
		t.Fatalf("second Wait = %v, want nil (idempotent)", err)
	}
	h.Close()

	// The slot is released: a new turn on the same instance launches.
	h2, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-normal", TurnID: "t2",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatalf("launch after reap = %v, want success (the slot must be released)", err)
	}
	terminateAndReap(t, h2)
}

// TestWaitDeadlineReturnsExitWhenInTime: a bounded wait that expires
// AFTER the child exits returns the published exit (not a timeout) — the
// bound is an honest observation, not a result.
func TestWaitDeadlineReturnsExitWhenInTime(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-wait", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sh", "-c", "sleep 0.2")})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, h)

	start := time.Now()
	exit, err := h.WaitDeadline(10 * time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitDeadline = (%+v, %v), want the exit (the child exits in time)", exit, err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("WaitDeadline took %v, want ~0.2s", elapsed)
	}
	if exit.Reason != "exited" {
		t.Fatalf("exit.Reason = %q, want exited", exit.Reason)
	}
}
