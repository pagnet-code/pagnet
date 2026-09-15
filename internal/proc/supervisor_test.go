//go:build unix

// Supervisor lifecycle tests (abuse addendum Part B §46–§51).
//
// These exercise the CENTRAL turn-process supervisor directly (white-box,
// same package): local launch idempotency, the per-instance exclusivity
// invariant, the launch guards (semaphore / owned ceiling / host pressure),
// the retry-safety machinery (circuit + exponential backoff, injectable
// clock), descendant reclaim, cancellation, process-explosion detection,
// and shutdown. They run on every unix platform (Linux AND macOS) so the
// containment contract is not Linux-only (§51).
package proc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

// newTestSupervisor builds a supervisor with a discarded logger and a
// StopAll cleanup so no test leaves an owned process group behind.
func newTestSupervisor(t *testing.T, cfg Config) *Supervisor {
	t.Helper()
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	s := NewSupervisor(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { s.StopAll(5 * time.Second) })
	return s
}

// waitForPID blocks until the handle's direct child has a pid (the launch
// registered and started). Returns the pid.
func waitForPID(t *testing.T, h *Handle) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pid := h.PID(); pid != 0 {
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process never started (pid 0)")
	return 0
}

// waitForGroupCount blocks until the group holds at least want processes.
func waitForGroupCount(t *testing.T, pgid, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if CountGroup(pgid) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("group %d never reached %d processes (last %d)", pgid, want, CountGroup(pgid))
}

// waitGroupGone blocks until the group is empty (all members reaped).
func waitGroupGone(t *testing.T, pgid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !GroupAlive(pgid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process group %d still alive (leak)", pgid)
}

// terminateAndReap terminates the group AND reaps the direct child
// concurrently — exactly how the adapter's turn loop / terminal exit loop
// behaves in production. Reaping concurrently means the direct child's
// zombie clears while Terminate polls GroupAlive, so the test does not
// wait out the full TermGrace.
func terminateAndReap(t *testing.T, h *Handle) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = h.Wait(); close(done) }()
	h.Terminate("test done")
	<-done
}

// --- §48 duplicate-launch -----------------------------------------------------

// TestLaunchDedupConcurrent: N concurrent goroutines submit the SAME
// (InstanceID, TurnID). Exactly ONE process must be spawned; every caller
// receives the same handle/pid. Run under the race detector.
func TestLaunchDedupConcurrent(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 8, MonitorInterval: time.Hour})
	const N = 16
	ctx := context.Background()
	handles := make([]*Handle, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h, err := s.Launch(ctx, LaunchRequest{
				InstanceID: "inst-1", TurnID: "turn-1",
				Runtime: "test", Class: ClassTurn,
				Cmd: exec.Command("sleep", "3600"),
			})
			handles[i] = h
			errs[i] = err
		}(i)
	}
	close(start) // release all at once (maximize the race window)
	wg.Wait()
	for i := 0; i < N; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: Launch: %v", i, errs[i])
		}
		if handles[i] == nil {
			t.Fatalf("goroutine %d: nil handle", i)
		}
	}
	pid := waitForPID(t, handles[0])
	for i := 0; i < N; i++ {
		if got := handles[i].PID(); got != pid {
			t.Fatalf("handle %d pid %d != %d — duplicate launch", i, got, pid)
		}
	}
	s.mu.Lock()
	nTurns := len(s.turns)
	s.mu.Unlock()
	if nTurns != 1 {
		t.Fatalf("registry holds %d turns, want exactly 1", nTurns)
	}
	if n := CountGroup(pid); n != 1 {
		t.Fatalf("group %d holds %d processes, want 1", pid, n)
	}
	// Owner terminate + reap (all 16 handles share one managedTurn).
	terminateAndReap(t, handles[0])
}

// TestLaunchDedupSequential: a durable redelivery of an in-flight turn
// (same key, after the first is running) reconciles to the existing
// process — it never spawns a second one.
func TestLaunchDedupSequential(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	ctx := context.Background()
	h1, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	pid1 := waitForPID(t, h1)
	// Redelivery of the same durable command.
	h2, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	if h2.PID() != pid1 {
		t.Fatalf("redelivery spawned a second process (pid %d != %d)", h2.PID(), pid1)
	}
	s.mu.Lock()
	n := len(s.turns)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("registry holds %d turns, want 1", n)
	}
	terminateAndReap(t, h1)
}

// --- per-instance exclusivity (§27) ------------------------------------------

func TestLaunchExclusivity(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	ctx := context.Background()
	h1, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, h1)
	// A DIFFERENT turn on the same instance is refused (one active turn
	// per AgentInstance, enforced locally).
	_, err = s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-2",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if !errors.Is(err, ErrInstanceBusy) {
		t.Fatalf("expected ErrInstanceBusy, got %v", err)
	}
	// A different instance is unaffected.
	h2, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-2", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatalf("different instance refused: %v", err)
	}
	// Owner terminate + reap both.
	for _, h := range []*Handle{h1, h2} {
		terminateAndReap(t, h)
	}
}

// TestStopThenImmediateStart (external audit F-004): Stop is async —
// Terminate initiates the kill and the owner's reap (which unregisters the
// turn from byInstance) follows independently. A Stop→immediate-Start that
// does not wait would race the reap and hit ErrInstanceBusy while the old
// turn is still registered. After WaitForStop, an immediate Launch for the
// same instance must succeed.
func TestStopThenImmediateStart(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	ctx := context.Background()
	h1, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, h1)

	// Simulate the owner (the adapter's turn loop) that reaps the turn:
	// it blocks on Wait until the process exits.
	ownerDone := make(chan struct{})
	go func() { _ = h1.Wait(); close(ownerDone) }()

	// Stop the turn (async) and wait for the reap + unregister.
	if err := s.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !s.WaitForStop("inst-1", 10*time.Second) {
		t.Fatal("WaitForStop timed out (turn not reaped/unregistered)")
	}
	<-ownerDone

	// An immediate Launch for the same instance must now succeed.
	h2, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-2",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatalf("immediate start after stop: %v (want success, the old turn is reaped)", err)
	}
	waitForPID(t, h2)
	terminateAndReap(t, h2)
}

// --- active-turn bound (§29) --------------------------------------------------

func TestMaxActiveTurns(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 2, MonitorInterval: time.Hour})
	ctx := context.Background()
	var handles []*Handle
	for _, id := range []string{"a", "b"} {
		h, err := s.Launch(ctx, LaunchRequest{InstanceID: id, TurnID: "t",
			Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
		if err != nil {
			t.Fatalf("launch %s: %v", id, err)
		}
		handles = append(handles, h)
	}
	// The semaphore is full: the third active turn is refused.
	_, err := s.Launch(ctx, LaunchRequest{InstanceID: "c", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if !errors.Is(err, ErrLimitRefused) {
		t.Fatalf("expected ErrLimitRefused (max active turns), got %v", err)
	}
	for _, h := range handles {
		terminateAndReap(t, h)
	}
}

// --- §49 retry-storm: circuit + backoff ---------------------------------------

// TestRetryStormBounded: a runtime whose launch always fails is driven
// repeatedly. The circuit opens after CircuitFailures failures and further
// launches are refused WITHOUT attempting a start — bounded attempts, flat
// process count, no goroutine explosion.
func TestRetryStormBounded(t *testing.T) {
	var now = time.Now()
	cfg := Config{
		MaxActiveTurns:  4,
		CircuitFailures: 3,
		CircuitWindow:   60 * time.Second,
		CircuitBlock:    60 * time.Second,
		MonitorInterval: time.Hour,
		Clock:           func() time.Time { return now },
	}
	s := newTestSupervisor(t, cfg)
	const M = 20
	baseGor := runtime.NumGoroutine()
	startAttempts, circuitRefusals := 0, 0
	for i := 0; i < M; i++ {
		// Distinct instances: exercise the circuit, not exclusivity.
		_, err := s.Launch(context.Background(), LaunchRequest{
			InstanceID: fmt.Sprintf("inst-%d", i), TurnID: "t",
			Runtime: "test", Class: ClassTurn,
			Cmd: exec.Command("/nonexistent/pagnet-fake-runtime"),
		})
		if err == nil {
			t.Fatalf("launch %d: expected failure", i)
		}
		switch {
		case errors.Is(err, os.ErrNotExist):
			startAttempts++ // an actual fork/exec was attempted
		case errors.Is(err, ErrLimitRefused):
			circuitRefusals++ // refused by the open circuit (no start)
		}
	}
	if !s.Stats().CircuitOpen {
		t.Fatalf("circuit did not open after %d failures", cfg.CircuitFailures)
	}
	if startAttempts > cfg.CircuitFailures {
		t.Fatalf("retry storm: %d start attempts exceed the circuit threshold %d",
			startAttempts, cfg.CircuitFailures)
	}
	if circuitRefusals == 0 {
		t.Fatalf("no circuit refusals observed (circuit not bounding retries)")
	}
	if finalGor := runtime.NumGoroutine(); finalGor > baseGor+2 {
		t.Fatalf("goroutine explosion: baseline %d final %d", baseGor, finalGor)
	}
	t.Logf("startAttempts=%d circuitRefusals=%d (bounded)", startAttempts, circuitRefusals)
}

// TestPressureBackoff: a resource-pressure failure arms the exponential
// backoff (BackoffMin * 2^shift, capped at BackoffMax) and a launch during
// the backoff is refused with ErrHostPressure. The injectable clock proves
// the backoff elapses without wall-clock waiting.
func TestPressureBackoff(t *testing.T) {
	var now = time.Now()
	cfg := Config{
		MaxActiveTurns:  4,
		BackoffMin:      time.Second,
		BackoffMax:      30 * time.Second,
		MonitorInterval: time.Hour,
		Clock:           func() time.Time { return now },
	}
	s := newTestSupervisor(t, cfg)

	s.recordPressureFailure()
	wait, active := s.backoffActive()
	if !active {
		t.Fatalf("backoff not active after a pressure failure")
	}
	if wait < time.Second || wait > time.Second+time.Second/2 {
		t.Fatalf("first backoff wait %v not in [1s, 1.5s]", wait)
	}
	// A launch during the backoff is refused (host pressure), no start.
	if _, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	}); !errors.Is(err, ErrHostPressure) {
		t.Fatalf("expected ErrHostPressure (backoff), got %v", err)
	}
	// Advance the clock past the first backoff: it must clear.
	now = now.Add(2 * time.Second)
	if _, active := s.backoffActive(); active {
		t.Fatalf("backoff still active after the clock advanced past it")
	}
	// A second pressure failure must DOUBLE the backoff (exponential).
	s.recordPressureFailure()
	wait2, active := s.backoffActive()
	if !active {
		t.Fatalf("backoff not active after the second pressure failure")
	}
	if wait2 < 2*time.Second || wait2 > 3*time.Second {
		t.Fatalf("second backoff wait %v not exponential (want [2s, 3s])", wait2)
	}
}

// --- host pressure guard (§33) ------------------------------------------------

// TestPressureGuardRefuses: when the user process count is at/above
// HostPressurePct of the (seamed) RLIMIT_NPROC, a launch is refused with
// ErrHostPressure and the counter increments.
func TestPressureGuardRefuses(t *testing.T) {
	cfg := Config{
		MaxActiveTurns:     4,
		HostPressurePct:    80,
		MonitorInterval:    time.Hour,
		processLimitFn:     func() int { return 1000 },
		userProcessCountFn: func() (int, error) { return 850, nil }, // 85% > 80%
	}
	s := newTestSupervisor(t, cfg)
	_, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	})
	if !errors.Is(err, ErrHostPressure) {
		t.Fatalf("expected ErrHostPressure, got %v", err)
	}
	if s.Stats().RefusedPressure == 0 {
		t.Fatalf("RefusedPressure counter not incremented")
	}
}

// TestPressureGuardBelowThreshold: below the threshold the launch proceeds
// (the guard does not over-refuse).
func TestPressureGuardBelowThreshold(t *testing.T) {
	cfg := Config{
		MaxActiveTurns:     4,
		HostPressurePct:    80,
		MonitorInterval:    time.Hour,
		processLimitFn:     func() int { return 1000 },
		userProcessCountFn: func() (int, error) { return 100, nil }, // 10% < 80%
	}
	s := newTestSupervisor(t, cfg)
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	})
	if err != nil {
		t.Fatalf("launch below pressure threshold refused: %v", err)
	}
	waitForPID(t, h)
	terminateAndReap(t, h)
}

// --- owned-process ceiling (§32) ---------------------------------------------

func TestOwnedCeiling(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, OwnedProcessesHard: 1,
		MonitorInterval: time.Hour})
	ctx := context.Background()
	h1, err := s.Launch(ctx, LaunchRequest{InstanceID: "a", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, h1)
	// Wait until the owned count reflects the running process.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.ownedSnapshot() < 1 {
		time.Sleep(20 * time.Millisecond)
	}
	_, err = s.Launch(ctx, LaunchRequest{InstanceID: "b", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if !errors.Is(err, ErrLimitRefused) {
		t.Fatalf("expected ErrLimitRefused (owned ceiling), got %v", err)
	}
	terminateAndReap(t, h1)
}

// --- descendant reclaim (§19/§24/§47) ----------------------------------------

// TestDescendantCleanup: a turn whose runtime spawns descendants that
// outlive it. When the turn completes, the WHOLE group (not just the direct
// child) must be reclaimed.
func TestDescendantCleanup(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	ctx := context.Background()
	// Parent spawns two long-lived descendants, then exits (the turn ends).
	cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600 & exit 0")
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	// The owner reaps the parent AND reclaims the descendants.
	_ = h.Wait()
	waitGroupGone(t, pid)
}

// TestCancelCleansGroup: cancelling the turn's context terminates the whole
// group (the direct child AND its descendants), not just the child.
func TestCancelCleansGroup(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600 & wait")
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	waitForGroupCount(t, pid, 3) // parent + 2 descendants
	// Owner goroutine reaps (as the adapter's turn loop would).
	reaped := make(chan struct{})
	go func() { _ = h.Wait(); close(reaped) }()
	cancel() // the ctx watcher terminates the group
	waitGroupGone(t, pid)
	<-reaped
}

// --- process explosion (§31) -------------------------------------------------

// TestProcessExplosion: a turn whose group grows past TurnProcessesHard is
// terminated by the monitor.
func TestProcessExplosion(t *testing.T) {
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:    4,
		TurnProcessesWarn: 2,
		TurnProcessesHard: 3,
		TermGrace:         2 * time.Second,
		MonitorInterval:   50 * time.Millisecond,
	})
	ctx := context.Background()
	cmd := exec.Command("sh", "-c", "for i in $(seq 1 10); do sleep 3600 & done; wait")
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	reaped := make(chan struct{})
	go func() { _ = h.Wait(); close(reaped) }()
	// The monitor detects the explosion and terminates the group.
	waitGroupGone(t, pid)
	<-reaped
	if s.Stats().ExplosionTotal == 0 {
		t.Fatalf("ExplosionTotal not incremented")
	}
}

// --- §50 shutdown -------------------------------------------------------------

// TestShutdown: several turn trees + a PTY are running; StopAll terminates
// every group, reaps every direct child, closes the PTY, refuses new
// launches, and completes within the deadline.
func TestShutdown(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 8, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	ctx := context.Background()
	var handles []*Handle
	for i := 0; i < 4; i++ {
		cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600 & wait")
		h, err := s.Launch(ctx, LaunchRequest{InstanceID: fmt.Sprintf("inst-%d", i),
			TurnID: "t", Runtime: "test", Class: ClassTurn, Cmd: cmd})
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, h)
	}
	for _, h := range handles {
		waitForPID(t, h)
	}
	ph, err := s.Launch(ctx, LaunchRequest{InstanceID: "pty-inst", TurnID: PTYTurnID,
		Runtime: "test", Class: ClassPTY, Cmd: exec.Command("sleep", "3600"),
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80}})
	if err != nil {
		t.Fatal(err)
	}
	waitForPID(t, ph)
	pids := []int{ph.PID()}
	// Owner goroutines (the adapters' turn loops / the terminal exit loop).
	var ownerWG sync.WaitGroup
	for _, h := range handles {
		pids = append(pids, h.PID())
		ownerWG.Add(1)
		go func(h *Handle) { defer ownerWG.Done(); _ = h.Wait() }(h)
	}
	ownerWG.Add(1)
	go func() { defer ownerWG.Done(); _ = ph.Wait() }()

	start := time.Now()
	survivors := s.StopAll(10 * time.Second)
	elapsed := time.Since(start)
	ownerWG.Wait()
	if survivors > 0 {
		t.Fatalf("StopAll left %d survivors", survivors)
	}
	if elapsed > 9*time.Second {
		t.Fatalf("StopAll took %v (near/over the deadline)", elapsed)
	}
	for _, pid := range pids {
		waitGroupGone(t, pid)
	}
	// No new launch is accepted once shutting down.
	if _, err := s.Launch(ctx, LaunchRequest{InstanceID: "new", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")}); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("expected ErrShuttingDown, got %v", err)
	}
}
