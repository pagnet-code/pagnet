//go:build darwin

// macOS-specific containment tests (abuse addendum Part B §51). The original
// forkpty/process-exhaustion incident occurred on macOS, so Linux-only tests
// are NOT sufficient. These exercise the SAME supervisor contract on Darwin:
// process-group creation, group termination, PTY cleanup, process-identity
// verification, and resource-pressure detection.
//
// They share the portable helpers from supervisor_test.go (build: unix).
// Run them on a macOS host: `go test -race ./internal/proc/...`.
package proc

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestDarwinGroupCreation: a turn process is placed in its OWN process group
// (child pgid == child pid), so the whole tree is one signalable unit.
func TestDarwinGroupCreation(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, MonitorInterval: time.Hour})
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	if h.PGID() != pid {
		t.Fatalf("turn pgid %d != pid %d (not an isolated group leader)", h.PGID(), pid)
	}
	if n := CountGroup(pid); n < 1 {
		t.Fatalf("group %d has %d members, want >= 1", pid, n)
	}
	terminateAndReap(t, h)
}

// TestDarwinGroupTermination: a turn tree with descendants is fully
// terminated by a group signal (TERM → grace → KILL), not just the child.
func TestDarwinGroupTermination(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600 & wait")
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test", Class: ClassTurn, Cmd: cmd,
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	waitForGroupCount(t, pid, 3) // parent + 2 descendants
	// A signal-0 probe on the negative pgid must reach the whole group.
	if err := SignalGroup(pid, syscall.Signal(0)); err != nil && !errors.Is(err, ErrGroupGone) {
		t.Fatalf("signal-0 probe on group %d failed: %v", pid, err)
	}
	terminateAndReap(t, h)
	waitGroupGone(t, pid)
}

// TestDarwinPTYCleanup: a PTY session (isolated session, Setsid+Setctty) is
// fully torn down — the group is killed and the master closed — so the PTY
// is released (the forkpty side of the incident).
func TestDarwinPTYCleanup(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "pty-inst", TurnID: PTYTurnID, Runtime: "test", Class: ClassPTY,
		Cmd:     exec.Command("sleep", "3600"),
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80},
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	if h.PTY() == nil {
		t.Fatalf("PTY handle has no master")
	}
	// The PTY session is its own session leader (pgid == pid).
	if h.PGID() != pid {
		t.Fatalf("PTY pgid %d != pid %d", h.PGID(), pid)
	}
	terminateAndReap(t, h)
	waitGroupGone(t, pid)
}

// TestDarwinIdentity: the start-identity marker is readable, non-empty, and
// stable for a live process (the PID-reuse-safe identity the ownership
// record stores). Two processes started at different times differ.
func TestDarwinIdentity(t *testing.T) {
	c1 := exec.Command("sleep", "3600")
	if err := c1.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c1.Process.Kill(); _ = c1.Wait() }()
	id1a, err := StartIdentity(c1.Process.Pid)
	if err != nil {
		t.Fatalf("StartIdentity: %v", err)
	}
	if id1a == "" {
		t.Fatalf("StartIdentity returned empty for a live process")
	}
	id1b, err := StartIdentity(c1.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if id1a != id1b {
		t.Fatalf("identity not stable: %q != %q", id1a, id1b)
	}
	// A second process started later has a different start identity.
	time.Sleep(50 * time.Millisecond)
	c2 := exec.Command("sleep", "3600")
	if err := c2.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Process.Kill(); _ = c2.Wait() }()
	id2, err := StartIdentity(c2.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id1a {
		t.Fatalf("two distinct processes share identity %q (PID-reuse detection broken)", id2)
	}
}

// TestDarwinPressureGuard: the host-pressure guard refuses a launch when the
// (seamed) user process count is at/above the threshold of the (seamed)
// RLIMIT_NPROC. The seam keeps this deterministic on any macOS host.
func TestDarwinPressureGuard(t *testing.T) {
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
