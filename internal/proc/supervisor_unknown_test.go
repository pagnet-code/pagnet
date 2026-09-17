//go:build unix

// Fail-closed-on-UNKNOWN enumeration tests (the darwin proc fix stream).
//
// A WHOLESALE process-enumeration failure (kern.proc.all on Darwin, the
// /proc root on Linux) is UNKNOWN, never EMPTY. These tests pin the two
// supervisor consequences of that invariant, using the Config seams
// (countOwnedFn / groupLiveMemberFn) to inject the failure deterministically
// without breaking the host's /proc or kern.proc:
//
//  1. The descendant reclaim (ownerWait) must NOT fire the reclaim kill on
//     an UNKNOWN enumeration — a false kill of a live group is the
//     worst-case; a skipped reclaim is a bounded leak the post-reap
//     GroupAlive verification (signal-0, not enumeration) still catches.
//  2. The owned-process ceiling (Launch) must NOT treat an UNKNOWN count as
//     "capacity available" — it refuses with ErrLimitRefused.
//
// These run on every unix platform (Linux AND macOS) so the fail-closed
// contract is not Linux-only. They do NOT depend on the real enumeration
// succeeding, so they stay green even on a runner whose process view is
// broken (the darwin CI condition).
package proc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReclaimSkippedOnUnknownEnumeration: a turn whose child exits but leaves
// a live descendant in the same pgid. The enumeration is forced to fail
// (UNKNOWN). The reclaim must be SKIPPED (not fire), so the descendant is
// NOT signaled. The descendant traps TERM and writes a marker file: if the
// reclaim wrongly fired, the marker appears and the test fails.
func TestReclaimSkippedOnUnknownEnumeration(t *testing.T) {
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:  4,
		TermGrace:       2 * time.Second,
		MonitorInterval: time.Hour,
		groupLiveMemberFn: func(int) (bool, error) {
			return false, errors.New("forced enumeration failure")
		},
	})
	// The descendant traps TERM and writes a marker: a TERM'd descendant
	// proves the reclaim fired.
	marker := filepath.Join(t.TempDir(), "killed")
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("(trap 'echo 1 > %s' TERM; sleep 10) >/dev/null 2>&1 & exec true", marker))
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd.Stdout = pw
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-unknown", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd,
	})
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		t.Fatalf("launch: %v", err)
	}
	pid := waitForPID(t, h)
	// The reclaim is SKIPPED (UNKNOWN), so the descendant is not reclaimed
	// by the supervisor. Kill the group in cleanup to avoid a lingering
	// process (the bounded-leak trade-off the fix accepts).
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	// Close our write end so the pipe reaches EOF when the child exits.
	_ = pw.Close()
	// Drain to EOF: the direct child has exited (zombie), exactly as the
	// production owner does before it reaps.
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("drain stdout: %v", err)
	}
	_ = pr.Close()
	// The owner reaps. The reclaim must be SKIPPED (UNKNOWN enumeration),
	// so the descendant is NOT signaled.
	if err := h.Wait(); err != nil {
		t.Fatalf("turn did not exit normally: %v", err)
	}
	// Give the trap handler time to run (in case the reclaim wrongly fired).
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("reclaim fired on UNKNOWN enumeration (descendant was TERM'd)")
	}
}

// TestOwnedCeilingRefusesOnUnknownEnumeration: the owned-process enumeration
// is forced to fail (UNKNOWN). A launch must be REFUSED with ErrLimitRefused
// (an UNKNOWN count is not "capacity available"), not allowed through.
func TestOwnedCeilingRefusesOnUnknownEnumeration(t *testing.T) {
	s := newTestSupervisor(t, Config{
		MaxActiveTurns:     4,
		OwnedProcessesHard: 256,
		MonitorInterval:    time.Hour,
		// Keep the host-pressure guard from refusing first (10% < 80%).
		processLimitFn:     func() int { return 1000 },
		userProcessCountFn: func() (int, error) { return 100, nil },
		countOwnedFn: func(map[int]bool) (int, error) {
			return 0, errors.New("forced enumeration failure")
		},
	})
	_, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-ceiling", TurnID: "t", Runtime: "test", Class: ClassTurn,
		Cmd: exec.Command("sleep", "3600"),
	})
	if !errors.Is(err, ErrLimitRefused) {
		t.Fatalf("expected ErrLimitRefused (unknown enumeration), got %v", err)
	}
	if s.Stats().RefusedLimit == 0 {
		t.Fatalf("RefusedLimit counter not incremented")
	}
}
