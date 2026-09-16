//go:build unix

// Regression tests for the E2E82 family P0 (the pid-reuse race in the
// turn-exit descendant reclaim).
//
// The defect: ownerWait reaped the direct child FIRST (freeing its pid),
// then checked the process group by pgid and SIGTERMed it. Between the
// reap and the group check, a NEW turn could reuse the freed pid and
// become a group leader with the SAME pgid, so the old turn's
// termination landed on the new turn's still-starting process (a rep
// hibernates, a new turn launches milliseconds later, and the previous
// turn's kill hits the new turn).
//
// The fix anchors the reclaim on each side of the reap:
//
//   - PRE-reap: the reclaim is gated on the direct child having already
//     exited (zombie). While the child is unreaped it still holds its
//     pid, so no other process can hold this pgid — the group is this
//     turn's own. A LIVE child means the group is the running turn
//     itself, and the reclaim must not fire.
//   - POST-reap: the pid is released, so the reclaim fires only when no
//     process currently holds the pgid number (a held number is a pid
//     reused by an unrelated new turn — never kill it).
//
// These tests pin the three properties the fix must preserve:
//
//	(a) the §19/§24 descendant reclaim still works — a turn whose child
//	    exits but leaves a live descendant in the same pgid has that
//	    descendant reclaimed, and the turn still exits normally;
//	(b) the anchoring invariant — after Wait returns, the group has no
//	    LIVE members, so nothing from the old turn survives to be
//	    confused with a new turn that reuses the pid;
//	(c) the early-Wait contract — an owner that calls Wait while the
//	    turn is still running must block, not terminate: the pre-reap
//	    check must not fire on a live child (the 2026-09-16 first cut of
//	    the pre-reap reclaim killed the just-launched group, and
//	    TestProcessExplosion lost its monitor explosion tick).
//
// The pid-reuse sequence itself (a new turn reusing the freed pid) is
// NOT deterministically reproducible in-package: the kernel assigns pids
// and reuse cannot be forced. The fix closes that race by construction
// (pre-reap: anchored on the unreaped child; post-reap: gated on the
// pgid number being unheld), and the load-sensitive E2E82 suite is the
// end-to-end evidence. These tests therefore do NOT attempt to fake pid
// reuse; they assert the anchoring invariants directly.
package proc

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// launchDescendantTurn launches a turn whose direct child exits
// immediately (exit 0) but leaves one live descendant (sleep 60) in the
// same pgid. The descendant's stdout is redirected to /dev/null so it
// does not hold the child's stdout pipe; the pipe therefore reaches EOF
// exactly when the child exits — the same signal the production owner
// uses (all stdout reads done) before it reaps. The returned read end is
// left open for the caller to drain to EOF.
func launchDescendantTurn(t *testing.T, s *Supervisor) (*Handle, int, *os.File) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "sleep 60 >/dev/null 2>&1 & exec true")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd.Stdout = pw
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-pidreuse", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd,
	})
	if err != nil {
		_ = pw.Close()
		_ = pr.Close()
		t.Fatalf("launch: %v", err)
	}
	pid := waitForPID(t, h)
	// Close our write end so the pipe reaches EOF when the child exits
	// (the child holds its own copy until it exits).
	_ = pw.Close()
	t.Cleanup(func() { _ = pr.Close() })
	return h, pid, pr
}

// drainToEOF reads the child's stdout to EOF: the child has exited
// (zombie) now, exactly as in the production owner before it reaps.
func drainToEOF(t *testing.T, pr *os.File) {
	t.Helper()
	if _, err := io.Copy(io.Discard, pr); err != nil {
		t.Fatalf("drain stdout: %v", err)
	}
}

// waitGroupNoLiveMembers blocks until the group has no LIVE (non-zombie)
// members (zombie-aware: a zombie is dead and cannot be confused with a
// new turn).
func waitGroupNoLiveMembers(t *testing.T, pgid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !GroupHasLiveMember(pgid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process group %d still has live members (leak)", pgid)
}

// (a) The §19/§24 descendant reclaim still works after the fix: a turn
// whose child exits but leaves a live descendant in the same pgid has
// that descendant reclaimed, and the turn exits normally (the child
// exited 0 before the reclaim, so the pre-reap check sees only the
// descendant, not the dying child).
func TestOwnerWaitDescendantReclaim(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	h, pid, pr := launchDescendantTurn(t, s)
	// Wait for the child to exit (zombie) before reaping, as the
	// production owner does (all stdout reads done first).
	drainToEOF(t, pr)
	// The owner reaps: the pre-reap reclaim kills the descendant, and the
	// turn exits normally.
	if err := h.Wait(); err != nil {
		t.Fatalf("turn did not exit normally: %v", err)
	}
	// The descendant is dead (the group has no live members).
	waitGroupNoLiveMembers(t, pid)
}

// (b) The anchoring invariant: after Wait returns, the group has no LIVE
// members — nothing from the old turn survives that could be confused
// with a new turn that reuses the pid.
func TestOwnerWaitAnchoringInvariant(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	h, pid, pr := launchDescendantTurn(t, s)
	drainToEOF(t, pr)
	if err := h.Wait(); err != nil {
		t.Fatalf("turn did not exit normally: %v", err)
	}
	if GroupHasLiveMember(pid) {
		t.Fatalf("group %d has live members after Wait (anchoring invariant violated)", pid)
	}
}

// (c) The early-Wait contract: an owner that calls Wait while the turn is
// still RUNNING must block — the pre-reap reclaim must not fire on a live
// child (the group is the running turn itself). The turn is terminated
// only by the explicit Terminate that follows, and Wait returns that
// exit (not a silent early one).
func TestOwnerWaitEarlyDoesNotTerminateRunningTurn(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	cmd := exec.Command("sh", "-c", "sleep 30")
	h, err := s.Launch(context.Background(), LaunchRequest{
		InstanceID: "inst-earlywait", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: cmd,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	pid := waitForPID(t, h)
	waitErr := make(chan error, 1)
	go func() { waitErr <- h.Wait() }()
	// Give the early Wait (and its pre-reap check) time to run. If the
	// check fires on the live child, the group is terminated and loses
	// its live members long before this assertion.
	time.Sleep(300 * time.Millisecond)
	if !GroupHasLiveMember(pid) {
		t.Fatalf("early Wait terminated the running turn (group %d has no live members)", pid)
	}
	select {
	case err := <-waitErr:
		t.Fatalf("Wait returned before the turn was stopped: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	// Only the explicit termination kills the turn; Wait then returns the
	// signal exit (the group was TERMed, not a clean exit 0).
	h.Terminate("test-stop")
	waitGroupNoLiveMembers(t, pid)
	if err := <-waitErr; err == nil {
		t.Fatalf("Wait after explicit stop returned nil, want the signal exit")
	}
}
