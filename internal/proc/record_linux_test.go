//go:build linux

// Restart-reconciliation tests (abuse addendum Part B §39). The ownership
// record is the only cross-restart memory of a live process tree. These
// prove the PID-reuse rule (identity mismatch ⇒ NEVER kill) and the
// marker-proven stale-group reclaim. Linux-only: the marker proof reads
// /proc/<pid>/environ (macOS cannot read another process's environment).
package proc

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeTestRecord(t *testing.T, dir string, rec ownershipRecord) string {
	t.Helper()
	ownDir := filepath.Join(dir, "proc-ownership")
	if err := os.MkdirAll(ownDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ownDir, rec.InstanceID+"--"+rec.TurnID+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReconcilePIDReuseNeverKills: a record whose leader PID is now held by
// a DIFFERENT process (identity mismatch — the PID was reused) must NOT be
// killed. The record is cleared, the process survives.
func TestReconcilePIDReuseNeverKills(t *testing.T) {
	stateDir := t.TempDir()
	s := newTestSupervisor(t, Config{StateDir: stateDir, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})

	// A live process that will "own" the reused PID.
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	reusedPID := cmd.Process.Pid
	actualIdentity, err := StartIdentity(reusedPID)
	if err != nil {
		t.Fatal(err)
	}
	// A record claiming that PID but with a DIFFERENT start identity.
	recPath := writeTestRecord(t, stateDir, ownershipRecord{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test",
		PID: reusedPID, PGID: reusedPID,
		Identity:  "999999999", // deliberately != actualIdentity
		StartedAt: time.Now(),
		Marker:    "PAGNET_TURN_ID=old",
	})
	_ = recPath

	s.Reconcile()

	if !ProcessAlive(reusedPID) {
		t.Fatalf("PID REUSE: the reused process %d was killed — identity mismatch must never kill", reusedPID)
	}
	if _, err := os.Stat(recPath); !os.IsNotExist(err) {
		t.Fatalf("record not cleared after reconciliation (err=%v)", err)
	}
	_ = actualIdentity
}

// TestReconcileStaleGroupTerminated: a record whose leader is still alive
// with the SAME start identity is provably ours — the group is terminated.
func TestReconcileStaleGroupTerminated(t *testing.T) {
	stateDir := t.TempDir()
	s := newTestSupervisor(t, Config{StateDir: stateDir, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})

	// A process in its OWN group (like a real turn), with a descendant.
	cmd := exec.Command("sh", "-c", "sleep 3600 & sleep 3600 & wait")
	cmd.SysProcAttr = GroupAttrs()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	identity, err := StartIdentity(pid)
	if err != nil {
		t.Fatal(err)
	}
	writeTestRecord(t, stateDir, ownershipRecord{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test",
		PID: pid, PGID: pid, Identity: identity,
		StartedAt: time.Now(), Marker: "PAGNET_TURN_ID=t",
	})

	s.Reconcile()

	// Reap the direct child (our own) so its zombie does not keep the
	// group "alive" (GroupAlive counts zombies); the descendants are
	// reparented to init and reaped there.
	go func() { _ = cmd.Wait() }()
	waitGroupGone(t, pid)
	if s.Stats().OrphanReconciled == 0 {
		t.Fatalf("OrphanReconciled not incremented")
	}
}

// TestReconcileMarkerProvenGroup: the recorded leader is GONE but its group
// survives, and a member carries the ownership marker — the group is proven
// ours and terminated.
func TestReconcileMarkerProvenGroup(t *testing.T) {
	stateDir := t.TempDir()
	s := newTestSupervisor(t, Config{StateDir: stateDir, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	marker := "PAGNET_TURN_ID=reconcile-test"

	// A leader that spawns a marker-carrying descendant, then exits (the
	// leader is gone; the descendant keeps the group alive).
	cmd := exec.Command("sh", "-c", "sleep 3600 & exit 0")
	cmd.SysProcAttr = GroupAttrs()
	cmd.Env = append(os.Environ(), marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	leaderPID := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !GroupAlive(leaderPID) {
		t.Fatalf("expected the group to survive the leader (descendant), but it is gone")
	}
	writeTestRecord(t, stateDir, ownershipRecord{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test",
		PID: leaderPID, PGID: leaderPID,
		Identity: "", StartedAt: time.Now(), Marker: marker,
	})

	s.Reconcile()

	waitGroupGone(t, leaderPID)
	if s.Stats().OrphanReconciled == 0 {
		t.Fatalf("OrphanReconciled not incremented")
	}
}

// TestReconcileUnprovenGroupLeftAlone: the leader is gone, the group
// survives, but NO member carries the marker — ownership is unprovable, so
// the processes are left running (never killed on a guess) and the record
// is cleared.
func TestReconcileUnprovenGroupLeftAlone(t *testing.T) {
	stateDir := t.TempDir()
	s := newTestSupervisor(t, Config{StateDir: stateDir, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})

	// A group with NO ownership marker (not provably ours).
	cmd := exec.Command("sh", "-c", "sleep 3600 & exit 0")
	cmd.SysProcAttr = GroupAttrs()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	leaderPID := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Defensive: kill any survivor so the test never leaves an orphan.
		_ = SignalGroup(leaderPID, syscall.SIGKILL)
	})
	if !GroupAlive(leaderPID) {
		t.Fatalf("expected the group to survive the leader, but it is gone")
	}
	recPath := writeTestRecord(t, stateDir, ownershipRecord{
		InstanceID: "inst-1", TurnID: "t", Runtime: "test",
		PID: leaderPID, PGID: leaderPID,
		Identity: "", StartedAt: time.Now(), Marker: "PAGNET_TURN_ID=absent",
	})

	s.Reconcile()

	// The unproven group must be LEFT ALONE (not killed).
	if !GroupAlive(leaderPID) {
		t.Fatalf("unproven group %d was killed — reconciliation must not kill without proof", leaderPID)
	}
	// But the record is cleared (nothing left to act on next restart).
	if _, err := os.Stat(recPath); !os.IsNotExist(err) {
		t.Fatalf("record not cleared (err=%v)", err)
	}
}
