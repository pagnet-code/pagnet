//go:build linux

// PDEATHSIG tests (P0 follow-up). Scope, stated precisely (see the
// childDeathSignal seam): PDEATHSIG protects the DIRECT runtime child
// only — if the daemon dies, the kernel SIGKILLs that one process. It
// additionally reduces the unrecorded direct-child crash window on
// Linux; it is NOT a whole-tree kernel kill and NOT a replacement for
// process-group cleanup or restart reconciliation (the durable
// ownership record + Reconcile remain the primary orphan-recovery
// mechanism).
package proc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGroupAttrsCarryPdeathsig: on linux, both process classes carry the
// kernel parent-death guarantee on the direct child.
func TestGroupAttrsCarryPdeathsig(t *testing.T) {
	if !childDeathSignal {
		t.Fatal("childDeathSignal is not set on linux")
	}
	if g := GroupAttrs(); g.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("GroupAttrs().Pdeathsig = %v, want SIGKILL", g.Pdeathsig)
	}
	if s := SessionAttrs(); s.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("SessionAttrs().Pdeathsig = %v, want SIGKILL", s.Pdeathsig)
	}
}

// pdeathChildDead reports whether pid is dead: reaped (no /proc entry)
// or a zombie (state 'Z' — dead, awaiting reap by init). A zombie-aware
// check: kill(pid, 0) would report a zombie as alive.
func pdeathChildDead(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return true // reaped
	}
	st := parseProcStat(pid, b)
	return st == nil || st.state == 'Z'
}

// TestPdeathParentRole is the parent of the PDEATHSIG behavior test: it
// starts a child with the production GroupAttrs (Pdeathsig=SIGKILL),
// publishes the child's pid, and exits — its death must make the kernel
// SIGKILL the child. Runs only when selected by name with
// PAGNET_PDEATH_PID_FILE set.
func TestPdeathParentRole(t *testing.T) {
	pidFile := os.Getenv("PAGNET_PDEATH_PID_FILE")
	if pidFile == "" {
		t.Skip("pdeath role: only runs when selected by name")
	}
	cmd := exec.Command("sleep", "3600")
	cmd.SysProcAttr = GroupAttrs()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	// Parent death: the kernel must SIGKILL the direct child.
	os.Exit(0)
}

// TestPdeathsigKillsChildOnParentDeath: a real parent death — the child
// (started with the production GroupAttrs) must be killed by the kernel
// the moment its parent exits.
func TestPdeathsigKillsChildOnParentDeath(t *testing.T) {
	if !childDeathSignal {
		t.Skip("platform has no parent-death signal")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=TestPdeathParentRole", "-test.count=1")
	cmd.Env = append(os.Environ(), "PAGNET_PDEATH_PID_FILE="+pidFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// waited flips once the test body consumes the result; the cleanup
	// must then NOT wait on done again (the buffered value is gone —
	// waiting on it would hang the whole test binary).
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = cmd.Process.Kill()
		<-done
	})
	// Wait for the child pid (the role writes it right before exiting).
	var childPID int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidFile); err == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		t.Fatal("child pid file never appeared")
	}
	// The role exits right after writing the file; the kernel must
	// SIGKILL the child on the parent's death. Poll until it is dead
	// (zombie-aware — the reaper here is init, not this test).
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !pdeathChildDead(childPID) {
		time.Sleep(50 * time.Millisecond)
	}
	if !pdeathChildDead(childPID) {
		t.Fatalf("child %d survived its parent's death (PDEATHSIG not applied)", childPID)
	}
	err = <-done
	waited = true
	if err != nil {
		t.Fatalf("parent role exited with an error: %v", err)
	}
}
