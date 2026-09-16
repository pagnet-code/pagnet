//go:build unix

// Process-group topology tests (P0 follow-up): prove that ONE ownership
// group per execution actually holds — the direct child AND its normal
// descendants are all in the same process group, for both process
// classes:
//
//   - ClassTurn (Setpgid): the child is its own group leader
//     (pgid == pid); a backgrounded descendant (non-interactive sh = no
//     job control) inherits the group.
//   - ClassPTY (Setsid+Setctty): the session leader is the group leader
//     (pgid == pid); a backgrounded descendant stays INSIDE the group.
package proc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// topoFixtureCmd returns a command that backgrounds a long-lived
// descendant (publishing its pid to pidFile) and then keeps running.
// The non-interactive sh has no job control, so the backgrounded child
// inherits sh's process group — exactly like a runtime's helpers do.
func topoFixtureCmd(pidFile string) *exec.Cmd {
	return exec.Command("sh", "-c", fmt.Sprintf("sleep 3600 & echo $! > %s; sleep 3600", pidFile))
}

// readTopoPID polls pidFile until it holds a pid (bounded).
func readTopoPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid file %s never appeared", path)
	return 0
}

// TestProcessGroupTopology (ClassTurn): the whole tree — the runtime
// (direct child) and its backgrounded descendant — is ONE process group
// (the group the supervisor created at Start).
func TestProcessGroupTopology(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	pidFile := filepath.Join(t.TempDir(), "grand.pid")
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-topo", TurnID: "t",
		Runtime: "test", Class: ClassTurn, Cmd: topoFixtureCmd(pidFile)})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	grand := readTopoPID(t, pidFile)
	if grand == pid {
		t.Fatalf("descendant pid %d == runtime pid (fixture broken)", grand)
	}
	pgid := h.PGID()
	if g, err := ProcessGroupOf(pid); err != nil || g != pgid {
		t.Fatalf("runtime ProcessGroupOf = %d (err %v), want the exec pgid %d", g, err, pgid)
	}
	if g, err := ProcessGroupOf(grand); err != nil || g != pgid {
		t.Fatalf("descendant ProcessGroupOf = %d (err %v), want the exec pgid %d — the tree escaped its ownership group", g, err, pgid)
	}
	terminateAndReap(t, h)
	waitGroupGone(t, pgid)
}

// TestPTYSessionDescendantTopology (ClassPTY): the PTY + Setsid + Setctty
// combination keeps the session leader as the group leader (pgid == pid)
// and normal descendants INSIDE the ownership group during normal
// execution.
func TestPTYSessionDescendantTopology(t *testing.T) {
	s := newTestSupervisor(t, Config{MaxActiveTurns: 4, TermGrace: 2 * time.Second,
		MonitorInterval: time.Hour})
	pidFile := filepath.Join(t.TempDir(), "grand.pid")
	ctx := context.Background()
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "pty-topo", TurnID: PTYTurnID,
		Runtime: "test", Class: ClassPTY, Cmd: topoFixtureCmd(pidFile),
		PTYSize: &pty.Winsize{Rows: 24, Cols: 80}})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, h)
	if h.PGID() != pid {
		t.Fatalf("PTY session leader pgid %d != pid %d (the leader must be the group leader)", h.PGID(), pid)
	}
	if h.PTY() == nil {
		t.Fatal("PTY master is nil on a ClassPTY handle")
	}
	grand := readTopoPID(t, pidFile)
	if grand == pid {
		t.Fatalf("descendant pid %d == runtime pid (fixture broken)", grand)
	}
	if g, err := ProcessGroupOf(grand); err != nil || g != h.PGID() {
		t.Fatalf("descendant ProcessGroupOf = %d (err %v), want the session pgid %d — the PTY tree escaped its ownership group", g, err, h.PGID())
	}
	terminateAndReap(t, h)
	waitGroupGone(t, h.PGID())
}
