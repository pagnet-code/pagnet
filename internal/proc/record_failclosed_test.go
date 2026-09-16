//go:build unix

// Fail-closed launch test (P0 follow-up): the ownership record is the
// only cross-restart memory of a process tree (§39). A launch whose
// record cannot be durably written must fail closed: the just-started
// tree is terminated and reaped, the instance slot is released, and the
// error surfaces — never a running process the supervisor cannot own.
package proc

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// launchedPIDHandler captures the "pid" attribute of the supervisor's
// "process launched" log line (white-box: the test is in the same
// package). It is the only way to learn the pid of a process whose
// launch FAILED: the handle is nil, and the fail-closed path terminates
// the child before it could report its own pid.
type launchedPIDHandler struct {
	ch chan int
}

func (h *launchedPIDHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *launchedPIDHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *launchedPIDHandler) WithGroup(string) slog.Handler { return h }

func (h *launchedPIDHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "process launched" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "pid" {
			select {
			case h.ch <- int(a.Value.Int64()):
			default:
			}
		}
		return true
	})
	return nil
}

func TestLaunchFailsClosedWhenRecordWriteFails(t *testing.T) {
	dir := t.TempDir()
	// Make writeRecord's MkdirAll fail: the record dir path exists as a
	// REGULAR FILE.
	if err := os.WriteFile(filepath.Join(dir, "proc-ownership"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Capture the launched pid from the supervisor's own log (see
	// launchedPIDHandler).
	pids := make(chan int, 1)
	cfg := Config{StateDir: dir, MaxActiveTurns: 4,
		TermGrace: 2 * time.Second, MonitorInterval: time.Hour}
	s := NewSupervisor(cfg, slog.New(&launchedPIDHandler{ch: pids}))
	t.Cleanup(func() { s.StopAll(5 * time.Second) })
	ctx := context.Background()
	_, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err == nil {
		t.Fatal("Launch succeeded despite the ownership record write failing")
	}
	if !strings.Contains(err.Error(), "ownership record") {
		t.Fatalf("expected an ownership-record error, got: %v", err)
	}

	// The spawned child must be dead (terminated + reaped by the
	// fail-closed path).
	var pid int
	select {
	case pid = <-pids:
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor never logged the launched pid")
	}
	if pid <= 0 {
		t.Fatal("captured pid is not positive")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && ProcessAlive(pid) {
		time.Sleep(50 * time.Millisecond)
	}
	if ProcessAlive(pid) {
		t.Fatalf("child %d still alive after the failed launch (must be terminated + reaped)", pid)
	}

	// The instance slot must be released: fix the record dir and launch
	// the SAME instance/turn again — it must succeed.
	if err := os.Remove(filepath.Join(dir, "proc-ownership")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "proc-ownership"), 0o700); err != nil {
		t.Fatal(err)
	}
	h, err := s.Launch(ctx, LaunchRequest{InstanceID: "inst-1", TurnID: "turn-1",
		Runtime: "test", Class: ClassTurn, Cmd: exec.Command("sleep", "3600")})
	if err != nil {
		t.Fatalf("second launch for the same instance/turn failed after the slot was released: %v", err)
	}
	waitForPID(t, h)
	terminateAndReap(t, h)
}
