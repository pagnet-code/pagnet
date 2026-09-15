//go:build linux

// PTY-session leak reproduction + regression test (abuse addendum Part B
// §46/§47, the PTY side of the macOS `forkpty: Resource temporarily
// unavailable` incident).
//
// Phase 1 (repro): the pre-fix terminal manager's stop() kills only the
// DIRECT child of the PTY. A runtime whose interactive UI spawns helper
// processes (the PAGNET_FAKE_PTY_CHILD fixture: a child that keeps the
// PTY slave open, standing in for a real TUI's helper processes) leaves
// that helper alive after stop():
//
//   - the helper holds the PTY slave → the PTY stays allocated (macOS
//     has a small PTY pool; this is the forkpty EAGAIN side of the
//     incident);
//   - the master never errors → the readLoop goroutine blocks on
//     Read forever (goroutine + FD leak per stopped session).
//
// Post-fix (this file's assertion): after stop() the session's whole
// process group is terminated and reaped — zero marker processes, no
// leaked goroutines, PTY released.
package daemon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
)

// Safety ceilings (2026-09-15 incident hardening): this test spawns a
// real PTY session with a slave-holding descendant, so its limits live
// in the fixture — a hard ceiling on simultaneously-alive marker
// children, a wall-time ceiling, and a defensive group-kill cleanup
// registered BEFORE the first child is launched (runs on pass, failure,
// and panic — no orphans).
const (
	ptyLeakMaxMarkerChildren = 16
	ptyLeakWallLimit         = 60 * time.Second
)

// p0FakeBinary builds (when stale/missing) the pagnet-fake-runtime
// fixture binary into the scratch dir (NEVER into the repo's bin/) and
// returns an ABSOLUTE path (the adapter sets cmd.Dir to the workspace;
// a relative binary path would resolve against that directory).
func p0FakeBinary(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PAGNET_P0_BIN_DIR")
	if dir == "" {
		abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".qwen", "tmp", "p0-bin"))
		if err != nil {
			t.Fatalf("resolve scratch bin dir: %v", err)
		}
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scratch bin dir: %v", err)
	}
	bin := filepath.Join(dir, "pagnet-fake-runtime")
	needBuild := true
	if fi, err := os.Stat(bin); err == nil {
		if src, err := os.Stat(filepath.Join("..", "..", "cmd", "pagnet-fake-runtime", "main.go")); err == nil && fi.ModTime().After(src.ModTime()) {
			needBuild = false
		}
	}
	if needBuild {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "build",
			"-o", bin, filepath.Join("..", "..", "cmd", "pagnet-fake-runtime")).CombinedOutput()
		if err != nil {
			t.Fatalf("build fake runtime fixture: %v\n%s", err, out)
		}
	}
	return bin
}

// countMarkerProcesses counts processes whose environment carries the
// ownership marker (the PTY child inherits it from the fake runtime,
// exactly like production descendants inherit PAGNET_TURN_ID).
func countMarkerProcesses(marker string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	needle := []byte("PAGNET_P0_LEAK=" + marker)
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !isDigitsName(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil {
			continue
		}
		if bytes.Contains(b, needle) {
			n++
		}
	}
	return n
}

func isDigitsName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// markerPGRPs returns the distinct process groups of the marker
// processes (the supervisor puts each PTY session in its own group).
func markerPGRPs(marker string) map[int]bool {
	out := map[int]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	needle := []byte("PAGNET_P0_LEAK=" + marker)
	for _, e := range entries {
		if !e.IsDir() || !isDigitsName(e.Name()) {
			continue
		}
		env, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || !bytes.Contains(env, needle) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// pgrp is field 5: after the LAST ')' (comm may contain spaces).
		s := string(stat)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+2 >= len(s) {
			continue
		}
		f := strings.Fields(s[i+2:])
		if len(f) < 3 {
			continue
		}
		if pgrp, err := strconv.Atoi(f[2]); err == nil && pgrp > 0 {
			out[pgrp] = true
		}
	}
	return out
}

// killMarkerGroups terminates every marker process group (TERM → KILL)
// — the defensive cleanup that runs even on assertion failure or panic,
// so the test never leaves orphans on the developer machine.
func killMarkerGroups(marker string) {
	for pgrp := range markerPGRPs(marker) {
		_ = syscall.Kill(-pgrp, syscall.SIGTERM)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(markerPGRPs(marker)) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	for pgrp := range markerPGRPs(marker) {
		_ = syscall.Kill(-pgrp, syscall.SIGKILL)
	}
}

// newP0Daemon builds a disconnected daemon wired for the leak test:
// debug mode (fake runtime registered), the fake adapter pointed at the
// fixture binary, and RuntimeEnv carrying the marker + the PTY-child
// fixture knob.
func newP0Daemon(t *testing.T, bin string, env []string) *Daemon {
	t.Helper()
	cfg := Config{
		StateDir:   t.TempDir(),
		Debug:      true,
		NoScan:     true,
		RuntimeEnv: env,
	}
	d, err := newDaemon(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() (string, error) { return "/bin/true", nil })
	if err != nil {
		t.Fatalf("newDaemon: %v", err)
	}
	fake := agentruntime.NewFake(bin)
	fake.Env = env
	d.adapters[domain.RuntimeFake] = fake
	return d
}

// TestPTYSessionLeak is the §46/§47 PTY regression: a PTY session whose
// runtime spawns a slave-holding helper must, after stop(), leave zero
// marker processes and no leaked goroutines.
func TestPTYSessionLeak(t *testing.T) {
	bin := p0FakeBinary(t)
	marker := fmt.Sprintf("pty-%d", os.Getpid())
	instID := domain.NewID().String()

	// Defensive cleanup registered BEFORE the first child is launched:
	// it runs on pass, on assertion failure, and on panic — no orphans.
	t.Cleanup(func() { killMarkerGroups(marker) })
	if live := countMarkerProcesses(marker); live > ptyLeakMaxMarkerChildren {
		killMarkerGroups(marker)
		t.Fatalf("SAFETY CEILING: %d marker processes alive exceed the ceiling %d before start",
			live, ptyLeakMaxMarkerChildren)
	}
	deadline := time.Now().Add(ptyLeakWallLimit)

	d := newP0Daemon(t, bin, []string{
		"PAGNET_P0_LEAK=" + marker,
		"PAGNET_FAKE_PTY_CHILD=1",
	})
	t.Cleanup(func() { _ = d.Close() })

	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: instID,
		Runtime:    "fake",
		Workspace:  t.TempDir(),
		Status:     "idle",
	}); err != nil {
		t.Fatalf("UpsertInstance: %v", err)
	}

	baseProcs := countMarkerProcesses(marker)
	baseGor := runtime.NumGoroutine()
	t.Logf("baseline: marker_procs=%d goroutines=%d", baseProcs, baseGor)

	s, err := d.terminal.start(instID, false)
	if err != nil {
		t.Fatalf("terminal start: %v", err)
	}
	_ = s

	// Wait for the PTY child fixture to appear: the fake runtime itself
	// carries the marker, the slave-holding child inherits it → >= 2.
	for countMarkerProcesses(marker) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := countMarkerProcesses(marker); got < 2 {
		t.Fatalf("pty child fixture did not start (marker procs=%d)", got)
	}
	t.Logf("session live: marker_procs=%d", countMarkerProcesses(marker))

	d.terminal.stop(instID)

	// Wait for the session to be removed from the manager's map.
	for time.Now().Before(deadline) {
		d.terminal.mu.Lock()
		_, live := d.terminal.sessions[instID]
		d.terminal.mu.Unlock()
		if !live {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.terminal.mu.Lock()
	_, stillLive := d.terminal.sessions[instID]
	d.terminal.mu.Unlock()
	if stillLive {
		t.Fatalf("session not removed after stop")
	}

	// Let the kernel finish reaping.
	time.Sleep(500 * time.Millisecond)

	finalProcs := countMarkerProcesses(marker)
	finalGor := runtime.NumGoroutine()
	t.Logf("final:    marker_procs=%d goroutines=%d", finalProcs, finalGor)

	if finalProcs > baseProcs {
		t.Errorf("LEAK: %d marker processes remain after pty stop (baseline %d) — "+
			"the slave-holding descendant survived and keeps the PTY allocated",
			finalProcs-baseProcs, baseProcs)
	}
	if finalGor > baseGor+2 {
		t.Errorf("goroutine leak: baseline %d final %d (readLoop blocked on the master?)",
			baseGor, finalGor)
	}
}

// TestPTYConcurrentStartSingleProcess (external audit F-002): 100
// concurrent starts for the same instance must yield exactly ONE live PTY
// process. The atomic STARTING reservation reconciles every concurrent
// start to the winner's session (waiting on its live channel). Pre-fix,
// the re-check-and-kill path would terminate the SHARED handle (the
// supervisor dedups the duplicate Launch to the same process), killing the
// winner's session. Safety ceilings live in the fixture: a hard cap on
// simultaneously-alive marker children, a wall limit, and a defensive
// group-kill cleanup registered before any child is launched.
func TestPTYConcurrentStartSingleProcess(t *testing.T) {
	bin := p0FakeBinary(t)
	marker := fmt.Sprintf("ptyc-%d", os.Getpid())
	instID := domain.NewID().String()

	// Defensive cleanup registered BEFORE the first child is launched:
	// runs on pass, on assertion failure, and on panic — no orphans.
	t.Cleanup(func() { killMarkerGroups(marker) })
	if live := countMarkerProcesses(marker); live > ptyLeakMaxMarkerChildren {
		killMarkerGroups(marker)
		t.Fatalf("SAFETY CEILING: %d marker processes alive exceed the ceiling %d before start",
			live, ptyLeakMaxMarkerChildren)
	}
	deadline := time.Now().Add(ptyLeakWallLimit)

	d := newP0Daemon(t, bin, []string{
		"PAGNET_P0_LEAK=" + marker,
		"PAGNET_FAKE_PTY_CHILD=1",
	})
	t.Cleanup(func() { _ = d.Close() })

	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: instID,
		Runtime:    "fake",
		Workspace:  t.TempDir(),
		Status:     "idle",
	}); err != nil {
		t.Fatalf("UpsertInstance: %v", err)
	}

	const n = 100
	results := make(chan *ptySession, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := d.terminal.start(instID, false)
			if err != nil {
				errs <- err
				return
			}
			results <- s
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	var errCount int
	var firstErr error
	for err := range errs {
		errCount++
		if firstErr == nil {
			firstErr = err
		}
	}
	sessions := map[*ptySession]bool{}
	for s := range results {
		sessions[s] = true
	}
	if errCount > 0 {
		t.Fatalf("%d of %d concurrent starts failed (want 0); first: %v", errCount, n, firstErr)
	}
	if len(sessions) != 1 {
		t.Fatalf("concurrent starts reconciled to %d distinct sessions, want exactly 1", len(sessions))
	}

	// The single session's fake runtime + its slave-holding child = 2
	// marker processes. If the reservation regressed to N launches, this
	// would be ~2N and trip the ceiling below.
	for countMarkerProcesses(marker) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := countMarkerProcesses(marker); got > ptyLeakMaxMarkerChildren {
		killMarkerGroups(marker)
		t.Fatalf("SAFETY CEILING: %d marker processes alive after %d concurrent starts (want ~2, one session)", got, n)
	}
	t.Logf("concurrent starts: distinct_sessions=1 marker_procs=%d", countMarkerProcesses(marker))
}
