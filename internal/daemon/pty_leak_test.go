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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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
//
// S2: the self-executable resolver must return THIS test binary (like
// production's resolveSelfExecutable): the daemon wires selfExe as the
// sandbox wrapper, and the test binary intercepts the wrapper's
// sandbox-exec subcommand in TestMain. (A placeholder binary such as
// /bin/true would be launched as the "sandboxed runtime" — true exits
// 0 silently, and the session would die before the runtime ever runs.)
func newP0Daemon(t *testing.T, bin string, env []string) *Daemon {
	t.Helper()
	cfg := Config{
		StateDir:   privateDaemonStateDir(t),
		Debug:      true,
		NoScan:     true,
		RuntimeEnv: env,
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	d, err := newDaemon(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() (string, error) { return selfExe, nil })
	if err != nil {
		t.Fatalf("newDaemon: %v", err)
	}
	fake := agentruntime.NewFake(bin)
	fake.Env = env
	d.adapters[domain.RuntimeFake] = fake
	return d
}

// waitPTYLeakChildReady waits for evidence emitted by the slave-holding
// descendant itself, after installing its SIGHUP disposition. A process count
// cannot establish readiness: it may briefly count the sandbox launcher before
// exec, rather than the descendant whose cleanup this regression exercises.
func waitPTYLeakChildReady(t *testing.T, s *ptySession, marker string, deadline time.Time) int {
	t.Helper()
	ready := regexp.MustCompile(`pagnet-pty-child-ready ([0-9]+)\r*\n`)
	for time.Now().Before(deadline) {
		s.bufMu.Lock()
		match := ready.FindSubmatch(s.ring)
		s.bufMu.Unlock()
		if len(match) == 2 {
			pid, err := strconv.Atoi(string(match[1]))
			if err != nil || pid <= 0 || pid == s.h.PID() {
				t.Fatal("invalid slave-holding child readiness identity")
			}
			env, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
			if err != nil || !bytes.Contains(env, []byte("PAGNET_P0_LEAK="+marker+"\x00")) {
				t.Fatal("ready child is not the marked fixture descendant", err)
			}
			pgrp, err := syscall.Getpgid(pid)
			if err != nil || pgrp != s.h.PID() {
				t.Fatal("ready child does not belong to the PTY process group", err)
			}
			childSlave, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", "0"))
			leaderSlave, leaderErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(s.h.PID()), "fd", "0"))
			if err != nil || leaderErr != nil || !strings.HasPrefix(childSlave, "/dev/pts/") || childSlave != leaderSlave {
				t.Fatal("ready child does not hold the session's PTY slave", err, leaderErr)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("slave-holding descendant never reported readiness")
	return 0
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
	childPID := waitPTYLeakChildReady(t, s, marker, deadline)
	t.Logf("slave-holding descendant ready: pid=%d", childPID)

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
	for s := range sessions {
		waitPTYLeakChildReady(t, s, marker, deadline)
	}
	if got := countMarkerProcesses(marker); got > ptyLeakMaxMarkerChildren {
		killMarkerGroups(marker)
		t.Fatalf("SAFETY CEILING: %d marker processes alive after %d concurrent starts (want ~2, one session)", got, n)
	}
	t.Logf("concurrent starts: distinct_sessions=1 marker_procs=%d", countMarkerProcesses(marker))
}
