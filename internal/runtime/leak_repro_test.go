//go:build linux

// Process-leak reproduction + stress regression test (abuse addendum
// Part B §46/§47).
//
// Phase 1 (repro): with the pre-fix adapters, each turn's descendants
// (the PAGNET_FAKE_DESCENDANTS fixture: sh → sleep branches, standing in
// for MCP bridges / shells / node helpers) outlive the turn process and
// are never reaped or killed — the marker process count climbed by the
// full branch count on EVERY cycle (100 leaked processes after 25
// cycles). That accumulation is the macOS
// `forkpty: Resource temporarily unavailable` incident's process side.
//
// Post-fix (this file's assertion): after every cycle the marker count
// must return to baseline — the turn's whole process group is
// terminated and reaped by the supervisor.
//
// SAFETY (2026-09-15 incident hardening): this test spawns real
// subprocesses, so its safety limits live IN the fixture, not in
// operator discipline:
//
//   - the heavy 1,000+ cycle variant is OPT-IN via PAGNET_PROC_STRESS=1;
//     the default run is a small bounded cycle count;
//   - a hard ceiling on simultaneously-alive marker children
//     (maxMarkerChildren): if the live count ever exceeds it, the test
//     STOPS SPAWNING, cleans up, and fails — the suite can never grow an
//     unbounded process population on a live host;
//   - a hard wall-time ceiling per run variant;
//   - a per-cycle context timeout (the supervisor's ctx watcher
//     terminates the whole group on expiry);
//   - a defensive cleanup (kill every marker process group) registered
//     BEFORE the first child is launched, so even an assertion failure
//     or a test panic leaves no orphans;
//   - the supervisor's owned-process ceiling (OwnedProcessesHard,
//     default 256) is engaged for the adapter's private supervisor.
//
// The full stress variant must only be run in a scoped container/cgroup
// (pids + memory limit) — see the P0 report's safe-stress command.
package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// --- safety ceilings (in the fixture, per the 2026-09-15 incident) --------

const (
	// procStressEnv opts in to the heavy 1,000+ cycle variant. Default
	// (unset) is the small bounded run — the ordinary gate.
	procStressEnv = "PAGNET_PROC_STRESS"
	// procCyclesEnv overrides the cycle count explicitly (bounded by the
	// wall-time ceiling below either way).
	procCyclesEnv = "PAGNET_PROC_CYCLES"

	defaultCycles = 25
	stressCycles  = 1000

	// maxMarkerChildren: hard ceiling on simultaneously-alive marker
	// processes (fake runtime + its descendant branches). Exceeding it
	// stops spawning immediately, cleans up, and fails the test.
	maxMarkerChildren = 64

	// Wall-time ceilings: the ordinary run must finish in well under two
	// minutes; the opt-in stress run in well under half an hour.
	normalRunWallLimit = 120 * time.Second
	stressRunWallLimit = 30 * time.Minute

	// cycleTimeout bounds one turn (the supervisor's ctx watcher
	// terminates the whole group on expiry).
	cycleTimeout = 60 * time.Second
)

// countMarkerProcesses counts processes whose environment carries the
// ownership marker (the fixture descendants inherit it from the fake
// runtime, exactly like production descendants inherit PAGNET_TURN_ID).
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
// processes (the supervisor puts each turn tree in its own group).
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
// so the test never leaves orphans on the developer machine (§47: "Do
// NOT leave test orphans on the developer machine if a test itself
// fails").
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

// countFDs is the test process's open file descriptor count.
func countFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// dumpMarkerTree prints the leaked processes (pid ppid pgid cmd) for
// the report's baseline diagnostics.
func dumpMarkerTree(t *testing.T, marker string) {
	t.Helper()
	entries, _ := os.ReadDir("/proc")
	needle := []byte("PAGNET_P0_LEAK=" + marker)
	for _, e := range entries {
		if !e.IsDir() || !isDigitsName(e.Name()) {
			continue
		}
		env, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if !bytes.Contains(env, needle) {
			continue
		}
		stat, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		cmd, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		t.Logf("leaked: pid=%s stat=%q comm=%q", e.Name(), stat, strings.TrimSpace(string(cmd)))
	}
}

// TestTurnProcessTreeLeak is the §46/§47 stress regression: repeated
// turn cycles with a descendant-spawning runtime; after each cycle the
// owned process count must return to baseline (no monotonic climb).
func TestTurnProcessTreeLeak(t *testing.T) {
	bin := p0FakeBinary(t)
	marker := fmt.Sprintf("leak-%d", os.Getpid())

	// Defensive cleanup registered BEFORE the first child is launched:
	// it runs on pass, on assertion failure, and on panic — no orphans.
	t.Cleanup(func() { killMarkerGroups(marker) })

	stress := os.Getenv(procStressEnv) == "1"
	cycles := defaultCycles
	if v := os.Getenv(procCyclesEnv); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cycles = n
		}
	}
	if stress && cycles < stressCycles {
		cycles = stressCycles
	}
	wallLimit := normalRunWallLimit
	if stress {
		wallLimit = stressRunWallLimit
	}
	t.Logf("stress=%v cycles=%d wallLimit=%v maxMarkerChildren=%d",
		stress, cycles, wallLimit, maxMarkerChildren)

	adapter := NewFake(bin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")

	baseProcs := countMarkerProcesses(marker)
	baseGor := runtime.NumGoroutine()
	baseFDs := countFDs()
	t.Logf("baseline: marker_procs=%d goroutines=%d fds=%d",
		baseProcs, baseGor, baseFDs)

	deadline := time.Now().Add(wallLimit)
	var samples [][3]int // cycle, marker_procs, goroutines
	for i := 1; i <= cycles; i++ {
		// Hard ceiling: if the live marker population already exceeds
		// the bound, STOP SPAWNING, clean up, and fail — the suite must
		// never be able to grow an unbounded process population.
		if live := countMarkerProcesses(marker); live > maxMarkerChildren {
			killMarkerGroups(marker)
			t.Fatalf("SAFETY CEILING: %d marker processes alive exceed the ceiling %d — stopping before cycle %d",
				live, maxMarkerChildren, i)
		}
		if time.Now().After(deadline) {
			killMarkerGroups(marker)
			t.Fatalf("SAFETY CEILING: wall time %v exceeded before cycle %d of %d",
				wallLimit, i, cycles)
		}

		ctx, cancel := context.WithTimeout(context.Background(), cycleTimeout)
		events := make(chan TurnEvent, 16)
		spec := TurnSpec{
			TurnID:     fmt.Sprintf("turn-%d", i),
			InstanceID: "inst-leak",
			Workspace:  workspace,
			SessionDir: sessionDir,
			Input:      "leak repro cycle",
			InputKind:  "task",
			Env: []string{
				"PAGNET_P0_LEAK=" + marker,
				"PAGNET_FAKE_DESCENDANTS=2",
			},
		}
		err := adapter.StartTurn(ctx, spec, events)
		cancel()
		if err != nil {
			killMarkerGroups(marker)
			t.Fatalf("cycle %d: StartTurn: %v", i, err)
		}
		procs := countMarkerProcesses(marker)
		samples = append(samples, [3]int{i, procs, runtime.NumGoroutine()})
		if i == 1 || i%5 == 0 || i == cycles {
			t.Logf("cycle %3d: marker_procs=%d goroutines=%d", i, procs, runtime.NumGoroutine())
		}
	}

	finalProcs := countMarkerProcesses(marker)
	finalGor := runtime.NumGoroutine()
	finalFDs := countFDs()
	t.Logf("final:    marker_procs=%d goroutines=%d fds=%d", finalProcs, finalGor, finalFDs)

	// No monotonic climb: the last sample must not exceed the first
	// cycle's count (post-fix both are baseline).
	if len(samples) >= 2 && samples[len(samples)-1][1] > samples[0][1] {
		t.Errorf("marker process count climbed: cycle1=%d final=%d (leak)",
			samples[0][1], samples[len(samples)-1][1])
	}
	// Back to baseline within tolerance (+2: kernel reaping lag).
	if finalProcs > baseProcs+2 {
		dumpMarkerTree(t, marker)
		t.Fatalf("LEAK: %d marker processes remain after %d cycles (baseline %d) — "+
			"turn process trees are not being reclaimed", finalProcs-baseProcs, cycles, baseProcs)
	}
	// Goroutines must not climb either (PTY/turn goroutine leaks).
	if finalGor > baseGor+4 {
		t.Errorf("goroutine leak: baseline %d final %d", baseGor, finalGor)
	}
	if finalFDs > baseFDs+4 {
		t.Errorf("fd leak: baseline %d final %d", baseFDs, finalFDs)
	}
}
