//go:build linux

package proc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Linux process information comes from /proc (no helper processes —
// §30/§33: never spawn `ps` on the safety path).

func init() {
	// Linux supports PDEATHSIG: if the daemon dies (crash/kill), the
	// kernel SIGKILLs the direct child immediately — the kernel backstop
	// for the start→record crash window (see childDeathSignal).
	childDeathSignal = true
	applyChildDeathSignal = func(a *syscall.SysProcAttr) {
		a.Pdeathsig = syscall.SIGKILL
	}
}

// procStat is the subset of /proc/<pid>/stat (+ the /proc/<pid> inode
// owner) the supervisor needs.
type procStat struct {
	pid   int
	pgrp  int
	uid   int
	state byte   // stat field 3: process state ('Z' = zombie)
	start uint64 // stat field 22: clock ticks since boot (start identity)
}

// readProcStats scans /proc once and returns the stat data of every
// process readable by this user (our own plus same-user processes —
// exactly the population that counts against RLIMIT_NPROC).
//
// The uid comes from the OWNER of the /proc/<pid> inode (the kernel
// sets it to the process's uid); /proc/<pid>/stat has no uid field —
// field 6 is the session id, which must not be mistaken for it.
func readProcStats() []procStat {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procStat
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", e.Name())
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		sys, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		if st := parseProcStat(pid, b); st != nil {
			st.uid = int(sys.Uid)
			out = append(out, *st)
		}
	}
	return out
}

// parseProcStat parses /proc/<pid>/stat. The comm field (2) may contain
// spaces and parentheses, so parsing starts after the LAST ')'.
func parseProcStat(pid int, b []byte) *procStat {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return nil
	}
	f := strings.Fields(s[i+2:])
	// f[0] is stat field 3 (state); pgrp is field 5 → f[2];
	// starttime is field 22 → f[19].
	if len(f) < 20 {
		return nil
	}
	pgrp, _ := strconv.Atoi(f[2])
	start, _ := strconv.ParseUint(f[19], 10, 64)
	var state byte
	if len(f[0]) > 0 {
		state = f[0][0]
	}
	return &procStat{pid: pid, pgrp: pgrp, state: state, start: start}
}

// CountGroup returns the number of processes currently in group pgid
// (zombies included — they count against the process limit too).
func CountGroup(pgid int) int {
	n := 0
	for _, st := range readProcStats() {
		if st.pgrp == pgid {
			n++
		}
	}
	return n
}

// CountOwned returns the total number of processes in any of the owned
// process groups (one /proc scan, not one per group).
func CountOwned(groups map[int]bool) int {
	if len(groups) == 0 {
		return 0
	}
	n := 0
	for _, st := range readProcStats() {
		if groups[st.pgrp] {
			n++
		}
	}
	return n
}

// CountGroups returns the per-group process counts for the given owned
// groups in ONE /proc scan (the monitor calls this every tick).
func CountGroups(groups map[int]bool) map[int]int {
	out := make(map[int]int, len(groups))
	if len(groups) == 0 {
		return out
	}
	for _, st := range readProcStats() {
		if groups[st.pgrp] {
			out[st.pgrp]++
		}
	}
	return out
}

// GroupMembers lists the pids currently in group pgid.
func GroupMembers(pgid int) []int {
	var out []int
	for _, st := range readProcStats() {
		if st.pgrp == pgid {
			out = append(out, st.pid)
		}
	}
	return out
}

// GroupHasLiveMember reports whether the group has any member that is
// actually alive (state != 'Z'). A zombie is a DEAD process awaiting
// reap: it cannot be signaled into dying, so the TERM→grace→KILL poll
// must not wait on it. Without this distinction, a turn whose direct
// child has exited but not yet been reaped by the owner (cmd.Wait)
// holds the group "alive" for the full grace window — the 2026-09-15
// 5s-per-cycle leak-test regression. The owner reaps the direct child
// separately; this check is about the descendants that a group kill
// can still reach.
func GroupHasLiveMember(pgid int) bool {
	for _, st := range readProcStats() {
		if st.pgrp == pgid && st.state != 'Z' {
			return true
		}
	}
	return false
}

// UserProcessCount returns the number of processes of the current user
// (the population RLIMIT_NPROC bounds).
func UserProcessCount() (int, error) {
	uid := os.Getuid()
	n := 0
	for _, st := range readProcStats() {
		if st.uid == uid {
			n++
		}
	}
	return n, nil
}

// ProcessIsZombie reports whether pid exists and has already exited
// (state 'Z' in /proc/<pid>/stat): dead, awaiting reap. An unreaped
// zombie still HOLDS its pid, so the process group it led (pgid == pid)
// remains anchored to it — no other process can hold that pgid until the
// reap frees the pid. The turn-exit descendant reclaim uses this to
// distinguish "the child has exited; surviving group members are its
// descendants" from "the child is still running; the group is the live
// turn" (managedTurn.ownerWait).
func ProcessIsZombie(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	st := parseProcStat(pid, b)
	return st != nil && st.state == 'Z'
}

// ProcessGroupOf returns the process group id of pid (field 5 of
// /proc/<pid>/stat). The comm field may contain spaces/parens, so
// parsing starts after the LAST ')' (parseProcStat).
func ProcessGroupOf(pid int) (int, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	st := parseProcStat(pid, b)
	if st == nil {
		return 0, os.ErrNotExist
	}
	return st.pgrp, nil
}

// StartIdentity returns the kernel start-time marker of pid (clock
// ticks since boot, /proc/<pid>/stat field 22). A PID reuse gets a
// different start time, so this is the PID-reuse-safe identity the
// ownership record stores (§39).
func StartIdentity(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	st := parseProcStat(pid, b)
	if st == nil {
		return "", os.ErrNotExist
	}
	return strconv.FormatUint(st.start, 10), nil
}

// EnvHasMarker reports whether pid's environment (read from
// /proc/<pid>/environ, same-user only) contains the KEY=VALUE marker.
// This is the ownership proof for restart reconciliation when the
// recorded leader pid is already gone but its group survives (§39/§42).
func EnvHasMarker(pid int, marker string) (bool, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return false, err
	}
	// environ is NUL-separated; match a whole KEY=VALUE entry.
	for _, kv := range strings.Split(string(b), "\x00") {
		if kv == marker {
			return true, nil
		}
	}
	return false, nil
}

// ProcFSAvailable reports whether /proc is usable (container quirks).
func ProcFSAvailable() bool {
	_, err := os.Stat("/proc/self/stat")
	return err == nil
}
