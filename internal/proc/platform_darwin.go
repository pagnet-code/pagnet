//go:build darwin

package proc

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// macOS process information comes from the kernel's KERN_PROC sysctl
// (the same source `ps` uses — read-only, no helper processes, §30/§33).
//
// Root cause of the 2026-09-17 macos-latest CI failures (proven against
// the XNU headers): extern_proc.p_pgrp is a kernel POINTER (struct pgrp *),
// not a pgid — modern XNU bzeros the whole kinfo_proc and
// fill_user64_externproc() never assigns p_pgrp, so kp.Proc.P_pgrp is
// ALWAYS 0 on every macOS. The authoritative pgid is eproc.e_pgid (pid_t),
// filled by the kernel as ep->e_pgid = p->p_pgrpid — the same source ps
// reads: kp.Eproc.Pgid for enumeration, getpgid(2) for per-pid queries.
//
// The original P0 incident happened on macOS, so this file is not a
// porting afterthought: group enumeration, start-identity, and
// pressure detection all run on the kernel API here, and the Darwin
// build-tagged tests exercise them on a macOS host. The CI
// `client (macos-latest)` job is the de-facto darwin acceptance runner
// (there is no separate acceptance document).

// darwinProc is the subset of KinfoProc the supervisor needs.
type darwinProc struct {
	pid  int
	pgrp int // Eproc.Pgid (eproc.e_pgid): the kernel-filled pgid — the same
	// source `ps` reads. extern_proc.p_pgrp is a kernel pointer that
	// modern XNU never fills (always 0) and must never be read.
	uid   int
	stat  byte  // P_stat & 0x1f: process state (darwinSZombie = dead)
	start int64 // P_starttime: microseconds since boot (start identity)
}

// darwinSZombie is the BSD/macOS process state for a zombie (SZOMB in
// <sys/proc.h>). x/sys/unix does not export the p_stat state constants
// for darwin, so the value is defined here. A zombie is a dead process
// awaiting reap — it cannot be signaled into dying.
const darwinSZombie = 5

// readDarwinProcs enumerates every process via kern.proc.all and returns
// the subset the supervisor needs. A failed enumeration is returned as an
// error (and recorded for EnumError) — it is UNKNOWN, never an empty list:
// a nil/empty result from a failed pass must not be read as "no processes".
func readDarwinProcs() ([]darwinProc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		setEnumErr(err)
		return nil, err
	}
	setEnumErr(nil)
	out := make([]darwinProc, 0, len(kps))
	for _, kp := range kps {
		if kp.Proc.P_pid == 0 {
			continue
		}
		out = append(out, darwinProc{
			pid:   int(kp.Proc.P_pid),
			pgrp:  int(kp.Eproc.Pgid),
			uid:   int(kp.Eproc.Ucred.Uid),
			stat:  byte(int(kp.Proc.P_stat) & 0x1f),
			start: kp.Proc.P_starttime.Sec*1000000 + int64(kp.Proc.P_starttime.Usec),
		})
	}
	return out, nil
}

// CountGroup returns the number of processes currently in group pgid.
func CountGroup(pgid int) int {
	procs, _ := readDarwinProcs()
	n := 0
	for _, p := range procs {
		if p.pgrp == pgid {
			n++
		}
	}
	return n
}

// CountOwnedErr is CountOwned with the enumeration error surfaced: a
// non-nil error means the count is UNKNOWN (the enumeration failed), not
// zero. The supervisor's owned-process ceiling uses this to fail closed.
func CountOwnedErr(groups map[int]bool) (int, error) {
	procs, err := readDarwinProcs()
	if err != nil {
		return 0, err
	}
	if len(groups) == 0 {
		return 0, nil
	}
	n := 0
	for _, p := range procs {
		if groups[p.pgrp] {
			n++
		}
	}
	return n, nil
}

// CountOwned returns the total number of processes in any of the owned
// process groups (one KERN_PROC_ALL pass, not one per group).
func CountOwned(groups map[int]bool) int {
	n, _ := CountOwnedErr(groups)
	return n
}

// CountGroups returns the per-group process counts for the given owned
// groups in ONE KERN_PROC_ALL pass (the monitor calls this every tick).
func CountGroups(groups map[int]bool) map[int]int {
	out := make(map[int]int, len(groups))
	if len(groups) == 0 {
		return out
	}
	procs, _ := readDarwinProcs()
	for _, p := range procs {
		if groups[p.pgrp] {
			out[p.pgrp]++
		}
	}
	return out
}

// GroupMembers lists the pids currently in group pgid.
func GroupMembers(pgid int) []int {
	procs, _ := readDarwinProcs()
	var out []int
	for _, p := range procs {
		if p.pgrp == pgid {
			out = append(out, p.pid)
		}
	}
	return out
}

// GroupHasLiveMemberErr is GroupHasLiveMember with the enumeration error
// surfaced: a non-nil error means the group's state is UNKNOWN (the
// enumeration failed), NOT "no live member". The supervisor's descendant
// reclaim and termination poll use this to fail closed.
// kill(-pgid, 0) was rejected as the liveness check: it cannot see zombies; see platform_linux.go.
func GroupHasLiveMemberErr(pgid int) (bool, error) {
	procs, err := readDarwinProcs()
	if err != nil {
		return false, err
	}
	for _, p := range procs {
		if p.pgrp == pgid && p.stat != darwinSZombie {
			return true, nil
		}
	}
	return false, nil
}

// GroupHasLiveMember reports whether the group has any member that is
// actually alive (state != SZOMB). A zombie is a dead process awaiting
// reap and cannot be signaled into dying, so the TERM→grace→KILL poll
// must not wait on it (see the Linux implementation for the full
// rationale — the 2026-09-15 5s-per-cycle leak-test regression).
func GroupHasLiveMember(pgid int) bool {
	ok, _ := GroupHasLiveMemberErr(pgid)
	return ok
}

// UserProcessCount returns the number of processes of the current user
// (the population RLIMIT_NPROC bounds).
func UserProcessCount() (int, error) {
	uid := os.Getuid()
	procs, _ := readDarwinProcs()
	n := 0
	for _, p := range procs {
		if p.uid == uid {
			n++
		}
	}
	return n, nil
}

// ProcessIsZombie reports whether pid exists and has already exited
// (P_stat == SZOMB, KERN_PROC_PID): dead, awaiting reap. See the Linux
// implementation for the ownership-anchor rationale (managedTurn.
// ownerWait).
func ProcessIsZombie(pid int) bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return false
	}
	return byte(int(kp.Proc.P_stat)&0x1f) == darwinSZombie
}

// ProcessGroupOf returns the process group id of pid (getpgid(2)).
func ProcessGroupOf(pid int) (int, error) {
	return unix.Getpgid(pid)
}

// StartIdentity returns the kernel start-time marker of pid
// (P_starttime, the full Timeval). The marker is MICROSECONDS since boot
// (Sec*1000000 + Usec), not seconds: second granularity would let two
// processes started within the same second share an identity, breaking
// the PID-reuse contract (§39) — a reused PID must yield a different
// identity, and processes launched milliseconds apart must too. A PID
// reuse gets a different start time, so this is the PID-reuse-safe
// identity the ownership record stores (§39).
func StartIdentity(pid int) (string, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}
	micros := kp.Proc.P_starttime.Sec*1000000 + int64(kp.Proc.P_starttime.Usec)
	return strconv.FormatInt(micros, 10), nil
}

// EnvHasMarker: macOS does not expose other processes' environments
// through any supported API, so marker-based ownership proof is not
// available there. Reconciliation falls back to leader-identity
// verification only (never killing on a bare PID, §39).
func EnvHasMarker(pid int, marker string) (bool, error) {
	return false, ErrMarkerUnavailable
}
