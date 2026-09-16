//go:build unix

// Package proc is the central process-supervision layer for pagnet's
// process-per-turn architecture (abuse addendum Part B, §16–§61).
//
// It owns, for every OS process pagnet starts on behalf of a turn or a
// PTY session:
//
//   - isolated process-group creation (Setpgid for turns, Setsid for PTY
//     sessions) so a turn's whole tree — runtime CLI, shells, MCP
//     bridges, node/python helpers — is one killable unit;
//   - group termination (TERM → grace → KILL via the OS kill syscall on
//     the negative PGID; never by shelling out to kill/pkill/ps);
//   - single-owner Wait (one goroutine reaps each direct child exactly
//     once and publishes the result);
//   - launch guards (global turn semaphore, per-turn and global
//     owned-process ceilings, host process-pressure refusal,
//     EAGAIN/EMFILE/ENFILE classification with exponential backoff and a
//     launch circuit breaker);
//   - local launch idempotency ((instanceID, turnID) dedup, one active
//     turn per instance);
//   - a persisted ownership record with PID-reuse-safe restart
//     reconciliation;
//   - low-cardinality lifecycle counters and structured logs.
//
// Platform details (process enumeration, start-identity, rlimits) live
// in the build-tagged platform_*.go files so domain code never touches
// syscalls directly (§22/§53: Windows can later plug in Job Objects
// behind the same seams).
package proc

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// childDeathSignal is set on platforms that support a parent-death
// signal to the DIRECT child (Linux PDEATHSIG). Scope, stated precisely:
//
//   - it protects the DIRECT runtime child only — if the daemon dies
//     (crash/kill), the kernel SIGKILLs that one process immediately,
//     which additionally reduces the unrecorded direct-child crash
//     window on Linux (a child started but not yet durably recorded dies
//     with the daemon instead of surviving unowned);
//   - it is NOT a whole-tree kernel kill: descendants are reparented to
//     init (MCP stdio bridges exit when their pipes close; PTY trees
//     additionally get SIGHUP via session-leader death + master close);
//   - it is NOT a replacement for process-group cleanup or restart
//     reconciliation — the durable ownership record + Reconcile remain
//     the PRIMARY orphan-recovery mechanism.
//
// Residual window (honest statement): between cmd.Start() and the
// durable record commit, a descendant may already exist; if the daemon
// dies in that interval, such a descendant can survive without any
// ownership proof and cannot be safely identified (never kill on a bare
// PID or name, §56). That residual is accepted; PDEATHSIG only shrinks
// the direct-child part of it on Linux.
//
// The signal itself is applied by applyChildDeathSignal: the Pdeathsig
// field exists only in the linux syscall package, so the assignment
// cannot live in this shared file — the platform file's init sets both
// the flag and the applier together.
var childDeathSignal = false

// applyChildDeathSignal applies the platform parent-death signal to a
// child's SysProcAttr. nil on platforms without the feature.
var applyChildDeathSignal func(*syscall.SysProcAttr)

// GroupAttrs returns the SysProcAttr that puts the child in its OWN
// process group (child pgid == child pid). Turns use this: descendants
// inherit the group, so the whole tree is one signalable unit. The
// child stays in pagnet's session — it has no controlling terminal
// (turn I/O is pipes), which is exactly the isolation we want. On
// platforms with childDeathSignal, the direct child additionally gets
// the kernel parent-death guarantee (see the seam above).
func GroupAttrs() *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Setpgid: true}
	if childDeathSignal && applyChildDeathSignal != nil {
		applyChildDeathSignal(a)
	}
	return a
}

// SessionAttrs returns the SysProcAttr for a PTY session: the child
// becomes the leader of a NEW session (and therefore of its own process
// group, pgid == pid) with the PTY slave as controlling terminal. This
// is what creack/pty's StartWithSize has always set (Setsid+Setctty);
// the supervisor now sets it explicitly so the PTY lifecycle is owned in
// one place and the group-kill math (pgid == leader pid) is documented.
// On platforms with childDeathSignal, the session leader additionally
// gets the kernel parent-death guarantee (see the seam above).
func SessionAttrs() *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if childDeathSignal && applyChildDeathSignal != nil {
		applyChildDeathSignal(a)
	}
	return a
}

// SignalGroup sends sig to the whole process group pgid via the OS kill
// syscall on the NEGATIVE pgid. §23: the critical cleanup path never
// spawns a helper process — when the host is process-exhausted,
// spawning is precisely what may fail.
//
// A "no such process" result means the group is already gone: it is
// reported as ErrGroupGone so callers can treat it as success.
func SignalGroup(pgid int, sig syscall.Signal) error {
	err := syscall.Kill(-pgid, sig)
	if err == nil {
		return nil
	}
	if err == syscall.ESRCH {
		return ErrGroupGone
	}
	return err
}

// ErrGroupGone reports that a process group no longer exists (already
// fully exited or already killed).
var ErrGroupGone = errors.New("process group no longer exists")

// GroupAlive reports whether any process is still in group pgid (a
// signal-0 probe on the negative pgid).
func GroupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	if err == nil {
		return true
	}
	return err != syscall.ESRCH && err != syscall.EPERM
}

// ProcessAlive is a signal-0 probe on one pid.
func ProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return err != syscall.ESRCH
}

// ProcessLimit returns the effective soft RLIMIT_NPROC (the per-user
// process ceiling the kernel enforces) or 0 when the platform does not
// expose a finite value. 0 means "pressure percentage unknown" — the
// caller falls back to the owned-process limits (§33: do not guess).
func ProcessLimit() int {
	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &rlim); err != nil {
		return 0
	}
	if rlim.Cur == ^uint64(0) || rlim.Cur == 0 { // RLIM_INFINITY
		return 0
	}
	if rlim.Cur > 1<<62 {
		return 0
	}
	return int(rlim.Cur)
}
