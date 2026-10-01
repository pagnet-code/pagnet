//go:build linux

package localpeer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// procStat is the subset of /proc/<pid>/stat the tree binding needs.
// Field numbering follows /proc(5): ppid is field 4, starttime is
// field 22 (clock ticks since boot — the pid-reuse discriminator).
type procStat struct {
	pid       int
	ppid      int
	starttime uint64
}

// parseProcStat parses one /proc/<pid>/stat line. The comm field (2) is
// parenthesized and may contain spaces, parentheses and newlines, so
// the field split starts after the LAST closing paren.
func parseProcStat(b []byte) (procStat, error) {
	s := string(b)
	end := strings.LastIndexByte(s, ')')
	open := strings.IndexByte(s, '(')
	if open <= 0 || end < open || end+2 > len(s) {
		return procStat{}, errors.New("malformed /proc stat (no comm close)")
	}
	// Field 1 (pid) sits before "(comm)"; fields 3+ follow the ") ".
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return procStat{}, fmt.Errorf("malformed /proc stat (pid): %w", err)
	}
	fields := strings.Fields(s[end+1:])
	// fields[0] is field 3 (state); ppid = field 4 → fields[1];
	// starttime = field 22 → fields[22-3].
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return procStat{}, errors.New("malformed /proc stat (too few fields)")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return procStat{}, fmt.Errorf("malformed /proc stat (ppid): %w", err)
	}
	starttime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("malformed /proc stat (starttime): %w", err)
	}
	return procStat{pid: pid, ppid: ppid, starttime: starttime}, nil
}

// readProcStat reads /proc/<pid>/stat for a live process.
func readProcStat(pid int) (procStat, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procStat{}, err
	}
	return parseProcStat(b)
}

// ReadProcess is a kernel process identity; it rejects zombies and mixed
// snapshots instead of treating absent ancestry as an empty owner tree.
func ReadProcess(pid int) (ProcessSnapshot, error) {
	st, err := readProcStat(pid)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return ProcessSnapshot{}, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ProcessSnapshot{}, errors.New("process owner unavailable")
	}
	return ProcessSnapshot{PID: st.pid, Parent: st.ppid, UID: owner.Uid, Start: int64(st.starttime)}, nil
}
func Owner(c net.Conn) (int, uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) { cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, err
	}
	if socketErr != nil || cred == nil {
		return 0, 0, errors.New("peer kernel credentials unavailable")
	}
	if cred.Pid <= 0 || cred.Uid != uint32(os.Getuid()) {
		return 0, 0, errors.New("peer is not the process owner")
	}
	return int(cred.Pid), cred.Uid, nil
}
