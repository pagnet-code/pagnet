//go:build linux

package daemon

// Process-tree binding of the agent bridge (security wave S1, Linux).
//
// The bridge socket is 0600 but same-UID: every process the user runs
// can connect. SO_PEERCRED names the connecting PROCESS (pid + uid),
// and /proc gives its parent chain. A legitimate bridge is a
// grandchild of the daemon's own runtime process (daemon spawns the
// runtime; the runtime's MCP client spawns the bridge), so its ancestor
// chain MUST reach the claimed instance's current supervisor root PID —
// and its start time must be no older than the root's (a pid reused for
// an unrelated process cannot predate the root it would falsely join).
//
// Any failure is a rejection with a distinct message; there is no
// degraded/allowed path on Linux.

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/pagnet-code/pagnet/internal/sandbox"
)

// bridgeIsolationMode reports this platform's bridge isolation state
// (the process-tree binding is enforced here).
func bridgeIsolationMode() string {
	return bridgeIsolationProcessBound
}

// runtimeSandboxMode reports this platform's runtime filesystem-sandbox
// state (S2, the S1 heartbeat-pattern extension): "landlock" when the
// Landlock kernel boundary is available (managed runtimes are
// sandboxed), "fail_closed" when it is NOT (kernel too old — the daemon
// refuses to launch untrusted runtimes rather than run them
// unsandboxed; without the sandbox, activation MUST NOT proceed —
// H3/H5).
func runtimeSandboxMode() string {
	if sandbox.Available() {
		return sandboxModeLandlock
	}
	var warned int32
	if atomic.CompareAndSwapInt32(&warned, 0, 1) {
		slog.Error("runtime sandbox unavailable: Landlock not supported by this kernel — managed runtimes will be refused (fail closed)",
			"kernel", sandbox.KernelRelease())
	}
	return sandboxModeFailClosed
}

// bridgeTreeMaxHops bounds the /proc ppid walk: a legitimate bridge is
// at most a couple of levels below the runtime (runtime → MCP client →
// bridge); a walk longer than this is a misbehaving or adversarial tree
// and is refused.
const bridgeTreeMaxHops = 32

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
	if end < 0 || end+2 > len(s) {
		return procStat{}, errors.New("malformed /proc stat (no comm close)")
	}
	// Field 1 (pid) sits before "(comm)"; fields 3+ follow the ") ".
	pid, err := strconv.Atoi(strings.TrimSpace(s[:strings.IndexByte(s, '(')]))
	if err != nil {
		return procStat{}, fmt.Errorf("malformed /proc stat (pid): %w", err)
	}
	fields := strings.Fields(s[end+1:])
	// fields[0] is field 3 (state); ppid = field 4 → fields[1];
	// starttime = field 22 → fields[22-3].
	if len(fields) < 20 {
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

// processTreeReaches walks the /proc ppid chain from peerPID upward and
// reports whether it reaches rootPID. Bounded (bridgeTreeMaxHops),
// cycle-safe, and it stops at init (a chain that hits ppid 0/1 without
// finding the root cannot reach it).
func processTreeReaches(peerPID, rootPID int) error {
	seen := make(map[int]bool, bridgeTreeMaxHops+1)
	cur := peerPID
	for hops := 0; hops <= bridgeTreeMaxHops; hops++ {
		if cur == rootPID {
			return nil
		}
		if seen[cur] {
			return fmt.Errorf("pid cycle at %d (tree refused)", cur)
		}
		seen[cur] = true
		st, err := readProcStat(cur)
		if err != nil {
			return fmt.Errorf("peer process %d vanished during verification: %w", cur, err)
		}
		if st.ppid <= 1 {
			return fmt.Errorf("peer process tree does not contain the instance root (chain hit init)")
		}
		cur = st.ppid
	}
	return fmt.Errorf("peer process tree does not contain the instance root (walk exceeded %d hops)", bridgeTreeMaxHops)
}

// verifyBridgePeer enforces the Linux process-tree binding on the
// accepted bridge connection: the peer must be the daemon's own user AND
// a descendant of the instance's current supervisor root process, no
// older than that root. It runs AFTER the nonce check (the portable
// layer) and BEFORE auth_ok.
func (d *Daemon) verifyBridgePeer(c net.Conn, rootPID int) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("bridge connection is not a Unix socket")
	}
	// SO_PEERCRED on the accepted fd (via SyscallConn.Control so the
	// connection's internal locking stays correct).
	var (
		cred    *unix.Ucred
		sockErr error
	)
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer credentials unavailable: %w", err)
	}
	if err := rawConn.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("peer credentials unavailable: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("peer credentials unavailable: %w", sockErr)
	}
	if cred.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("peer uid %d is not the daemon uid %d (peer refused)", cred.Uid, os.Getuid())
	}
	peerPID := int(cred.Pid)
	// The root must still be alive and own the claimed pid: a stale pid
	// (the instance's process died between the auth read and now) fails
	// the read and is rejected.
	rootStat, err := readProcStat(rootPID)
	if err != nil {
		return fmt.Errorf("instance root process %d is not alive: %w", rootPID, err)
	}
	peerStat, err := readProcStat(peerPID)
	if err != nil {
		return fmt.Errorf("peer process %d vanished: %w", peerPID, err)
	}
	// pid-reuse discriminator: a real descendant starts AFTER its
	// ancestor. (Clock-tick resolution: equal start times pass — a
	// process cannot start on an earlier tick than its parent, and an
	// equal tick is the tightest the kernel can express.)
	if peerStat.starttime < rootStat.starttime {
		return fmt.Errorf("peer process %d predates the instance root %d (pid reuse refused)", peerPID, rootPID)
	}
	if err := processTreeReaches(peerPID, rootPID); err != nil {
		return err
	}
	return nil
}
