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
	"github.com/pagnet-code/pagnet/internal/sandbox"
	"log/slog"
	"net"
	"sync/atomic"
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

func (d *Daemon) verifyBridgePeer(c net.Conn, rootPID int) error {
	return d.verifyOwnedBridgePeer(c, rootPID)
}
