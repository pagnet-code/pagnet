//go:build !linux

package daemon

// Non-Linux platforms (macOS development machines): no SO_PEERCRED.
//
// The owner-scoped contract for these platforms is NON-ISOLATED: the
// process-tree binding is unavailable, so the portable layer is the
// security boundary — the per-activation nonce (a capability only the
// instance's own runtime can hold, because only it receives the
// daemon-rendered MCP config) plus the "the claimed instance has a
// live supervisor process" check. Identifier-only auth is refused here
// too: a bridge without a valid current nonce is rejected exactly as on
// Linux. A one-time warning at socket start and the heartbeat's
// bridge-isolation state make the weaker guarantee visible.

import (
	"net"
)

// bridgeIsolationNonceOnly is the isolation state this platform
// enforces (reported on the daemon heartbeat).
const bridgeIsolationNonceOnly = "nonce-only (platform lacks peer credentials)"

// bridgeIsolationMode reports this platform's bridge isolation state.
func bridgeIsolationMode() string {
	return bridgeIsolationNonceOnly
}

// verifyBridgePeer is the non-Linux stand-in for the process-tree
// binding: a no-op, because the portable checks (nonce + live instance
// process) already ran before this call. The isolation state on this
// platform is "nonce-only" BY DESIGN — the same-UID boundary is not
// isolated here, and that is surfaced, not hidden.
func (d *Daemon) verifyBridgePeer(c net.Conn, rootPID int) error {
	return nil
}
