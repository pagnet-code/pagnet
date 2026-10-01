//go:build darwin

package daemon

import (
	"net"
)

func bridgeIsolationMode() string { return bridgeIsolationProcessBound }
func runtimeSandboxMode() string  { return sandboxModeUnsupportedPlatform }
func (d *Daemon) verifyBridgePeer(c net.Conn, rootPID int) error {
	return d.verifyOwnedBridgePeer(c, rootPID)
}
