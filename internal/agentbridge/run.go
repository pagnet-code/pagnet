// The shared MCP bridge body (packaging migration step 5). The daemon
// spawns its bridges as <self> mcp worker|control, so EVERY binary that
// can run the daemon (pagnet, and pagnetd until the unified binary
// replaces it) must be able to run the bridge too. The entrypoints live
// in the cmd/ packages; this is the one shared run/dial implementation
// they all route to.

package agentbridge

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

// log is the bridge's own stderr logger (JSON): the bridge is spawned
// by an agent runtime whose stdout is the MCP protocol channel —
// diagnostics go to stderr, never stdout.
var log = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// RunBridge serves one MCP bridge over stdio: check the injected
// environment, connect to the daemon's Unix socket with the instance
// identity, register the surface's tools, and serve until the runtime
// closes stdin. serverName must stay the EXACT name the daemon's MCP
// config carries ("pagnet" / "pagnet-control").
func RunBridge(socket, serverName string, register func(s *server.MCPServer, br *Bridge)) error {
	instanceID := os.Getenv("PAGNET_INSTANCE_ID")
	networkID := os.Getenv("PAGNET_NETWORK_ID") // empty for representatives
	if socket == "" {
		return errors.New("--socket is required (the daemon injects it)")
	}
	if instanceID == "" {
		return errors.New("PAGNET_INSTANCE_ID is not set (this process must be launched by the pagnet daemon)")
	}

	br, err := dialWithRetry(socket, instanceID, networkID)
	if err != nil {
		return err
	}
	defer br.Close()
	log.Info("mcp bridge connected", "server", serverName, "instance", instanceID, "network", networkID)

	s := server.NewMCPServer(serverName, "1.0.0")
	register(s, br)
	return server.ServeStdio(s)
}

// dialWithRetry dials the daemon's Unix socket with a short retry
// window: the socket is local and comes up with the daemon, but the
// runtime process may start a fraction earlier.
func dialWithRetry(socket, instanceID, networkID string) (*Bridge, error) {
	var br *Bridge
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		br, err = Dial(socket, instanceID, networkID)
		if err == nil {
			return br, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("agent bridge unavailable at %s: %w", socket, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
