// The MCP bridge entrypoints (packaging migration, step 2):
//
//	pagnet mcp worker  — the worker agent's network surface (stdio MCP)
//	pagnet mcp control — the representative's control surface (stdio MCP)
//
// They are INTERNAL: the daemon spawns them for the agent runtimes it
// launches (PAGNET_MCP_CONFIG), so the parent command is hidden from
// the top-level help. The tool names are fixed protocol names — see
// internal/agentbridge (tools_worker.go / tools_control.go). The old
// pagnet-mcp / pagnet-control binaries keep building and behave
// identically until a later migration step removes them.

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"pagnet/internal/agentbridge"
)

var mcpLog = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// mcpCmd is the hidden `pagnet mcp` parent (internal entrypoints).
func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "mcp",
		Short:  "MCP bridge entrypoints (internal: spawned by the daemon)",
		Hidden: true,
	}
	cmd.AddCommand(mcpWorkerCmd(), mcpControlCmd())
	return cmd
}

func mcpWorkerCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Worker MCP bridge: the worker agent's network surface (stdio MCP)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPBridge(socket, "pagnet", agentbridge.RegisterWorkerTools)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "daemon Unix socket (required; injected via PAGNET_MCP_CONFIG)")
	return cmd
}

func mcpControlCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Representative MCP bridge: the control surface (stdio MCP)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPBridge(socket, "pagnet-control", agentbridge.RegisterControlTools)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "daemon Unix socket (required; injected via PAGNET_MCP_CONFIG)")
	return cmd
}

// runMCPBridge is the shared bridge body (ported from the pagnet-mcp /
// pagnet-control mains): env checks, dial with a short retry window,
// tool registration, stdio serve. serverName must stay the EXACT name
// the daemon's MCP config carries ("pagnet" / "pagnet-control").
func runMCPBridge(socket, serverName string, register func(s *server.MCPServer, br *agentbridge.Bridge)) error {
	instanceID := os.Getenv("PAGNET_INSTANCE_ID")
	networkID := os.Getenv("PAGNET_NETWORK_ID") // empty for representatives
	if socket == "" {
		return errors.New("--socket is required (the daemon injects it)")
	}
	if instanceID == "" {
		return errors.New("PAGNET_INSTANCE_ID is not set (this process must be launched by the pagnet daemon)")
	}

	br, err := dialBridge(socket, instanceID, networkID)
	if err != nil {
		return err
	}
	defer br.Close()
	mcpLog.Info("mcp bridge connected", "server", serverName, "instance", instanceID, "network", networkID)

	s := server.NewMCPServer(serverName, "1.0.0")
	register(s, br)
	return server.ServeStdio(s)
}

// dialBridge dials the daemon's Unix socket with a short retry window:
// the socket is local and comes up with the daemon, but the runtime
// process may start a fraction earlier.
func dialBridge(socket, instanceID, networkID string) (*agentbridge.Bridge, error) {
	var br *agentbridge.Bridge
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		br, err = agentbridge.Dial(socket, instanceID, networkID)
		if err == nil {
			return br, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("agent bridge unavailable at %s: %w", socket, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
