// The MCP bridge entrypoints (packaging migration, step 2):
//
//	pagnet mcp worker  — the worker agent's network surface (stdio MCP)
//	pagnet mcp control — the representative's control surface (stdio MCP)
//
// They are INTERNAL: the daemon spawns them for the agent runtimes it
// launches (PAGNET_MCP_CONFIG), so the parent command is hidden from
// the top-level help. The tool names are fixed protocol names — see
// internal/agentbridge (tools_worker.go / tools_control.go). The run
// body is the shared agentbridge.RunBridge — the same implementation
// pagnetd's hidden mcp subcommands route to (step 5: the daemon spawns
// the bridges as <self> mcp worker|control, so every binary that can
// run the daemon must be able to run the bridge). The old
// pagnet-mcp / pagnet-control binaries keep building and behave
// identically until a later migration step removes them.

package main

import (
	"github.com/spf13/cobra"

	"pagnet/internal/agentbridge"
)

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
			return agentbridge.RunBridge(socket, "pagnet", agentbridge.RegisterWorkerTools)
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
			return agentbridge.RunBridge(socket, "pagnet-control", agentbridge.RegisterControlTools)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "daemon Unix socket (required; injected via PAGNET_MCP_CONFIG)")
	return cmd
}
