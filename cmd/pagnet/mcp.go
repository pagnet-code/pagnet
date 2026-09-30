// MCP entrypoints use separate trust boundaries:
//
// pagnet mcp worker/control are spawned by the managed daemon and use its
// authenticated local socket. pagnet mcp external connects independent agents
// and plugins using a dedicated principal credential and explicit grants.

package main

import (
	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/internal/agentbridge"
)

// mcpCmd exposes the external integration while retaining managed entrypoints.
func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "mcp",
		Short:  "MCP bridges for managed and external agents",
		Hidden: false,
	}
	cmd.AddCommand(mcpWorkerCmd(), mcpControlCmd(), mcpExternalCmd(), mcpConnectCmd())
	return cmd
}

func mcpWorkerCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:    "worker",
		Hidden: true,
		Short:  "Worker MCP bridge: the worker agent's network surface (stdio MCP)",
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return agentbridge.RunBridge(socket, "pagnet", "worker", agentbridge.RegisterWorkerTools)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "daemon Unix socket (required; injected via PAGNET_MCP_CONFIG)")
	return cmd
}

func mcpControlCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:    "control",
		Hidden: true,
		Short:  "Representative MCP bridge: the control surface (stdio MCP)",
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return agentbridge.RunBridge(socket, "pagnet-control", "representative", agentbridge.RegisterControlTools)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "daemon Unix socket (required; injected via PAGNET_MCP_CONFIG)")
	return cmd
}
