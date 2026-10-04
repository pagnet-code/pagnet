package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/pagnet-code/pagnet/internal/fabrichost"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
	"github.com/spf13/cobra"
)

func mcpFabricCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{Use: "fabric", Short: "Connect an MCP client to your local Pagnet node", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		auth, err := fabrichost.FromEnvironment(os.Getenv)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		connection, reader, err := fabrichost.Dial(ctx, socket, auth)
		if err != nil {
			return err
		}
		return fabricmcp.Forward(ctx, connection, reader, os.Stdin, os.Stdout, 1<<20)
	}}
	cmd.Flags().StringVar(&socket, "socket", "", "private local Fabric socket (required)")
	_ = cmd.MarkFlagRequired("socket")
	return cmd
}
