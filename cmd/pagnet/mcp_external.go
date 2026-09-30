package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/internal/externalbridge"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

func mcpExternalCmd() *cobra.Command {
	var network, listen string
	var grants []string
	cmd := &cobra.Command{Use: "external", Short: "Independent principal MCP bridge for external agents and plugins", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := externalbridge.Config{Network: network, Grants: grants}
		// Validate all local policy before consuming a one-time activation.
		if _, err := externalbridge.New(nil, cfg); err != nil {
			return err
		}
		token := os.Getenv("PAGNET_MCP_HTTP_TOKEN")
		if listen != "" {
			if err := externalbridge.ValidateListen(listen, token); err != nil {
				return err
			}
		}
		ctx := cmd.Context()
		connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		sdkConfig := sdk.ConfigFromEnv()
		if !strings.HasPrefix(sdkConfig.Credential, "pgn_act_v1_") && !strings.HasPrefix(sdkConfig.Credential, "pgn_epd_v1_") {
			cancel()
			return errors.New("external MCP: PAGNET_CREDENTIAL must be an activation or endpoint principal credential")
		}
		client, err := sdk.Connect(connectCtx, sdkConfig)
		cancel()
		if err != nil {
			return err
		}
		defer client.Close()
		identity, err := client.WhoAmI(ctx)
		if err != nil {
			return err
		}
		active := false
		for _, m := range identity.Memberships {
			if m.NetworkID == network && m.State == "active" {
				active = true
			}
		}
		if !active {
			return errors.New("external MCP: principal requires active membership in the configured network")
		}
		bridge, err := externalbridge.New(client, cfg)
		if err != nil {
			return err
		}
		if listen == "" {
			return server.ServeStdio(bridge.Server())
		}
		httpServer := &http.Server{Addr: listen, Handler: externalbridge.HTTPHandler(bridge.Server(), token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpServer.Shutdown(shutdownCtx)
			case <-done:
			}
		}()
		err = httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}}
	cmd.Flags().StringVar(&network, "network", "", "fixed network UUID (required)")
	cmd.Flags().StringSliceVar(&grants, "allow-invoke", nil, "exact PRINCIPAL_UUID/CAPABILITY_ID grant (repeatable; default discovery only)")
	cmd.Flags().StringVar(&listen, "listen", "", "optional loopback IP:port for streamable HTTP at /mcp; requires PAGNET_MCP_HTTP_TOKEN")
	return cmd
}
