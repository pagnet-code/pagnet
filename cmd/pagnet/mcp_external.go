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
	var network, listen, publicURL, issuer, introspection, subject, profile, stateDir string
	var grants, messagingTargets []string
	cmd := &cobra.Command{Use: "external", Short: "Independent principal MCP bridge for external agents and plugins", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		sdkConfig := sdk.ConfigFromEnv()
		var expectedPrincipal string
		if profile != "" {
			for _, flag := range []string{"network", "allow-invoke", "allow-message", "listen", "oauth-resource", "oauth-issuer", "oauth-introspection", "oauth-subject"} {
				if cmd.Flags().Changed(flag) {
					return errors.New("external profile cannot be combined with policy or HTTP overrides")
				}
			}
			p, saved, err := externalProfileConfig(machineStateDir(stateDir), profile)
			if err != nil {
				return err
			}
			if err := verifyExternalProfile(cmd.Context(), p, saved); err != nil {
				return err
			}
			network, grants, messagingTargets, sdkConfig, expectedPrincipal = p.Network, p.Grants, p.MessagingTargets, saved, p.Principal
		}
		cfg := externalbridge.Config{Network: network, Grants: grants, MessagingTargets: messagingTargets}
		// Validate all local policy before consuming a one-time activation.
		if _, err := externalbridge.New(nil, cfg); err != nil {
			return err
		}
		token := os.Getenv("PAGNET_MCP_HTTP_TOKEN")
		oauth := externalbridge.OAuthConfig{ResourceURL: publicURL, Issuer: issuer, IntrospectionURL: introspection, Subject: subject, ClientID: os.Getenv("PAGNET_MCP_OAUTH_CLIENT_ID"), ClientSecret: os.Getenv("PAGNET_MCP_OAUTH_CLIENT_SECRET"), AllowInvoke: len(grants) > 0 || len(messagingTargets) > 0}
		useOAuth := publicURL != "" || issuer != "" || introspection != "" || subject != ""
		if useOAuth {
			if listen == "" {
				return errors.New("external MCP: OAuth requires --listen behind a public HTTPS proxy")
			}
			if token != "" {
				return errors.New("external MCP: OAuth and shared bearer modes are mutually exclusive")
			}
			if err := oauth.Validate(); err != nil {
				return err
			}
		}
		if listen != "" {
			if useOAuth {
				if err := externalbridge.ValidateBind(listen); err != nil {
					return err
				}
			} else if err := externalbridge.ValidateListen(listen, token); err != nil {
				return err
			}
		}
		ctx := cmd.Context()
		connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		if expectedPrincipal != "" && identity.PrincipalID != expectedPrincipal {
			return errors.New("external bridge authenticated another principal")
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
		handler := externalbridge.HTTPHandler(bridge.Server(), token)
		if useOAuth {
			handler, err = externalbridge.OAuthHTTPHandler(bridge.Server(), oauth)
			if err != nil {
				return err
			}
		}
		httpServer := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
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
	cmd.Flags().StringVar(&profile, "profile", "", "private local external profile name (stdio only)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "private profile state directory")
	cmd.Flags().StringVar(&network, "network", "", "fixed network UUID (required)")
	cmd.Flags().StringSliceVar(&grants, "allow-invoke", nil, "exact PRINCIPAL_UUID/CAPABILITY_ID grant (repeatable; default discovery only)")
	cmd.Flags().StringSliceVar(&messagingTargets, "allow-message", nil, "exact agent UUID allowed for encrypted ASK and this connector's own replies (repeatable)")
	cmd.Flags().StringVar(&listen, "listen", "", "optional loopback IP:port for streamable HTTP at /mcp; requires PAGNET_MCP_HTTP_TOKEN")
	cmd.Flags().StringVar(&publicURL, "oauth-resource", "", "canonical public HTTPS /mcp URL; enables established-provider OAuth mode")
	cmd.Flags().StringVar(&issuer, "oauth-issuer", "", "exact OAuth authorization issuer URL")
	cmd.Flags().StringVar(&introspection, "oauth-introspection", "", "HTTPS RFC7662 endpoint on issuer origin")
	cmd.Flags().StringVar(&subject, "oauth-subject", "", "exact provider subject allowed to use this dedicated principal")
	return cmd
}
