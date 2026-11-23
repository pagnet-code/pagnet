package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/pagnet-code/pagnet/internal/externalbridge"
	"github.com/pagnet-code/pagnet/internal/externalbridge/inbox"
	"github.com/pagnet-code/pagnet/internal/externalbridge/qwenrelay"
	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

func mcpExternalCmd() *cobra.Command {
	var network, listen, publicURL, issuer, introspection, subject, profile, stateDir string
	var grants, messagingTargets, events []string
	var runtimeBinding string
	var receiveAsks bool
	var allowedSenders []string
	cmd := &cobra.Command{Use: "external", Short: "Independent principal MCP bridge for external agents and plugins", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if runtimeBinding != "" && (profile == "" || !receiveAsks || listen != "") {
			return errors.New("--runtime-binding requires a private --profile, --receive-asks and stdio")
		}
		var qwen *runtimeconnect.Qwen
		if runtimeBinding != "" {
			var err error
			qwen, err = externalRuntimeBinding(machineStateDir(stateDir), profile, runtimeBinding)
			if err != nil {
				return err
			}
		}
		sdkConfig := sdk.ConfigFromEnv()
		sdkConfig.DisableMessageReceive = true
		if receiveAsks && profile == "" {
			return errors.New("--receive-asks requires a private --profile")
		}
		var expectedPrincipal string
		if profile != "" {
			for _, flag := range []string{"network", "allow-invoke", "allow-message", "allow-events", "listen", "oauth-resource", "oauth-issuer", "oauth-introspection", "oauth-subject"} {
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
			allowedSenders = p.AllowedSenders
			if receiveAsks && len(allowedSenders) == 0 {
				return errors.New("--receive-asks requires profile allowedSenders; add senders with --allow-from")
			}
			network, grants, messagingTargets, events, sdkConfig, expectedPrincipal = p.Network, p.Grants, p.MessagingTargets, p.Events, saved, p.Principal
		}
		cfg := externalbridge.Config{Network: network, Grants: grants, MessagingTargets: messagingTargets, Events: events}
		// Validate all local policy before consuming a one-time activation.
		if _, err := externalbridge.New(nil, cfg); err != nil {
			return err
		}
		token := os.Getenv("PAGNET_MCP_HTTP_TOKEN")
		oauth := externalbridge.OAuthConfig{ResourceURL: publicURL, Issuer: issuer, IntrospectionURL: introspection, Subject: subject, ClientID: os.Getenv("PAGNET_MCP_OAUTH_CLIENT_ID"), ClientSecret: os.Getenv("PAGNET_MCP_OAUTH_CLIENT_SECRET"), AllowInvoke: len(grants) > 0 || len(messagingTargets) > 0 || len(events) > 0}
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
		ctx, stop := context.WithCancel(cmd.Context())
		defer stop()
		var inboxStore *inbox.Store
		var receiver *externalbridge.AskInbox
		connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if !strings.HasPrefix(sdkConfig.Credential, "pgn_act_v1_") && !strings.HasPrefix(sdkConfig.Credential, "pgn_epd_v1_") {
			cancel()
			return errors.New("external MCP: PAGNET_CREDENTIAL must be an activation or endpoint principal credential")
		}
		if receiveAsks {
			store, err := inbox.Open(filepath.Join(sdkConfig.StateDir, "inbox"), inbox.Limits{})
			if err != nil {
				cancel()
				return err
			}
			defer store.Close()
			receiver, err = externalbridge.NewAskInbox(store, network, expectedPrincipal, allowedSenders)
			if err != nil {
				cancel()
				return err
			}
			inboxStore = store
			cfg.Inbox = receiver
			sdkConfig.DisableMessageReceive = false
			sdkConfig.MessageHandler = receiver.Receive
			sdkConfig.RetryMessageHandlerErrors = true
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
		if qwen != nil {
			relay, err := qwenrelay.New(receiver, inboxStore, qwen, client)
			if err != nil {
				return err
			}
			relay.SetStatusObserver(func(id string, status qwenrelay.Status) {
				if status.Error != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "Qwen relay ASK %s: %s\n", id, status.State)
				}
			})
			done := make(chan struct{})
			defer func() { stop(); <-done }()
			go func() {
				defer close(done)
				if err := relay.Run(ctx); err != nil && ctx.Err() == nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "Qwen relay stopped with an error; inspect the private inbox before restarting")
				}
			}()
		}
		bridge, err := externalbridge.New(client, cfg)
		if err != nil {
			return err
		}
		if len(events) > 0 {
			if err := bridge.StartEvents(ctx, externalbridge.AgentEvents(client, network)); err != nil {
				return err
			}
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
	cmd.Flags().StringVar(&runtimeBinding, "runtime-binding", "", "private auto-answer runtime connection name (requires profile, receive-asks and stdio)")
	cmd.Flags().BoolVar(&receiveAsks, "receive-asks", false, "durably receive ASKs from this private profile’s allowed senders")
	cmd.Flags().StringVar(&profile, "profile", "", "private local external profile name (stdio only)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "private profile state directory")
	cmd.Flags().StringVar(&network, "network", "", "fixed network UUID (required)")
	cmd.Flags().StringSliceVar(&grants, "allow-invoke", nil, "exact PRINCIPAL_UUID/CAPABILITY_ID grant (repeatable; default discovery only)")
	cmd.Flags().StringSliceVar(&messagingTargets, "allow-message", nil, "exact agent UUID allowed for encrypted ASK and this connector's own replies (repeatable)")
	cmd.Flags().StringSliceVar(&events, "allow-events", nil, "event pattern this connector may receive, exact type or single-level wildcard like task.* (repeatable; default no events)")
	cmd.Flags().StringVar(&listen, "listen", "", "optional loopback IP:port for streamable HTTP at /mcp; requires PAGNET_MCP_HTTP_TOKEN")
	cmd.Flags().StringVar(&publicURL, "oauth-resource", "", "canonical public HTTPS /mcp URL; enables established-provider OAuth mode")
	cmd.Flags().StringVar(&issuer, "oauth-issuer", "", "exact OAuth authorization issuer URL")
	cmd.Flags().StringVar(&introspection, "oauth-introspection", "", "HTTPS RFC7662 endpoint on issuer origin")
	cmd.Flags().StringVar(&subject, "oauth-subject", "", "exact provider subject allowed to use this dedicated principal")
	return cmd
}

// externalRuntimeBinding accepts only the saved opt-in connection for this exact
// profile. Runtime endpoint and credentials cannot be supplied through MCP args.
func externalRuntimeBinding(state, profile, name string) (*runtimeconnect.Qwen, error) {
	if !strings.HasPrefix(name, "pagnet_external_") || strings.ContainsAny(name, "/\\") || len(name) != 48 {
		return nil, errors.New("invalid Pagnet runtime connection name")
	}
	var binding runtimeconnect.Binding
	if err := externalprofile.LoadBinding(filepath.Join(state, "runtime-connections", name+".json"), &binding); err != nil {
		return nil, err
	}
	if binding.Name != name || binding.Profile != profile || !binding.AutoAnswer {
		return nil, errors.New("runtime connection is not an auto-answer binding for this profile")
	}
	if !filepath.IsAbs(binding.TokenFile) {
		return nil, errors.New("runtime binding requires an absolute private token file")
	}
	token, err := externalprofile.ReadSecret(binding.TokenFile)
	if err != nil {
		return nil, err
	}
	return runtimeconnect.NewQwen(binding, token)
}
