package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/externalbridge"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type savedBrowserConnector struct {
	Policy     sdk.BrowserBridgePolicy `json:"policy"`
	Server     string                  `json:"server"`
	Activation string                  `json:"activation"`
}

func mcpConnectCmd() *cobra.Command {
	var connector, setup, serverURL, stateDir string
	cmd := &cobra.Command{Use: "connect", Short: "Connect browser agents through Pagnet hosting; keys stay on this device", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := uuid.Parse(connector); err != nil {
			return errors.New("--connector must be a UUID")
		}
		if stateDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			stateDir = filepath.Join(home, ".pagnet")
		}
		dir := filepath.Join(stateDir, "browser-connectors")
		path := filepath.Join(dir, connector+".json")
		var saved savedBrowserConnector
		if setup != "" {
			cfg := sdk.Config{Server: serverURL, Credential: setup, StateDir: stateDir}
			if err := cfg.Validate(); err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(cmd.Context(), "POST", serverURL+"/api/v1/browser-connectors/"+connector+"/setup", bytes.NewReader([]byte("{}")))
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+setup)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Do(req)
			if err != nil {
				return errors.New("connector setup unavailable")
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("connector setup failed (HTTP %d); create a fresh connection if the one-time setup expired", resp.StatusCode)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			if err != nil || json.Unmarshal(data, &saved.Policy) != nil || saved.Policy.ConnectorID != connector {
				return errors.New("invalid connector setup response")
			}
			saved.Server = serverURL
			saved.Activation = setup
			if _, err := externalbridge.New(nil, externalbridge.Config{Network: saved.Policy.NetworkID, Grants: saved.Policy.Grants}); err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			raw, err := json.Marshal(saved)
			if err != nil {
				return err
			}
			tmp, err := os.CreateTemp(dir, ".setup-*")
			if err != nil {
				return err
			}
			defer os.Remove(tmp.Name())
			if err = tmp.Chmod(0600); err == nil {
				_, err = tmp.Write(raw)
			}
			closeErr := tmp.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err = os.Rename(tmp.Name(), path); err != nil {
				return err
			}
		} else {
			raw, err := os.ReadFile(path)
			if err != nil {
				return errors.New("connector has no local setup; use the one-time command from Integrations")
			}
			if json.Unmarshal(raw, &saved) != nil || saved.Policy.ConnectorID != connector {
				return errors.New("invalid local connector configuration")
			}
		}
		cfg := sdk.Config{Server: saved.Server, Credential: saved.Activation, StateDir: stateDir}
		client, err := sdk.Connect(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer client.Close()
		bridge, err := externalbridge.New(client, externalbridge.Config{Network: saved.Policy.NetworkID, Grants: saved.Policy.Grants})
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Browser connector running. Keep this process running; restart with: pagnet mcp connect --connector "+connector)
		delay := time.Second
		for {
			err = client.ServeBrowserBridge(cmd.Context(), saved.Policy, bridge.HandleHosted)
			if cmd.Context().Err() != nil {
				return nil
			}
			if errors.Is(err, sdk.ErrCredentialDead) {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Browser connector reconnecting; gateway requests remain unavailable until the bridge reconnects.")
			timer := time.NewTimer(delay)
			select {
			case <-cmd.Context().Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			if delay < 15*time.Second {
				delay *= 2
			}
		}
	}}
	cmd.Flags().StringVar(&connector, "connector", "", "connector UUID from Integrations (required)")
	cmd.Flags().StringVar(&setup, "setup", "", "one-time setup token (first connection only)")
	cmd.Flags().StringVar(&serverURL, "server", "https://app.pagnet.dev", "Pagnet server URL")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "local private state directory")
	return cmd
}
