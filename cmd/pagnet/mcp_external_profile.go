package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func externalProfileConfig(state, name string) (externalprofile.Profile, sdk.Config, error) {
	path, err := externalprofile.Path(state, name)
	if err != nil {
		return externalprofile.Profile{}, sdk.Config{}, err
	}
	p, err := externalprofile.Load(path)
	if err != nil {
		return p, sdk.Config{}, err
	}
	principalState := filepath.Join(state, "external-profiles", name+".state")
	cfg := sdk.Config{Server: p.Server, Credential: p.Credential, StateDir: principalState}
	// Activation is exchanged only once; reconnect uses the same principal's
	// authenticated durable keyring, never another profile's credential.
	if stored, err := sdk.StoredCredential(principalState, p.Principal); err == nil && stored != "" {
		cfg.Credential = stored
	}
	return p, cfg, nil
}
func verifyExternalProfile(ctx context.Context, p externalprofile.Profile, cfg sdk.Config) error {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(cfg.Server, "/")+"/api/v1/auth/principal/me", nil)
	if err != nil {
		return errors.New("external principal verification unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Credential)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("external principal verification unavailable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 || resp.StatusCode != 200 {
		return errors.New("external profile credential expired, revoked or unavailable")
	}
	var identity struct {
		Principal   struct{ ID string }
		Memberships []struct{ NetworkID, State string }
	}
	if json.Unmarshal(data, &identity) != nil || identity.Principal.ID != p.Principal {
		return errors.New("external profile credential belongs to another principal")
	}
	for _, m := range identity.Memberships {
		if m.NetworkID == p.Network && m.State == "active" {
			return nil
		}
	}
	return errors.New("external profile requires active membership in its exact network")
}
func mcpExternalProfileCmd() *cobra.Command {
	var state, principal, network, server string
	var grants, targets []string
	cmd := &cobra.Command{Use: "external-profile", Short: "Store private local connection settings for independent runtime MCP"}
	cmd.PersistentFlags().StringVar(&state, "state-dir", "", "private Pagnet state directory")
	add := &cobra.Command{Use: "add NAME", Args: cobra.ExactArgs(1), Short: "Save a profile; enter its credential at a hidden local prompt", RunE: func(cmd *cobra.Command, args []string) error {
		path, err := externalprofile.Path(machineStateDir(state), args[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Enter the principal activation or endpoint credential (hidden; saved locally only):")
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("credential entry requires an interactive terminal; alternatively create the documented private profile file")
		}
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return errors.New("cannot read credential")
		}
		p := externalprofile.Profile{Version: 1, Principal: principal, Network: network, Server: server, Credential: strings.TrimSpace(string(value)), Grants: grants, MessagingTargets: targets}
		if err := p.Validate(); err != nil {
			return err
		}
		if err := verifyExternalProfile(cmd.Context(), p, sdk.Config{Server: p.Server, Credential: p.Credential}); err != nil {
			return err
		}
		if err := externalprofile.SaveNew(path, p); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved private profile %s. No runtime or global configuration was changed.\n", args[0])
		return nil
	}}
	add.Flags().StringVar(&principal, "principal", "", "expected principal UUID")
	add.Flags().StringVar(&network, "network", "", "fixed network UUID")
	add.Flags().StringVar(&server, "server", "https://app.pagnet.dev", "Pagnet server HTTPS URL")
	add.Flags().StringSliceVar(&grants, "allow-invoke", nil, "exact principal/capability grant; discovery only by default")
	add.Flags().StringSliceVar(&targets, "allow-message", nil, "exact agent UUID allowed for ASK and own replies")
	_ = add.MarkFlagRequired("principal")
	_ = add.MarkFlagRequired("network")
	cmd.AddCommand(add)
	return cmd
}
