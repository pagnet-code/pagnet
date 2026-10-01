package main

import (
	"bytes"
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

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/jev"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const jevConnectTimeout = 45 * time.Second

type jevProvider interface {
	CheckKey(context.Context) error
	EvaluateValue(context.Context, any) (jev.Result, error)
}

func jevServiceCmd() *cobra.Command {
	return jevServiceCmdWithProvider(func(key, model string) (jevProvider, error) { return jev.New(key, model) })
}

func readJevKey(file string) (string, error) {
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return "", errors.New("cannot read local TypeSafe key file")
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil || !stat.Mode().IsRegular() {
			return "", errors.New("TypeSafe key file must be regular")
		}
		if err := validateJevKeyFileOwner(stat); err != nil {
			return "", err
		}
		if stat.Mode().Perm()&0077 != 0 {
			return "", errors.New("TypeSafe key file must be accessible only to its owner (chmod 600)")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(raw) > 4096 {
			return "", errors.New("invalid TypeSafe key file")
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if key := os.Getenv("TYPESAFE_API_KEY"); key != "" {
		return key, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("set TYPESAFE_API_KEY locally or use --key-file with a private local file")
	}
	fmt.Fprint(os.Stderr, "TypeSafe API key (hidden, kept only in this process): ")
	key, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", errors.New("could not read TypeSafe API key")
	}
	return strings.TrimSpace(string(key)), nil
}
func jevServiceCmdWithProvider(newProvider func(string, string) (jevProvider, error)) *cobra.Command {
	var service, setup, server, stateDir, keyFile, model string
	var daemon bool
	cmd := &cobra.Command{Use: "jev", Short: "Run Jev as an outbound-connected Pagnet service; the TypeSafe key stays local", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if _, err := uuid.Parse(service); err != nil {
			return errors.New("--service must be the service UUID from Pagnet")
		}
		if stateDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			stateDir = filepath.Join(home, ".pagnet")
		}
		path := filepath.Join(stateDir, "services", "jev", service+".json")
		saved := serviceRunnerProfile{Service: service, Server: server, Credential: setup, Model: model, Adapter: "jev"}
		if setup == "" {
			var err error
			saved, err = loadServiceRunnerProfile(path, service)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("server") && server != saved.Server {
				return errors.New("a saved service profile is bound to its original --server; use a separate --state-dir for another server")
			}
		}
		if saved.Adapter != "jev" {
			return errors.New("this service profile is not a Jev runner; use a fresh setup command")
		}
		cfg := sdk.Config{Server: saved.Server, Credential: saved.Credential, StateDir: stateDir}
		if err := cfg.Validate(); err != nil {
			return err
		}
		if cmd.Flags().Changed("model") {
			saved.Model = model
		}
		if setup != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "Checking the service setup credential. CLI account login is not required.")
			if err := verifyJevSetup(cmd.Context(), cfg, service); err != nil {
				return err
			}
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Reading your local TypeSafe API key (use TYPESAFE_API_KEY or --key-file; otherwise enter it at the hidden prompt).")
		key, err := readJevKey(keyFile)
		if err != nil {
			return err
		}
		provider, err := newProvider(key, saved.Model)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Checking the TypeSafe key without running an evaluation.")
		if err := provider.CheckKey(cmd.Context()); err != nil {
			return err
		}
		if setup != "" || cmd.Flags().Changed("model") {
			if err := saveServiceRunnerProfile(path, saved); err != nil {
				return err
			}
		}
		if daemon {
			return launchServiceDetached(cmd.ErrOrStderr(), saved, stateDir, []string{"TYPESAFE_API_KEY=" + key})
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Connecting the Jev endpoint to Pagnet (up to 45 seconds).")
		startupCtx, startupCancel := context.WithTimeout(cmd.Context(), jevConnectTimeout)
		client, err := sdk.Connect(startupCtx, cfg)
		startupCancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return errors.New("Jev endpoint connection timed out; check the server and network connection, then retry. If the setup credential expired, generate a new credential from this service's page")
			}
			return fmt.Errorf("Jev endpoint connection failed: %w", err)
		}
		defer client.Close()
		identity, err := client.WhoAmI(cmd.Context())
		if err != nil {
			return err
		}
		if identity.PrincipalID != service || identity.Kind != "service" {
			return errors.New("setup credential does not belong to the requested service")
		}
		svc := client.Service(identity.Name)
		if err := svc.Handle(jev.CapabilityID, func(ctx context.Context, inv *sdk.Invocation) (any, error) {
			return provider.EvaluateValue(ctx, inv.Input)
		}); err != nil {
			return err
		}
		if err := svc.Capability(jev.Capability()); err != nil {
			return err
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Jev endpoint connected. Advertising typesafe.evaluate; encrypted networks become ready through each network's original authority host, which must be online. This is independent of the CLI account on this machine. State and questions are sent to TypeSafe; the API key stays on this host.")
		readinessCtx, readinessCancel := context.WithCancel(cmd.Context())
		readinessDone := make(chan struct{})
		defer func() { readinessCancel(); <-readinessDone }()
		fmt.Fprintln(cmd.ErrOrStderr(), "Keep this process running. Restart with: pagnet service jev --service "+service+" (supply your local API key again).")
		go func() { defer close(readinessDone); reportJevReadiness(readinessCtx, client, cmd.ErrOrStderr()) }()
		err = svc.Serve(cmd.Context())
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}}
	cmd.Flags().BoolVar(&daemon, "daemon", false, "run Jev in the background; private log and PID under the service state directory")
	cmd.Flags().StringVar(&service, "service", "", "service UUID from Services")
	cmd.Flags().StringVar(&setup, "setup", "", "Pagnet service activation or endpoint credential (first setup only)")
	cmd.Flags().StringVar(&server, "server", "https://app.pagnet.dev", "Pagnet server URL")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "private Pagnet state directory")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "private local file containing the TypeSafe API key; never uploaded")
	cmd.Flags().StringVar(&model, "model", "jev-latest", "Jev model alias or version (fixed for this service profile)")
	return cmd
}

func verifyJevSetup(ctx context.Context, cfg sdk.Config, service string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(cfg.Server, "/")+"/api/v1/services/"+service+"/jev/setup", nil)
	if err != nil {
		return errors.New("cannot verify service setup")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Credential)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("service setup verification unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	var proof struct {
		Service     string `json:"serviceId"`
		Integration string `json:"integration"`
	}
	if resp.StatusCode != 200 || err != nil || len(raw) > 4096 || json.NewDecoder(bytes.NewReader(raw)).Decode(&proof) != nil || proof.Service != service || proof.Integration != "typesafe-jev" {
		return errors.New("service setup rejected: the credential may be expired, consumed, revoked, or belong to another service; generate a new credential from this service page (CLI account login is not required)")
	}
	return nil
}

// Report transitions only; membership access and enrollment remain authoritative
// server decisions. A connected endpoint is not necessarily encryption-ready.
func reportJevReadiness(ctx context.Context, client *sdk.Client, out io.Writer) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	last := ""
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		nets, err := client.Networks(probeCtx)
		cancel()
		if err == nil {
			ready := 0
			for _, n := range nets {
				if n.CryptoReady {
					ready++
				}
			}
			state := fmt.Sprintf("Network encryption readiness: %d/%d networks ready.", ready, len(nets))
			if ready < len(nets) {
				state += " Waiting for the network authority host to finish enrollment."
			}
			if len(nets) == 0 {
				state += " Grant this service access to a network before invoking it."
			}
			if state != last {
				fmt.Fprintln(out, state)
				last = state
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-client.Done():
			return
		case <-ticker.C:
		}
	}
}
