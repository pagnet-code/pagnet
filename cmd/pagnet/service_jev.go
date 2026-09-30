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

type savedJevService struct {
	Service    string `json:"service"`
	Server     string `json:"server"`
	Activation string `json:"activation"`
	Model      string `json:"model"`
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
func loadJevProfile(path, service string) (savedJevService, error) {
	var saved savedJevService
	f, err := os.Open(path)
	if err != nil {
		return saved, errors.New("no valid local Jev setup; use the one-time command from Services")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return saved, errors.New("local Jev profile must be a regular file")
	}
	// Unix ownership is meaningful; other platforms use the SDK state directory's
	// account access controls, just as the durable endpoint keyring does.
	if err := validateJevProfileOwner(info); err != nil {
		return saved, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return saved, errors.New("invalid local Jev profile")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Service != service {
		return saved, errors.New("invalid local Jev profile")
	}
	return saved, nil
}

func saveJevProfile(path string, v savedJevService) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".jev-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(v)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func jevServiceCmd() *cobra.Command {
	var service, setup, server, stateDir, keyFile, model string
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
		saved := savedJevService{service, server, setup, model}
		if setup == "" {
			var err error
			saved, err = loadJevProfile(path, service)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("server") && server != saved.Server {
				return errors.New("a saved service profile is bound to its original --server; use a separate --state-dir for another server")
			}
		}
		cfg := sdk.Config{Server: saved.Server, Credential: saved.Activation, StateDir: stateDir}
		if err := cfg.Validate(); err != nil {
			return err
		}
		if cmd.Flags().Changed("model") {
			saved.Model = model
		}
		if setup != "" {
			if err := verifyJevSetup(cmd.Context(), cfg, service); err != nil {
				return err
			}
		}
		key, err := readJevKey(keyFile)
		if err != nil {
			return err
		}
		provider, err := jev.New(key, saved.Model)
		if err != nil {
			return err
		}
		if err := provider.CheckKey(cmd.Context()); err != nil {
			return err
		}
		if setup != "" || cmd.Flags().Changed("model") {
			if err := saveJevProfile(path, saved); err != nil {
				return err
			}
		}
		client, err := sdk.Connect(cmd.Context(), cfg)
		if err != nil {
			return err
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
		fmt.Fprintln(cmd.ErrOrStderr(), "Jev runner started. Endpoint registration and network encryption enrollment continue automatically through your online Pagnet host. Granted callers can invoke typesafe.evaluate once both are ready. State and questions are sent to TypeSafe; the API key stays on this host.")
		fmt.Fprintln(cmd.ErrOrStderr(), "Keep this process running. Restart with: pagnet service jev --service "+service+" (supply your local API key again).")
		err = svc.Serve(cmd.Context())
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}}
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
		return errors.New("setup credential does not belong to the requested Jev service, or has expired")
	}
	return nil
}
