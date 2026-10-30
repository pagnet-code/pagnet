package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

type textBridgeConnection = textbridge.RuntimeConnection

type textBridgeDependencies struct {
	owner                    func() (*cliCtx, error)
	provider                 func(provider.Config) (textbridge.Provider, error)
	connect                  func(context.Context, sdk.Config) (textBridgeConnection, error)
	registrationContext      func() (*cliCtx, error)
	registrationAuthenticate func(*cliCtx) error

	senderConnect func(context.Context, sdk.Config) (textBridgeSenderConnection, error)
}

func textBridgeCmd() *cobra.Command {
	return textBridgeCmdWithDependencies(textBridgeDependencies{
		owner:    func() (*cliCtx, error) { return newCLI("") },
		provider: func(c provider.Config) (textbridge.Provider, error) { return provider.New(c) },
		connect:  func(ctx context.Context, c sdk.Config) (textBridgeConnection, error) { return sdk.Connect(ctx, c) },
	})
}

func textBridgeCmdWithDependencies(deps textBridgeDependencies) *cobra.Command {
	cmd := &cobra.Command{Use: "text-bridge", Short: "Run a local, bounded text-only provider service", Args: cobra.NoArgs}
	var stateDir string
	cmd.PersistentFlags().StringVar(&stateDir, "state-dir", "", "private local state directory (default ~/.pagnet)")
	cmd.AddCommand(textBridgeRegisterCmd(&stateDir, deps))
	cmd.AddCommand(textBridgeSenderCmd(&stateDir, textBridgeSenderDependencies{owner: deps.owner, connect: deps.senderConnect}))
	var name, origin, model, keyFile, projectContract string
	var calls int64
	enable := &cobra.Command{Use: "enable", Args: cobra.NoArgs, Short: "Create a service and save its private local responder profile", RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
		if err := textBridgeValidateProjectContract(projectContract); err != nil {
			return err
		}
		if strings.TrimSpace(name) == "" || calls <= 0 || keyFile == "" {
			return errors.New("--name, --provider-origin, --model, --key-file and positive --calls-per-day are required")
		}
		keyPath, err := filepath.Abs(keyFile)
		if err != nil {
			return errors.New("invalid local key file path")
		}
		key, err := textbridge.ReadProviderKey(keyPath)
		if err != nil {
			return err
		}
		config := provider.Config{BaseURL: origin, Model: model, APIKey: key}
		if _, err := deps.provider(config); err != nil {
			return err
		}
		base, err := textbridge.ProfileBase(stateDir)
		if err != nil {
			return err
		}
		// Check durable local writes before creating a remote service.
		probe, err := os.CreateTemp(base, ".preflight-*")
		if err != nil {
			return errors.New("text bridge state directory is not writable")
		}
		probeErr := probe.Sync()
		closeErr := probe.Close()
		removeErr := os.Remove(probe.Name())
		if probeErr != nil || closeErr != nil || removeErr != nil {
			return errors.New("text bridge state directory cannot persist local setup")
		}
		owner, err := deps.owner()
		if err != nil {
			return err
		}
		created, err := textBridgeCreateService(cmd.Context(), owner, name)
		if err != nil {
			return err
		}
		defer func() {
			if retErr != nil {
				retErr = fmt.Errorf("service %s was created but local setup failed; inspect this service in Services before retrying: %w", created.ID, retErr)
			}
		}()
		p := textbridge.Profile{Service: created.ID, Server: owner.base, Credential: created.Credential, ProviderOrigin: origin, Model: model, KeyFile: keyPath, Fingerprint: textbridge.ProviderFingerprint(config), Limits: ledger.Limits{CallsPerDay: calls, MaxConcurrent: 1}}
		if cmd.Flags().Changed("project-contract") {
			p.ProjectContract = projectContract
		}
		if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: p.Service}).Validate(); err != nil {
			return errors.New("created service has invalid connection configuration; inspect Services")
		}
		dir := filepath.Join(base, p.Service)
		if err := textbridge.PrivateDir(dir); err != nil {
			return err
		}
		unlock, err := textbridge.LockProfile(dir)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("service profile already exists or cannot be inspected")
		}
		store, err := ledger.Open(filepath.Join(dir, "ledger"), p.LedgerBinding(), p.Limits)
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		if err := textbridge.SaveProfile(dir, p); err != nil {
			return errors.New("service created but local setup could not be saved; inspect Services before creating another service")
		}
		fmt.Fprintln(cmd.OutOrStdout(), p.Service)
		return nil
	}}
	enable.Flags().StringVar(&projectContract, "project-contract", textbridge.SharingProjectContract, "project contract: sdk_project_v2 or owner_text_project_v1")
	enable.Flags().StringVar(&name, "name", "", "service name")
	enable.Flags().StringVar(&origin, "provider-origin", "", "owner-selected provider origin")
	enable.Flags().StringVar(&model, "model", "", "fixed provider model")
	enable.Flags().StringVar(&keyFile, "key-file", "", "owner-only local provider key file")
	enable.Flags().Int64Var(&calls, "calls-per-day", 0, "maximum provider calls per UTC day")
	cmd.AddCommand(enable)
	for _, operation := range []string{"run", "status", "disable", "resolve"} {
		op := operation
		var service, project, ask string
		var abandon, accept bool
		sub := &cobra.Command{Use: op, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if !textBridgeUUID(service) {
				return errors.New("--service must be a service UUID")
			}
			if op == "resolve" && (!textBridgeUUID(project) || !textBridgeUUID(ask) || !abandon || !accept) {
				return errors.New("resolve requires --project UUID --ask UUID --abandon --accept-possible-charge")
			}
			if op == "status" {
				status, err := textbridge.ReadProfileStatus(cmd.Context(), stateDir, service)
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
			}
			dir, err := textbridge.ProfileDirectory(stateDir, service)
			if err != nil {
				return err
			}
			unlock, err := textbridge.LockProfile(dir)
			if err != nil {
				return err
			}
			defer unlock()
			p, err := textbridge.LoadProfile(dir, service)
			if err != nil {
				return err
			}
			store, err := textbridge.OpenProfileLedger(dir, p)
			if err != nil {
				return err
			}
			defer store.Close()
			budget, err := store.BudgetSnapshot(cmd.Context())
			if err != nil {
				return err
			}
			switch op {
			case "disable":
				if err := store.SetEnabled(cmd.Context(), false); err != nil {
					return err
				}
				p.Disabled = true
				return textbridge.SaveProfile(dir, p)
			case "resolve":
				if !p.Disabled || budget.Enabled {
					return errors.New("disable this service before resolving an unknown provider claim")
				}
				job, err := store.Get(cmd.Context(), project, ask)
				if err != nil {
					return err
				}
				_, err = store.AbandonProviderClaim(cmd.Context(), project, ask, job.Revision)
				return err
			case "run":
				if p.Registration != nil && p.Registration.Pending {
					return fmt.Errorf("text bridge registration is unconfirmed; retry pagnet text-bridge register --service %s before running", p.Service)
				}
				if p.Disabled || !budget.Enabled || (p.Registration != nil && p.Registration.DesiredState == "disabled") {
					return errors.New("text bridge is disabled; create a new service to enable new work")
				}
				return textBridgeRun(cmd.Context(), dir, p, store, deps, cmd.ErrOrStderr())
			}
			return nil
		}}
		sub.Flags().StringVar(&service, "service", "", "saved service UUID")
		if op == "resolve" {
			sub.Flags().StringVar(&project, "project", "", "sharing project UUID")
			sub.Flags().StringVar(&ask, "ask", "", "ASK UUID")
			sub.Flags().BoolVar(&abandon, "abandon", false, "abandon an unknown provider result without retrying")
			sub.Flags().BoolVar(&accept, "accept-possible-charge", false, "acknowledge the call may have been charged; daily usage is retained")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}

func textBridgeUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s && id != uuid.Nil
}

func textBridgeRun(parent context.Context, dir string, p textbridge.Profile, store *ledger.Store, deps textBridgeDependencies, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return textbridge.RunProfile(ctx, dir, p, store, textbridge.RuntimeConfig{
		NewProvider: deps.provider,
		Connect:     deps.connect,
		Enabled:     func(string) bool { return true },
		OnError:     func(err error) { textBridgeReportError(stderr, err) },
	})
}

func textBridgeReportError(stderr io.Writer, err error) {
	message := "text bridge background operation failed; inspect status for unresolved claims"
	if errors.Is(err, ledger.ErrLimit) {
		message = "text bridge provider budget exhausted; inspect status for usage and unresolved claims"
	}
	if errors.Is(err, ledger.ErrDisabled) {
		message = "text bridge provider dispatch is disabled"
	}
	fmt.Fprintln(stderr, message)
}

func textBridgeValidateProjectContract(contract string) error {
	if contract != textbridge.SharingProjectContract && contract != textbridge.OwnerTextProjectContract {
		return errors.New("--project-contract must be sdk_project_v2 or owner_text_project_v1")
	}
	return nil
}
