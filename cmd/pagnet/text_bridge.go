package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/spf13/cobra"
)

// Profiles bind a single service to immutable provider policy. There is no
// re-enable operation: disabled profiles cannot revive previously queued work.
type textBridgeProfile struct {
	Service, Server, Credential                 string
	ProviderOrigin, Model, KeyFile, Fingerprint string
	Limits                                      ledger.Limits
	Disabled                                    bool
}

type textBridgeConnection interface {
	textbridge.Transport
	WhoAmI(context.Context) (*sdk.Identity, error)
	OnSharingProjectMessage(func(context.Context, sdk.SharingProjectMessage) error)
	OnSharingProjectReady(func(string))
	Done() <-chan struct{}
	Err() error
	Close() error
}

type textBridgeDependencies struct {
	owner    func() (*cliCtx, error)
	provider func(provider.Config) (textbridge.Provider, error)
	connect  func(context.Context, sdk.Config) (textBridgeConnection, error)
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
	var name, origin, model, keyFile string
	var calls int64
	enable := &cobra.Command{Use: "enable", Args: cobra.NoArgs, Short: "Create a service and save its private local responder profile", RunE: func(cmd *cobra.Command, _ []string) (retErr error) {
		if strings.TrimSpace(name) == "" || calls <= 0 || keyFile == "" {
			return errors.New("--name, --provider-origin, --model, --key-file and positive --calls-per-day are required")
		}
		keyPath, err := filepath.Abs(keyFile)
		if err != nil {
			return errors.New("invalid local key file path")
		}
		key, err := textBridgeKey(keyPath)
		if err != nil {
			return err
		}
		config := provider.Config{BaseURL: origin, Model: model, APIKey: key}
		if _, err := deps.provider(config); err != nil {
			return err
		}
		base, err := textBridgeBase(stateDir)
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
		var created struct {
			ID         string `json:"id"`
			Credential string `json:"activationCredential"`
		}
		// This creation request is deliberately sent exactly once, without the
		// shared CLI's reauthentication retry or redirects. Never expose its body.
		body, _ := json.Marshal(map[string]any{"name": name})
		req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, strings.TrimRight(owner.base, "/")+"/api/v1/service-recipes", bytes.NewReader(body))
		if err != nil {
			return errors.New("invalid service creation request")
		}
		req.Header.Set("Authorization", "Bearer "+owner.token)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("service creation outcome uncertain; inspect Services before creating another service")
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
		decodeErr := json.Unmarshal(raw, &created)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && textBridgeUUID(created.ID) {
			defer func() {
				if retErr != nil {
					retErr = fmt.Errorf("service %s was created but local setup failed; inspect this service in Services before retrying: %w", created.ID, retErr)
				}
			}()
		}
		if err != nil || len(raw) > 32768 || resp.StatusCode < 200 || resp.StatusCode >= 300 || decodeErr != nil || !textBridgeUUID(created.ID) || created.Credential == "" {
			return errors.New("service creation did not return a usable setup; inspect Services before creating another service")
		}
		p := textBridgeProfile{Service: created.ID, Server: owner.base, Credential: created.Credential, ProviderOrigin: origin, Model: model, KeyFile: keyPath, Fingerprint: textBridgeFingerprint(config), Limits: ledger.Limits{CallsPerDay: calls, MaxConcurrent: 1}}
		if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: p.Service}).Validate(); err != nil {
			return errors.New("created service has invalid connection configuration; inspect Services")
		}
		dir := filepath.Join(base, p.Service)
		if err := textBridgePrivateDir(dir); err != nil {
			return err
		}
		unlock, err := textBridgeLock(dir)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(dir, "profile.json")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("service profile already exists or cannot be inspected")
		}
		store, err := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
		if err != nil {
			return err
		}
		if err := store.Close(); err != nil {
			return err
		}
		if err := textBridgeSaveProfile(dir, p); err != nil {
			return errors.New("service created but local setup could not be saved; inspect Services before creating another service")
		}
		fmt.Fprintln(cmd.OutOrStdout(), p.Service)
		return nil
	}}
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
			base, err := textBridgeBase(stateDir)
			if err != nil {
				return err
			}
			dir := filepath.Join(base, service)
			if err := textBridgePrivateDir(dir); err != nil {
				return err
			}
			if op != "status" {
				unlock, err := textBridgeLock(dir)
				if err != nil {
					return err
				}
				defer unlock()
			}
			p, err := textBridgeLoadProfile(dir, service)
			if err != nil {
				return err
			}
			// A saved profile must never initialize a replacement empty ledger.
			if _, err := os.Lstat(filepath.Join(dir, "ledger", "ledger.sqlite")); err != nil {
				return errors.New("saved text bridge ledger is missing or inaccessible")
			}
			store, err := ledger.Open(filepath.Join(dir, "ledger"), ledger.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service}, p.Limits)
			if err != nil {
				return err
			}
			defer store.Close()
			budget, err := store.BudgetSnapshot(cmd.Context())
			if err != nil {
				return err
			}
			switch op {
			case "status":
				return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
					Service  string
					Disabled bool
					Budget   ledger.BudgetStatus
				}{p.Service, p.Disabled, budget})
			case "disable":
				if err := store.SetEnabled(cmd.Context(), false); err != nil {
					return err
				}
				p.Disabled = true
				return textBridgeSaveProfile(dir, p)
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
				if p.Disabled || !budget.Enabled {
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

func textBridgeBase(state string) (string, error) {
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		state = filepath.Join(home, ".pagnet")
	}
	base, err := filepath.Abs(filepath.Join(state, "text-bridge"))
	if err != nil {
		return "", err
	}
	return base, textBridgePrivateDir(base)
}

func textBridgeKey(path string) (string, error) {
	raw, err := textBridgeReadPrivate(path, 8192)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", errors.New("provider key file is empty")
	}
	return key, nil
}

func textBridgeFingerprint(c provider.Config) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func textBridgeLoadProfile(dir, service string) (textBridgeProfile, error) {
	var p textBridgeProfile
	raw, err := textBridgeReadPrivate(filepath.Join(dir, "profile.json"), 32768)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Service != service || !filepath.IsAbs(p.KeyFile) || p.Fingerprint == "" || p.Limits.CallsPerDay <= 0 || p.Limits.MaxConcurrent != 1 {
		return p, errors.New("invalid local text bridge profile")
	}
	if err := (sdk.Config{Server: p.Server, Credential: p.Credential, ExpectedPrincipalID: service}).Validate(); err != nil {
		return p, errors.New("invalid local text bridge connection profile")
	}
	return p, nil
}

func textBridgeSaveProfile(dir string, p textBridgeProfile) error {
	f, err := os.CreateTemp(dir, ".profile-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(p)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "profile.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func textBridgeRun(parent context.Context, dir string, p textBridgeProfile, store *ledger.Store, deps textBridgeDependencies, stderr io.Writer) error {
	key, err := textBridgeKey(p.KeyFile)
	if err != nil {
		return err
	}
	config := provider.Config{BaseURL: p.ProviderOrigin, Model: p.Model, APIKey: key}
	if textBridgeFingerprint(config) != p.Fingerprint {
		return errors.New("provider configuration changed; create a new service for new configuration")
	}
	client, err := deps.provider(config)
	if err != nil {
		return err
	}
	if err := textBridgePrivateDir(filepath.Join(dir, "sdk")); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	startup, done := context.WithTimeout(ctx, 45*time.Second)
	conn, err := deps.connect(startup, sdk.Config{Server: p.Server, Credential: p.Credential, StateDir: filepath.Join(dir, "sdk"), ExpectedPrincipalID: p.Service})
	done()
	if err != nil {
		return errors.New("text bridge service connection failed")
	}
	defer conn.Close()
	identity, err := conn.WhoAmI(ctx)
	if err != nil || identity == nil || identity.Kind != "service" || identity.PrincipalID != p.Service {
		return errors.New("text bridge authenticated identity does not match saved service")
	}
	b := textbridge.New(store, conn, client, textbridge.Config{
		ProviderConfigFingerprint: p.Fingerprint,
		Enabled:                   func(string) bool { return true },
		OnError:                   func(err error) { textBridgeReportError(stderr, err) },
	})
	conn.OnSharingProjectMessage(b.HandleMessage)
	conn.OnSharingProjectReady(func(string) { b.Wake() })
	worker := make(chan error, 1)
	go func() { worker <- b.Run(ctx) }()
	select {
	case err = <-worker:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-conn.Done():
		cancel()
		<-worker
		if conn.Err() != nil {
			return errors.New("text bridge service connection terminated")
		}
		return nil
	case <-ctx.Done():
		cancel()
		<-worker
		return nil
	}
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
