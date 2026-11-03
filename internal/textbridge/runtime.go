package textbridge

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

// RuntimeConnection is the service endpoint owned by one in-process runtime.
type RuntimeConnection interface {
	Transport
	WhoAmI(context.Context) (*sdk.Identity, error)
	OnSharingProjectMessage(func(context.Context, sdk.SharingProjectMessage) error)
	OnSharingProjectReady(func(string))
	Done() <-chan struct{}
	Err() error
	Close() error
}

// RuntimeConfig supplies current owner policy and optional boundary factories.
// A nil Enabled predicate fences all dispatch. Enabled and OnError follow the
// same contract as Config. Enabled must not acquire the profile policy lock;
// selected frozen summaries consult saved policy separately for each dispatch.
// Nil factories use the standard provider and SDK.
type RuntimeConfig struct {
	NewProvider func(provider.Config) (Provider, error)
	// NewSnapshotProvider is used only for an explicitly selected frozen summary.
	NewSnapshotProvider func(provider.Config, string) (Provider, error)
	Connect             func(context.Context, sdk.Config) (RuntimeConnection, error)
	// Authorize runs on the authenticated endpoint before handlers or dispatch.
	// For selected frozen summaries it runs under policy.lock and must not acquire it.
	Authorize func(context.Context, RuntimeConnection) error
	Enabled   func(string) bool
	OnError   func(error)
	// OnSenderReady publishes a proved sender and returns cleanup joining its callers.
	OnSenderReady func(*sender.Controller) func()
}

// RunProfile runs a local responder until cancellation, connection termination,
// or worker failure. The caller owns the profile lock and ledger, and must check
// saved disabled/registration state before starting. The runtime owns and closes
// its SDK connection and joins its worker before returning. It does not install
// process signal handlers or close the caller's ledger.
func RunProfile(parent context.Context, dir string, p Profile, store Ledger, config RuntimeConfig) error {
	if err := p.validateProjectContract(); err != nil {
		return err
	}
	if p.ProjectContract == OwnerTextProjectContract && (p.ServiceRole() != "responder" || config.Authorize == nil) {
		return errors.New("owner responder requires installation authorization")
	}
	var err error
	var client Provider
	var plan *FrozenSummaryPlan
	fingerprint := p.Fingerprint
	if p.FrozenSummaryApprovalID != "" {
		current, err := LoadProfile(dir, p.Service)
		if err != nil {
			return err
		}
		if current.FrozenSummaryApprovalID != p.FrozenSummaryApprovalID {
			return errors.New("frozen summary selection changed")
		}
		plan, err = ResolveFrozenSummary(dir, p.FrozenSummaryApprovalID, current, time.Now())
		if err != nil {
			return err
		}
		p = current
		fingerprint = plan.Fingerprint()
		newSnapshot := config.NewSnapshotProvider
		if newSnapshot == nil {
			newSnapshot = func(c provider.Config, instructions string) (Provider, error) {
				return provider.NewSnapshot(c, instructions)
			}
		}
		client, err = newSnapshot(plan.config, plan.approval.Instructions)
		if err != nil {
			return err
		}
	} else {
		key, err := ReadProviderKey(p.KeyFile)
		if err != nil {
			return err
		}
		providerConfig := provider.Config{BaseURL: p.ProviderOrigin, Model: p.Model, APIKey: key}
		if ProviderFingerprint(providerConfig) != p.Fingerprint {
			return errors.New("provider configuration changed; create a new service for new configuration")
		}
		newProvider := config.NewProvider
		if newProvider == nil {
			newProvider = func(c provider.Config) (Provider, error) { return provider.New(c) }
		}
		client, err = newProvider(providerConfig)
		if err != nil {
			return err
		}
	}
	// Call only while holding policy.lock. A new plan is resolved each time so
	// expiry and provider key changes remain visible even while that lock is held.
	validateSelection := func() (*FrozenSummaryPlan, error) {
		current, err := LoadProfile(dir, p.Service)
		if err != nil {
			return nil, err
		}
		if current.FrozenSummaryApprovalID != p.FrozenSummaryApprovalID {
			return nil, errors.New("frozen summary selection changed")
		}
		fresh, err := ResolveFrozenSummary(dir, p.FrozenSummaryApprovalID, current, time.Now())
		if err != nil {
			return nil, err
		}
		if fresh.Fingerprint() != fingerprint {
			return nil, errors.New("frozen summary configuration changed")
		}
		return fresh, nil
	}
	startupPolicy := func(ctx context.Context, effect func() error) error {
		if plan != nil {
			unlock, err := LockProfilePolicy(ctx, dir)
			if err != nil {
				return err
			}
			defer unlock()
			if _, err := validateSelection(); err != nil {
				return err
			}
		}
		return effect()
	}
	if err := PrivateDir(filepath.Join(dir, "sdk")); err != nil {
		return err
	}
	connect := config.Connect
	if connect == nil {
		connect = func(ctx context.Context, c sdk.Config) (RuntimeConnection, error) { return sdk.Connect(ctx, c) }
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	startup, done := context.WithTimeout(ctx, 45*time.Second)
	conn, err := connect(startup, sdk.Config{Server: p.Server, Credential: p.Credential, StateDir: filepath.Join(dir, "sdk"), ExpectedPrincipalID: p.Service})
	done()
	if err != nil {
		return errors.New("text bridge service connection failed")
	}
	defer conn.Close()
	monitorDone := make(chan struct{})
	monitorExited := make(chan struct{})
	defer func() { close(monitorDone); <-monitorExited }()
	go func() {
		defer close(monitorExited)
		select {
		case <-conn.Done():
			cancel()
		case <-monitorDone:
		}
	}()
	identity, err := conn.WhoAmI(ctx)
	if err != nil || !ownerIdentityMatches(p, identity) {
		return errors.New("text bridge authenticated identity does not match saved service")
	}
	endpoint, endpointDone, err := ownerEndpointSession(conn, p)
	if err != nil {
		return err
	}
	if err := startupPolicy(ctx, func() error {
		if config.Authorize != nil {
			return config.Authorize(ctx, conn)
		}
		return nil
	}); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-conn.Done():
		return errors.New("text bridge service connection terminated")
	default:
	}
	adapter, err := selectOwnerProjectAdapter(ctx, conn, p, identity, endpoint, endpointDone)
	if err != nil {
		return err
	}
	var projectTransport Transport = conn
	var callbacks interface {
		OnSharingProjectMessage(func(context.Context, sdk.SharingProjectMessage) error)
		OnSharingProjectReady(func(string))
	} = conn
	projectDone := conn.Done()
	if adapter != nil {
		projectTransport = adapter
		callbacks = adapter
		projectDone = adapter.Done()
	}
	enabled := func(project string) bool {
		select {
		case <-projectDone:
			return false
		default:
		}
		return ctx.Err() == nil && config.Enabled != nil && config.Enabled(project) && (adapter == nil || adapter.Ready(project)) && (plan == nil || plan.AllowsProject(project))
	}
	var gate DispatchGate
	if plan != nil {
		gate = func(ctx context.Context, _ DispatchAction, scope DispatchScope, dispatch func(func() error) error) error {
			unlock, err := LockProfilePolicy(ctx, dir)
			if err != nil {
				return err
			}
			defer unlock()
			revalidate := func() error {
				fresh, err := validateSelection()
				if err != nil {
					return err
				}
				if !fresh.AllowsProject(scope.ProjectID) || fresh.Fingerprint() != scope.QueuedFingerprint {
					return errors.New("frozen summary dispatch scope changed")
				}
				return nil
			}
			if err := revalidate(); err != nil {
				return err
			}
			return dispatch(revalidate)
		}
	}
	b := New(store, projectTransport, client, Config{ProviderConfigFingerprint: fingerprint, DispatchGate: gate, Enabled: enabled, OnError: config.OnError, DeferMessageWake: adapter != nil})
	if err := startupPolicy(ctx, func() error {
		callbacks.OnSharingProjectMessage(b.HandleMessage)
		callbacks.OnSharingProjectReady(func(string) { b.Wake() })
		return nil
	}); err != nil {
		return err
	}
	if adapter != nil {
		if err := adapter.EnrollProjects(ctx); err != nil {
			return err
		}
	}
	worker := make(chan error, 1)
	go func() { worker <- b.Run(ctx) }()
	select {
	case err = <-worker:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-projectDone:
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
