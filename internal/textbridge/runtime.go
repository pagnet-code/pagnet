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
// same contract as Config. Nil factories use the standard provider and SDK.
type RuntimeConfig struct {
	NewProvider func(provider.Config) (Provider, error)
	Connect     func(context.Context, sdk.Config) (RuntimeConnection, error)
	// Authorize runs on the authenticated endpoint before handlers or dispatch.
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
	client, err := newProvider(providerConfig)
	if err != nil {
		return err
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
	if err != nil || identity == nil || identity.Kind != "service" || identity.PrincipalID != p.Service {
		return errors.New("text bridge authenticated identity does not match saved service")
	}
	if config.Authorize != nil {
		if err := config.Authorize(ctx, conn); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-conn.Done():
		return errors.New("text bridge service connection terminated")
	default:
	}
	enabled := func(project string) bool {
		select {
		case <-conn.Done():
			return false
		default:
		}
		return ctx.Err() == nil && config.Enabled != nil && config.Enabled(project)
	}
	b := New(store, conn, client, Config{ProviderConfigFingerprint: p.Fingerprint, Enabled: enabled, OnError: config.OnError})
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
