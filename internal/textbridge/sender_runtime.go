package textbridge

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

// RunSenderProfile owns one SDK connection and one controller until cancellation
// or transport termination. The caller owns the sender store and profile lock.
// Authorize must prove the pinned installation before handlers or work begin.
func RunSenderProfile(parent context.Context, dir string, p Profile, store *sender.Store, config RuntimeConfig) error {
	if err := p.validateProjectContract(); err != nil {
		return err
	}
	if p.ServiceRole() != "sender" || p.Disabled || config.Authorize == nil {
		return errors.New("enabled managed sender profile and authorization required")
	}
	if enabled, err := store.Enabled(parent); err != nil {
		return err
	} else if !enabled {
		return sender.ErrDisabled
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
		return errors.New("sender service connection failed")
	}
	defer conn.Close()
	monitorDone, monitorExited := make(chan struct{}), make(chan struct{})
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
		return errors.New("sender authenticated identity does not match saved service")
	}
	endpoint, endpointDone, err := ownerEndpointSession(conn, p)
	if err != nil {
		return err
	}
	if err := config.Authorize(ctx, conn); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	adapter, err := selectOwnerProjectAdapter(ctx, conn, p, identity, endpoint, endpointDone)
	if err != nil {
		return err
	}
	var senderConn sender.Connection
	if adapter != nil {
		senderConn = adapter
	} else {
		var ok bool
		senderConn, ok = conn.(sender.Connection)
		if !ok {
			return errors.New("SDK connection does not support sender operations")
		}
	}
	controller := sender.NewController(store, senderConn, p.Service, sender.ControllerConfig{Enabled: config.Enabled, OnError: config.OnError, OnReady: config.OnSenderReady})
	return controller.Run(ctx)
}
