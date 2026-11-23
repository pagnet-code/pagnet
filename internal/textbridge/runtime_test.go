package textbridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

type runtimeConnection struct {
	Transport
	identity    *sdk.Identity
	identityErr error
	terminal    chan struct{}
	terminalErr error
	closed      chan struct{}
	closeOnce   sync.Once
	message     func(context.Context, sdk.SharingProjectMessage) error
	ready       func(string)
	onReady     func()
}

func (c *runtimeConnection) WhoAmI(context.Context) (*sdk.Identity, error) {
	return c.identity, c.identityErr
}
func (c *runtimeConnection) OnSharingProjectMessage(f func(context.Context, sdk.SharingProjectMessage) error) {
	c.message = f
}
func (c *runtimeConnection) OnSharingProjectReady(f func(string)) {
	c.ready = f
	if c.onReady != nil {
		c.onReady()
	}
}
func (c *runtimeConnection) Done() <-chan struct{} { return c.terminal }
func (c *runtimeConnection) Err() error            { return c.terminalErr }
func (c *runtimeConnection) Close() error          { c.closeOnce.Do(func() { close(c.closed) }); return nil }

func runtimeFixture(t *testing.T) (string, Profile, *ledger.Store, *runtimeConnection) {
	t.Helper()
	_, dir, p := savedTestProfile(t)
	store, err := OpenProfileLedger(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	conn := &runtimeConnection{identity: &sdk.Identity{Kind: "service", PrincipalID: p.Service}, terminal: make(chan struct{}), closed: make(chan struct{})}
	return dir, p, store, conn
}
func runtimeConfig(t *testing.T, dir string, p Profile, conn *runtimeConnection, client Provider) RuntimeConfig {
	t.Helper()
	return RuntimeConfig{
		NewProvider: func(config provider.Config) (Provider, error) {
			if config.BaseURL != p.ProviderOrigin || config.Model != p.Model || config.APIKey != "provider-secret" {
				t.Error("runtime did not use saved provider configuration")
			}
			return client, nil
		},
		Connect: func(ctx context.Context, config sdk.Config) (RuntimeConnection, error) {
			if config.Server != p.Server || config.Credential != p.Credential || config.ExpectedPrincipalID != p.Service || config.StateDir != filepath.Join(dir, "sdk") {
				t.Error("runtime did not bind saved endpoint configuration")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 45*time.Second || time.Until(deadline) < 40*time.Second {
				t.Error("runtime lost bounded startup timeout")
			}
			return conn, nil
		},
	}
}

func TestRunProfileCallbacksAndClosedDispatchGate(t *testing.T) {
	for _, gate := range []string{"closed", "closes during status"} {
		t.Run(gate, func(t *testing.T) {
			dir, p, store, conn := runtimeFixture(t)
			client := &fakeProvider{}
			tr := &fakeTransport{status: sdk.SharingProjectStatus{ProjectID: "project", State: "active", EndpointProved: true}}
			conn.Transport = tr
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := runtimeConfig(t, dir, p, conn, client)
			gateClosed := gate == "closed"
			statusCalls := 0
			tr.onStatus = func() { statusCalls++; gateClosed = true }
			gateCalls := 0
			config.Enabled = func(project string) bool {
				gateCalls++
				if project != "project" {
					t.Error("runtime lost project gate scope")
				}
				if gateClosed {
					cancel()
					return false
				}
				return true
			}
			conn.onReady = func() {
				if err := conn.message(context.Background(), sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{ProjectID: "project", ID: "ask", Kind: "ASK", SenderPrincipalID: "sender"}, Plaintext: []byte("question"), Wire: []byte("authenticated wire")}); err != nil {
					t.Error(err)
				}
				conn.ready("project")
			}
			if err := RunProfile(ctx, dir, p, store, config); err != nil {
				t.Fatal(err)
			}
			if conn.message == nil || conn.ready == nil || gateCalls == 0 {
				t.Fatal("runtime did not install callbacks and consult dispatch gate")
			}
			if gate == "closes during status" && statusCalls != 1 {
				t.Fatal("gate was not rechecked after endpoint status")
			}
			if client.calls != 0 {
				t.Fatal("closed gate dispatched provider work")
			}
			budget, err := store.BudgetSnapshot(context.Background())
			if err != nil || budget.Used != 0 || len(budget.Active) != 0 {
				t.Fatal("closed gate consumed provider budget or closed caller ledger")
			}
			job, err := store.Get(context.Background(), "project", "ask")
			if err != nil || job.Phase != ledger.Queued || job.Data.ProviderConfigFingerprint != p.Fingerprint {
				t.Fatal("message callback did not durably retain gated work")
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("runtime did not close owned connection")
			}
		})
	}
}

type joiningRuntimeLedger struct {
	Ledger
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	exited   chan struct{}
}

func (s *joiningRuntimeLedger) List(ctx context.Context, _ ...ledger.Phase) ([]ledger.Job, error) {
	close(s.entered)
	<-ctx.Done()
	close(s.canceled)
	<-s.release
	close(s.exited)
	return nil, ctx.Err()
}
func runtimeAwait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(description)
	}
}
func TestRunProfileCancelsAndJoinsWorker(t *testing.T) {
	for _, shutdown := range []string{"cancellation", "clean connection close", "failed connection close"} {
		t.Run(shutdown, func(t *testing.T) {
			dir, p, _, conn := runtimeFixture(t)
			store := &joiningRuntimeLedger{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if shutdown == "failed connection close" {
				conn.terminalErr = errors.New("private connection error")
			}
			config := runtimeConfig(t, dir, p, conn, &fakeProvider{})
			result := make(chan error, 1)
			go func() { result <- RunProfile(ctx, dir, p, store, config) }()
			runtimeAwait(t, store.entered, "runtime worker never started")
			if shutdown == "cancellation" {
				cancel()
			} else {
				close(conn.terminal)
			}
			runtimeAwait(t, store.canceled, "runtime did not cancel worker")
			select {
			case <-result:
				t.Fatal("runtime returned before its worker exited")
			case <-conn.closed:
				t.Fatal("runtime closed connection before joining worker")
			case <-time.After(20 * time.Millisecond):
			}
			close(store.release)
			select {
			case err := <-result:
				if shutdown == "failed connection close" {
					if err == nil || strings.Contains(err.Error(), "private") {
						t.Fatal("connection failure was not safely reported")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("runtime leaked worker after cancellation")
			}
			runtimeAwait(t, store.exited, "runtime left worker running")
			runtimeAwait(t, conn.closed, "runtime leaked owned connection")
		})
	}
}

func TestRunProfileRejectsWrongServiceIdentity(t *testing.T) {
	for _, kind := range []string{"agent", "different service", "nil identity", "identity error"} {
		t.Run(kind, func(t *testing.T) {
			dir, p, store, conn := runtimeFixture(t)
			switch kind {
			case "agent":
				conn.identity.Kind = "agent"
			case "different service":
				conn.identity.PrincipalID = "other"
			case "nil identity":
				conn.identity = nil
			case "identity error":
				conn.identityErr = errors.New("private identity error")
			}
			err := RunProfile(context.Background(), dir, p, store, runtimeConfig(t, dir, p, conn, &fakeProvider{}))
			if err == nil || strings.Contains(err.Error(), "private") || conn.message != nil || conn.ready != nil {
				t.Fatal("unverified endpoint reached runtime worker callbacks")
			}
			runtimeAwait(t, conn.closed, "wrong-identity endpoint was not closed")
			if _, err := store.BudgetSnapshot(context.Background()); err != nil {
				t.Fatal("runtime closed caller's ledger")
			}
		})
	}
}

func TestRunProfileRejectsChangedProviderKeyBeforeFactories(t *testing.T) {
	dir, p, store, _ := runtimeFixture(t)
	if err := os.WriteFile(p.KeyFile, []byte("changed-private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	config := RuntimeConfig{NewProvider: func(provider.Config) (Provider, error) { t.Fatal("changed key initialized provider"); return nil, nil }, Connect: func(context.Context, sdk.Config) (RuntimeConnection, error) {
		t.Fatal("changed key connected endpoint")
		return nil, nil
	}}
	err := RunProfile(context.Background(), dir, p, store, config)
	if err == nil || !strings.Contains(err.Error(), "configuration changed") || strings.Contains(err.Error(), "changed-private-key") {
		t.Fatal("provider fingerprint mismatch did not fail safely")
	}
}

func TestRunProfileAuthorizationBeforeDispatch(t *testing.T) {
	for _, kind := range []string{"reject", "identity mismatch", "success"} {
		t.Run(kind, func(t *testing.T) {
			dir, p, store, conn := runtimeFixture(t)
			client := &fakeProvider{}
			cfg := runtimeConfig(t, dir, p, conn, client)
			authorized := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg.Authorize = func(ctx context.Context, got RuntimeConnection) error {
				if got != conn || conn.message != nil || conn.ready != nil || client.calls != 0 {
					t.Fatal("dispatch preceded authorization")
				}
				authorized = true
				if kind == "reject" {
					return errors.New("rejected")
				}
				return nil
			}
			if kind == "identity mismatch" {
				conn.identity.PrincipalID = "other"
			}
			conn.onReady = func() {
				if !authorized {
					t.Error("callbacks preceded authorization")
				}
				cancel()
			}
			err := RunProfile(ctx, dir, p, store, cfg)
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("authorization failure accepted")
			}
			if kind == "identity mismatch" && authorized {
				t.Fatal("hook ran for wrong identity")
			}
			if kind != "success" && (conn.message != nil || conn.ready != nil) {
				t.Fatal("callbacks installed after rejection")
			}
			if client.calls != 0 {
				t.Fatal("provider dispatched before authorization")
			}
		})
	}
}

func TestRunProfileJoinsAuthorizationOnCancellation(t *testing.T) {
	for _, cause := range []string{"parent", "endpoint"} {
		t.Run(cause, func(t *testing.T) {
			dir, p, store, conn := runtimeFixture(t)
			cfg := runtimeConfig(t, dir, p, conn, &fakeProvider{})
			entered := make(chan struct{})
			release := make(chan struct{})
			cancelled := make(chan struct{})
			cfg.Authorize = func(ctx context.Context, _ RuntimeConnection) error {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				return ctx.Err()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- RunProfile(ctx, dir, p, store, cfg) }()
			runtimeAwait(t, entered, "authorization start")
			if cause == "parent" {
				cancel()
			} else {
				close(conn.terminal)
			}
			runtimeAwait(t, cancelled, "authorization cancellation")
			select {
			case <-done:
				t.Fatal("runtime returned before joining authorization")
			default:
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatal("cancelled authorization accepted")
			}
			if conn.message != nil || conn.ready != nil {
				t.Fatal("cancelled startup installed callbacks")
			}
		})
	}
}
