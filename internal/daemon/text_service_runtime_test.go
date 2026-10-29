//go:build unix

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

type textRuntimeEndpoint struct {
	textbridge.Transport
	mu                               sync.Mutex
	principal, endpoint              string
	terminal, session, closed, ready chan struct{}
	closeOnce, readyOnce             sync.Once
	message                          func(context.Context, sdk.SharingProjectMessage) error
	proof                            func(context.Context, sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error)
	proofs                           []sdk.TextServiceInstallationProof
}

func newTextRuntimeEndpoint(service string) *textRuntimeEndpoint {
	return &textRuntimeEndpoint{principal: service, endpoint: uuid.NewString(), terminal: make(chan struct{}), session: make(chan struct{}), closed: make(chan struct{}), ready: make(chan struct{})}
}
func (e *textRuntimeEndpoint) WhoAmI(context.Context) (*sdk.Identity, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &sdk.Identity{Kind: "service", PrincipalID: e.principal, EndpointID: e.endpoint}, nil
}
func (e *textRuntimeEndpoint) TextServiceEndpointSession() (string, <-chan struct{}, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.endpoint, e.session, nil
}
func (e *textRuntimeEndpoint) ProveTextServiceInstallation(ctx context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
	e.mu.Lock()
	copy := p
	copy.Nonce = append([]byte(nil), p.Nonce...)
	e.proofs = append(e.proofs, copy)
	f := e.proof
	e.mu.Unlock()
	if f != nil {
		return f(ctx, p)
	}
	return sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}, nil
}
func (e *textRuntimeEndpoint) OnSharingProjectMessage(f func(context.Context, sdk.SharingProjectMessage) error) {
	e.mu.Lock()
	e.message = f
	e.mu.Unlock()
}
func (e *textRuntimeEndpoint) OnSharingProjectReady(func(string)) {
	e.readyOnce.Do(func() { close(e.ready) })
}
func (e *textRuntimeEndpoint) Done() <-chan struct{} { return e.terminal }
func (e *textRuntimeEndpoint) Err() error            { return nil }
func (e *textRuntimeEndpoint) Close() error {
	e.closeOnce.Do(func() { close(e.closed); close(e.terminal) })
	return nil
}
func (e *textRuntimeEndpoint) SharingProjectStatus(_ context.Context, project string) (sdk.SharingProjectStatus, error) {
	return sdk.SharingProjectStatus{ProjectID: project, State: "active", EndpointProved: true}, nil
}
func (e *textRuntimeEndpoint) swap() {
	e.mu.Lock()
	close(e.session)
	e.session = make(chan struct{})
	e.endpoint = uuid.NewString()
	e.mu.Unlock()
}
func (e *textRuntimeEndpoint) send() error {
	e.mu.Lock()
	f := e.message
	e.mu.Unlock()
	if f == nil {
		return errors.New("no handler")
	}
	return f(context.Background(), sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{ProjectID: "project", ID: "ask", Kind: "ASK", SenderPrincipalID: "sender"}, Plaintext: []byte("question"), Wire: []byte("authenticated")})
}

type textRuntimeProvider struct {
	calls             atomic.Int32
	entered           chan struct{}
	canceled, release chan struct{}
}

func (p *textRuntimeProvider) Complete(ctx context.Context, _ string) (string, error) {
	p.calls.Add(1)
	if p.entered != nil {
		close(p.entered)
	}
	<-ctx.Done()
	if p.canceled != nil {
		close(p.canceled)
	}
	if p.release != nil {
		<-p.release
	}
	return "", ctx.Err()
}

type textLifecycleFixture struct {
	mu            sync.Mutex
	item          textServiceInstallation
	present       bool
	lists, claims int
	claimTTL      time.Duration
	endpoints     []*textRuntimeEndpoint
	s             *textServiceSupervisor
	c             *textServiceClient
	dir           string
	profile       textbridge.Profile
	provider      *textRuntimeProvider
}

func textLifecycle(t *testing.T) *textLifecycleFixture {
	t.Helper()
	f := &textLifecycleFixture{present: true, provider: &textRuntimeProvider{}}
	s, c, dir, p, v := textFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodGet {
			f.lists++
			all := []textServiceInstallation{}
			if f.present {
				all = append(all, f.item)
			}
			json.NewEncoder(w).Encode(all)
			return
		}
		f.claims++
		var b textServiceClaimBody
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		f.item.Generation = b.ExpectedGeneration + 1
		claim := b.ClaimID
		f.item.ActiveClaimID = &claim
		ttl := f.claimTTL
		if ttl == 0 {
			ttl = time.Minute
		}
		expiry := time.Now().Add(ttl)
		f.item.ClaimExpiresAt = &expiry
		json.NewEncoder(w).Encode(sdk.TextServiceReadiness{InstallationID: f.item.ID, ClaimID: &claim, Generation: f.item.Generation, ClaimExpiresAt: &expiry})
	})
	f.s = s
	f.c = c
	f.dir = dir
	f.profile = p
	f.item = v
	p.ProviderOrigin = "https://provider.example"
	p.Model = "fixed"
	p.KeyFile = filepath.Join(filepath.Dir(dir), "key")
	if e := os.WriteFile(p.KeyFile, []byte("test-provider-key"), 0600); e != nil {
		t.Fatal(e)
	}
	p.Fingerprint = textbridge.ProviderFingerprint(provider.Config{BaseURL: p.ProviderOrigin, Model: p.Model, APIKey: "test-provider-key"})
	if e := textbridge.SaveProfile(dir, p); e != nil {
		t.Fatal(e)
	}
	f.profile = p
	s.runProfile = textbridge.RunProfile
	s.proofRetry = time.Millisecond
	s.retry = 5 * time.Millisecond
	s.newProvider = func(provider.Config) (textbridge.Provider, error) { return f.provider, nil }
	s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		e := newTextRuntimeEndpoint(p.Service)
		f.endpoints = append(f.endpoints, e)
		return e, nil
	}
	return f
}
func textAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle did not complete")
	}
}
func (f *textLifecycleFixture) start(t *testing.T) *textRuntimeEndpoint {
	t.Helper()
	f.mu.Lock()
	before := len(f.endpoints)
	f.mu.Unlock()
	if e := f.s.reconcile(context.Background(), f.c); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.endpoints) > before {
			e := f.endpoints[len(f.endpoints)-1]
			f.mu.Unlock()
			return e
		}
		f.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("SDK not connected")
	return nil
}
func (f *textLifecycleFixture) runtime() *textServiceRuntime {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	return f.s.running[f.item.ID]
}

func TestTextServiceRuntimeRejectsUnprovenEndpoint(t *testing.T) {
	for _, kind := range []string{"false", "claim mismatch", "generation mismatch", "installation mismatch", "identity mismatch"} {
		t.Run(kind, func(t *testing.T) {
			f := textLifecycle(t)
			e := newTextRuntimeEndpoint(f.profile.Service)
			if kind == "identity mismatch" {
				e.principal = uuid.NewString()
			}
			e.proof = func(_ context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
				r := sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}
				switch kind {
				case "false":
					r.Ready = false
				case "claim mismatch":
					v := uuid.NewString()
					r.ClaimID = &v
				case "generation mismatch":
					r.Generation++
				case "installation mismatch":
					r.InstallationID = uuid.NewString()
				}
				return r, nil
			}
			f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) { return e, nil }
			if err := f.s.reconcile(context.Background(), f.c); err != nil {
				t.Fatal(err)
			}
			r := f.runtime()
			textAwait(t, r.stopped)
			e.mu.Lock()
			callbacks := e.message != nil
			proofs := len(e.proofs)
			e.mu.Unlock()
			if callbacks || f.provider.calls.Load() != 0 {
				t.Fatal("unproven endpoint dispatched")
			}
			if kind == "identity mismatch" && proofs != 0 {
				t.Fatal("wrong identity sent proof")
			}
			f.s.disconnect()
			textAwait(t, e.closed)
		})
	}
}

func TestTextServiceRuntimeRetriesExactProof(t *testing.T) {
	f := textLifecycle(t)
	e := newTextRuntimeEndpoint(f.profile.Service)
	calls := 0
	e.proof = func(_ context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
		calls++
		if calls == 1 {
			return sdk.TextServiceReadiness{}, errors.New("ambiguous")
		}
		return sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}, nil
	}
	f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) { return e, nil }
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	textAwait(t, e.ready)
	e.mu.Lock()
	proofs := append([]sdk.TextServiceInstallationProof(nil), e.proofs...)
	e.mu.Unlock()
	if len(proofs) != 2 || proofs[0].ClaimID != proofs[1].ClaimID || proofs[0].Generation != proofs[1].Generation || !bytes.Equal(proofs[0].Nonce, proofs[1].Nonce) {
		t.Fatal("ambiguous proof retry changed identity")
	}
	if unlock, err := textbridge.LockProfile(f.dir); err == nil {
		unlock()
		t.Fatal("controller did not retain profile lock")
	}
	f.s.disconnect()
	unlock, err := textbridge.LockProfile(f.dir)
	if err != nil {
		t.Fatal("disconnect retained profile lock")
	}
	unlock()
}

func TestTextServiceRuntimeDisconnectDuringStartup(t *testing.T) {
	f := textLifecycle(t)
	e := newTextRuntimeEndpoint(f.profile.Service)
	entered := make(chan struct{})
	e.proof = func(ctx context.Context, _ sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
		close(entered)
		<-ctx.Done()
		return sdk.TextServiceReadiness{}, ctx.Err()
	}
	f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) { return e, nil }
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	textAwait(t, entered)
	f.s.disconnect()
	textAwait(t, e.closed)
	e.mu.Lock()
	callbacks := e.message != nil
	e.mu.Unlock()
	if callbacks || f.provider.calls.Load() != 0 {
		t.Fatal("startup cancellation dispatched")
	}
}

func TestTextServiceRuntimeRemoteFences(t *testing.T) {
	for _, kind := range []string{"disable", "removal", "binding"} {
		t.Run(kind, func(t *testing.T) {
			f := textLifecycle(t)
			e := f.start(t)
			textAwait(t, e.ready)
			f.mu.Lock()
			switch kind {
			case "disable":
				f.item.DesiredState = "disabled"
				f.item.Generation++
			case "removal":
				f.present = false
			case "binding":
				f.item.ServiceID = uuid.NewString()
			}
			f.mu.Unlock()
			if err := f.s.reconcile(context.Background(), f.c); err != nil {
				t.Fatal(err)
			}
			textAwait(t, e.closed)
			unlock, err := textbridge.LockProfile(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			p, err := textbridge.LoadProfile(f.dir, f.profile.Service)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "disable" {
				st, err := textbridge.OpenProfileLedger(f.dir, p)
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				b, err := st.BudgetSnapshot(context.Background())
				if err != nil || b.Enabled || !p.Disabled || p.Registration.DesiredState != "disabled" {
					t.Fatal("remote disable not durably fenced")
				}
			}
		})
	}
}

func TestTextServiceRuntimeDisconnectPreservesAmbiguousProvider(t *testing.T) {
	for _, cause := range []string{"host", "endpoint"} {
		t.Run(cause, func(t *testing.T) {
			f := textLifecycle(t)
			f.provider.entered = make(chan struct{})
			e := f.start(t)
			textAwait(t, e.ready)
			if err := e.send(); err != nil {
				t.Fatal(err)
			}
			textAwait(t, f.provider.entered)
			r := f.runtime()
			if cause == "host" {
				f.s.disconnect()
			} else {
				e.swap()
				textAwait(t, r.stopped)
				f.s.disconnect()
			}
			textAwait(t, e.closed)
			st, err := textbridge.OpenProfileLedger(f.dir, f.profile)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			job, err := st.Get(context.Background(), "project", "ask")
			if err != nil || job.Phase != ledger.Unknown {
				t.Fatal("ambiguous provider outcome lost")
			}
			b, err := st.BudgetSnapshot(context.Background())
			if err != nil || b.Used != 1 || len(b.Active) != 1 || f.provider.calls.Load() != 1 {
				t.Fatal("provider claim replayed or released")
			}
		})
	}
}

func TestTextServiceRuntimeEndpointReplacementRequiresFreshClaim(t *testing.T) {
	f := textLifecycle(t)
	first := f.start(t)
	textAwait(t, first.ready)
	r := f.runtime()
	first.swap()
	textAwait(t, r.stopped)
	second := f.start(t)
	textAwait(t, second.ready)
	first.mu.Lock()
	a := first.proofs[0]
	first.mu.Unlock()
	second.mu.Lock()
	b := second.proofs[0]
	second.mu.Unlock()
	if first == second || a.ClaimID == b.ClaimID || bytes.Equal(a.Nonce, b.Nonce) || b.Generation <= a.Generation {
		t.Fatal("SDK replacement inherited proof")
	}
	f.mu.Lock()
	claims := f.claims
	f.mu.Unlock()
	if claims != 2 {
		t.Fatal("replacement did not claim exactly once")
	}
}

func TestTextServiceRuntimeEndpointSwapDuringProof(t *testing.T) {
	f := textLifecycle(t)
	e := newTextRuntimeEndpoint(f.profile.Service)
	entered := make(chan struct{})
	release := make(chan struct{})
	e.proof = func(ctx context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
		close(entered)
		<-release
		return sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}, nil
	}
	f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) { return e, nil }
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	textAwait(t, entered)
	r := f.runtime()
	e.swap()
	close(release)
	textAwait(t, r.stopped)
	e.mu.Lock()
	callbacks := e.message != nil
	e.mu.Unlock()
	if callbacks || f.provider.calls.Load() != 0 {
		t.Fatal("replacement inherited in-flight proof")
	}
}

func TestTextServiceRuntimeIdleAndDuplicateWakes(t *testing.T) {
	f := textLifecycle(t)
	f.claimTTL = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.s.run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	var e *textRuntimeEndpoint
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.endpoints) > 0 {
			e = f.endpoints[0]
		}
		f.mu.Unlock()
		if e != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e == nil {
		t.Fatal("runtime did not start")
	}
	textAwait(t, e.ready)
	f.mu.Lock()
	before := f.lists
	f.mu.Unlock()
	time.Sleep(550 * time.Millisecond)
	f.mu.Lock()
	after := f.lists
	f.mu.Unlock()
	if before != after {
		t.Fatal("idle supervisor polled")
	}
	for range 10 {
		f.s.signal()
	}
	time.Sleep(30 * time.Millisecond)
	f.mu.Lock()
	claims, connections := f.claims, len(f.endpoints)
	f.mu.Unlock()
	if claims != 1 || connections != 1 {
		t.Fatal("wake duplicated runtime")
	}
}

func TestTextServiceRuntimeDisableJoinsBeforeDisconnectReleasesLock(t *testing.T) {
	f := textLifecycle(t)
	f.provider.entered = make(chan struct{})
	f.provider.canceled = make(chan struct{})
	f.provider.release = make(chan struct{})
	e := f.start(t)
	textAwait(t, e.ready)
	if err := e.send(); err != nil {
		t.Fatal(err)
	}
	textAwait(t, f.provider.entered)
	f.mu.Lock()
	f.item.DesiredState = "disabled"
	f.item.Generation++
	f.mu.Unlock()
	reconciled := make(chan error, 1)
	go func() { reconciled <- f.s.reconcile(context.Background(), f.c) }()
	textAwait(t, f.provider.canceled)
	disconnected := make(chan struct{})
	go func() { f.s.disconnect(); close(disconnected) }()
	select {
	case <-disconnected:
		t.Fatal("disconnect escaped provider join")
	default:
	}
	if unlock, err := textbridge.LockProfile(f.dir); err == nil {
		unlock()
		t.Fatal("profile lock released before disable persisted")
	}
	close(f.provider.release)
	if err := <-reconciled; err != nil {
		t.Fatal(err)
	}
	textAwait(t, disconnected)
	unlock, err := textbridge.LockProfile(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	p, err := textbridge.LoadProfile(f.dir, f.profile.Service)
	if err != nil || !p.Disabled {
		t.Fatal("disconnect overtook durable disable")
	}
	st, err := textbridge.OpenProfileLedger(f.dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	budget, err := st.BudgetSnapshot(context.Background())
	if err != nil || budget.Enabled {
		t.Fatal("ledger disable not persisted")
	}
	job, err := st.Get(context.Background(), "project", "ask")
	if err != nil || job.Phase != ledger.Unknown {
		t.Fatal("disable lost ambiguous provider result")
	}
}

func TestTextServiceOwnerProofBeforeDispatch(t *testing.T) {
	for _, responseContract := range []string{"", textbridge.SharingProjectContract, textbridge.OwnerTextProjectContract} {
		t.Run(responseContract, func(t *testing.T) {
			f := textLifecycle(t)
			f.profile = textFixtureContract(t, f.dir, f.profile, textbridge.OwnerTextProjectContract)
			f.c.session.ProtocolFeatures = append(f.c.session.ProtocolFeatures, textServiceContractsProtocol)
			e := newTextRuntimeEndpoint(f.profile.Service)
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			e.proof = func(_ context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
				if p.ProjectContract != textbridge.OwnerTextProjectContract {
					t.Error("owner proof omitted contract")
				}
				close(entered)
				<-release
				return sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true, ProjectContract: responseContract}, nil
			}
			var dispatched atomic.Bool
			f.s.runProfile = func(ctx context.Context, _ string, _ textbridge.Profile, _ textbridge.Ledger, config textbridge.RuntimeConfig) error {
				defer close(finished)
				if config.Enabled("project") {
					t.Error("enabled before proof")
				}
				err := config.Authorize(ctx, e)
				if err != nil {
					return err
				}
				if !config.Enabled("project") {
					t.Error("matching proof did not enable dispatch")
				}
				dispatched.Store(true)
				<-ctx.Done()
				return ctx.Err()
			}
			if err := f.s.reconcile(context.Background(), f.c); err != nil {
				t.Fatal(err)
			}
			textAwait(t, entered)
			if f.runtime().enabled.Load() || dispatched.Load() {
				t.Fatal("dispatch preceded proof response")
			}
			close(release)
			if responseContract == textbridge.OwnerTextProjectContract {
				deadline := time.Now().Add(3 * time.Second)
				for !dispatched.Load() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if !dispatched.Load() {
					t.Fatal("matching owner proof did not dispatch")
				}
			} else {
				textAwait(t, finished)
				if dispatched.Load() {
					t.Fatal("unbound owner proof dispatched")
				}
			}
			f.s.disconnect()
			textAwait(t, finished)
		})
	}
}
