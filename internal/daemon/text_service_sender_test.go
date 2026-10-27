//go:build unix

package daemon

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

const managedSenderProject = "22222222-2222-4222-8222-222222222222"
const managedSenderRecipient = "33333333-3333-4333-8333-333333333333"

type textSenderState struct {
	mu              sync.Mutex
	wires           map[string]sdk.PreparedSharingProjectMessage
	receipts        map[string]sdk.SharingProjectMessageReceipt
	prepares, sends atomic.Int32
	uncertain       bool
	sent            chan string
}
type textSenderEndpoint struct {
	*textRuntimeEndpoint
	state *textSenderState
}

func (e *textSenderEndpoint) EnableSharingProjects() {}
func (e *textSenderEndpoint) OnSharingProjectReady(h func(string)) {
	e.textRuntimeEndpoint.OnSharingProjectReady(h)
	h(managedSenderProject)
}
func (e *textSenderEndpoint) PrepareSharingProjectMessageWithID(_, _, _, id string, input, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	e.state.prepares.Add(1)
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	p := sdk.PreparedSharingProjectMessage{ID: id, Wire: []byte("ciphertext:" + id)}
	e.state.wires[id] = p
	return p, nil
}
func (e *textSenderEndpoint) LoadPreparedSharingProjectMessage(_, id string) (sdk.PreparedSharingProjectMessage, error) {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	if p, ok := e.state.wires[id]; ok {
		return p, nil
	}
	return sdk.PreparedSharingProjectMessage{}, os.ErrNotExist
}
func (e *textSenderEndpoint) SharingProjectMessageReceipt(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	if r, ok := e.state.receipts[id]; ok {
		return r, nil
	}
	return sdk.SharingProjectMessageReceipt{}, os.ErrNotExist
}
func (e *textSenderEndpoint) SendPreparedSharingProjectMessage(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	e.state.sends.Add(1)
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	e.state.sent <- id
	if e.state.uncertain {
		return sdk.SharingProjectMessageReceipt{}, errors.New("uncertain admission")
	}
	sum := sha256.Sum256(e.state.wires[id].Wire)
	r := sdk.SharingProjectMessageReceipt{MessageID: id, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	e.state.receipts[id] = r
	return r, nil
}
func senderLifecycle(t *testing.T) (*textLifecycleFixture, *textSenderState, sender.Operation) {
	t.Helper()
	f := textLifecycle(t)
	// This fixture reuses responder host setup, but represents a sender-only
	// installation with no second local responder profile for the same service.
	if err := os.Remove(filepath.Join(f.dir, "profile.json")); err != nil {
		t.Fatal(err)
	}
	dir, err := textbridge.ProfileDirectoryForRole(f.s.daemon.StateDir, f.profile.Service, "sender")
	if err != nil {
		t.Fatal(err)
	}
	p := textbridge.Profile{Role: "sender", Service: f.profile.Service, Server: f.profile.Server, Credential: f.profile.Credential, Registration: f.profile.Registration}
	p.Registration.Role = "sender"
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	o, err := store.Reserve(context.Background(), managedSenderProject, managedSenderRecipient, "question")
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	f.dir, f.profile = dir, p
	f.item.Role = "sender"
	state := &textSenderState{wires: map[string]sdk.PreparedSharingProjectMessage{}, receipts: map[string]sdk.SharingProjectMessageReceipt{}, sent: make(chan string, 10)}
	f.s.connect = func(_ context.Context, c sdk.Config) (textbridge.RuntimeConnection, error) {
		if c.ExpectedPrincipalID != p.Service || c.StateDir != filepath.Join(dir, "sdk") {
			t.Error("sender SDK binding lost")
		}
		e := &textSenderEndpoint{textRuntimeEndpoint: newTextRuntimeEndpoint(p.Service), state: state}
		f.mu.Lock()
		f.endpoints = append(f.endpoints, e.textRuntimeEndpoint)
		f.mu.Unlock()
		return e, nil
	}
	return f, state, o
}
func awaitSenderSend(t *testing.T, state *textSenderState, ask string) {
	t.Helper()
	select {
	case id := <-state.sent:
		if id != ask {
			t.Fatal("changed ASK identity")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("managed sender did not send")
	}
}

func TestTextServiceSenderProofBeforeSendAndSingleRuntime(t *testing.T) {
	f, state, o := senderLifecycle(t)
	entered, release := make(chan struct{}), make(chan struct{})
	e := &textSenderEndpoint{textRuntimeEndpoint: newTextRuntimeEndpoint(f.profile.Service), state: state}
	e.proof = func(ctx context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return sdk.TextServiceReadiness{}, ctx.Err()
		}
		return sdk.TextServiceReadiness{InstallationID: p.InstallationID, ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}, nil
	}
	var connects atomic.Int32
	f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) {
		connects.Add(1)
		return e, nil
	}
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	textAwait(t, entered)
	if state.prepares.Load() != 0 || state.sends.Load() != 0 {
		t.Fatal("sender dispatched before proof")
	}
	if unlock, err := textbridge.LockProfile(f.dir); err == nil {
		unlock()
		t.Fatal("runtime released sender lock")
	}
	close(release)
	awaitSenderSend(t, state, o.AskID)
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	if connects.Load() != 1 || state.prepares.Load() != 1 || state.sends.Load() != 1 || f.provider.calls.Load() != 0 {
		t.Fatal("duplicate sender runtime or provider dispatch")
	}
	r := f.runtime()
	e.swap()
	textAwait(t, r.stopped)
	if r.enabled.Load() {
		t.Fatal("changed SDK endpoint retained authority")
	}
	f.s.disconnect()
	textAwait(t, e.closed)
	if unlock, err := textbridge.LockProfile(f.dir); err != nil {
		t.Fatal("joined sender retained lock", err)
	} else {
		unlock()
	}
}

func TestTextServiceSenderRejectsWrongPins(t *testing.T) {
	for _, kind := range []string{"role", "service", "host", "SDK identity", "SDK proof"} {
		t.Run(kind, func(t *testing.T) {
			f, state, _ := senderLifecycle(t)
			if kind == "role" || kind == "service" || kind == "host" {
				f.mu.Lock()
				switch kind {
				case "role":
					f.item.Role = "responder"
				case "service":
					f.item.ServiceID = uuid.NewString()
				case "host":
					f.item.HostID = uuid.NewString()
				}
				f.mu.Unlock()
				_ = f.s.reconcile(context.Background(), f.c)
				f.mu.Lock()
				claims, endpoints := f.claims, len(f.endpoints)
				f.mu.Unlock()
				if claims != 0 || endpoints != 0 {
					t.Fatal("wrong installation pins started sender")
				}
				return
			}
			e := &textSenderEndpoint{textRuntimeEndpoint: newTextRuntimeEndpoint(f.profile.Service), state: state}
			if kind == "SDK identity" {
				e.principal = uuid.NewString()
			} else {
				e.proof = func(_ context.Context, p sdk.TextServiceInstallationProof) (sdk.TextServiceReadiness, error) {
					return sdk.TextServiceReadiness{InstallationID: uuid.NewString(), ClaimID: &p.ClaimID, Generation: p.Generation, Ready: true}, nil
				}
			}
			f.s.connect = func(context.Context, sdk.Config) (textbridge.RuntimeConnection, error) { return e, nil }
			if err := f.s.reconcile(context.Background(), f.c); err != nil {
				t.Fatal(err)
			}
			textAwait(t, f.runtime().stopped)
			if state.prepares.Load() != 0 || state.sends.Load() != 0 {
				t.Fatal("wrong SDK pins dispatched sender")
			}
		})
	}
}

func TestTextServiceSenderReconnectRetainsAmbiguousASK(t *testing.T) {
	f, state, o := senderLifecycle(t)
	state.uncertain = true
	first := f.start(t)
	awaitSenderSend(t, state, o.AskID)
	f.s.disconnect()
	textAwait(t, first.closed)
	state.mu.Lock()
	wire := string(state.wires[o.AskID].Wire)
	state.uncertain = false
	state.mu.Unlock()
	session := f.c.session
	session.NativeAdmissionID, session.RunnerID = uuid.NewString(), uuid.NewString()
	session.RunnerEpoch = time.Now().UTC()
	f.s.admit(session)
	f.s.mu.Lock()
	f.c = f.s.client
	f.s.mu.Unlock()
	f.start(t)
	awaitSenderSend(t, state, o.AskID)
	state.mu.Lock()
	same := string(state.wires[o.AskID].Wire) == wire
	state.mu.Unlock()
	if state.prepares.Load() != 1 || state.sends.Load() != 2 || !same {
		t.Fatal("host reconnect changed ciphertext or ASK identity")
	}
}

func TestTextServiceSenderDisablePersistsAndBlocksCLIEngine(t *testing.T) {
	f, state, o := senderLifecycle(t)
	state.uncertain = true
	endpoint := f.start(t)
	awaitSenderSend(t, state, o.AskID)
	f.mu.Lock()
	f.item.DesiredState = "disabled"
	f.item.Generation++
	f.mu.Unlock()
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	textAwait(t, endpoint.closed)
	p, err := textbridge.LoadProfile(f.dir, f.profile.Service)
	if err != nil || !p.Disabled || p.Registration.DesiredState != "disabled" {
		t.Fatalf("sender profile disable: %+v %v", p.Registration, err)
	}
	store, err := textbridge.OpenSenderStore(f.dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enabled, err := store.Enabled(context.Background())
	if err != nil || enabled {
		t.Fatal("sender ledger disable not durable", err)
	}
	if _, err := store.Reserve(context.Background(), managedSenderProject, managedSenderRecipient, "new"); !errors.Is(err, sender.ErrDisabled) {
		t.Fatal("disabled sender reserved new work", err)
	}
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	count := len(f.endpoints)
	f.mu.Unlock()
	if count != 1 || state.sends.Load() != 1 {
		t.Fatal("remote disable restarted sender")
	}
}

func TestTextServiceSenderRepairsPartialDisable(t *testing.T) {
	for _, gate := range []string{"profile", "store"} {
		t.Run(gate, func(t *testing.T) {
			f, _, _ := senderLifecycle(t)
			p := f.profile
			if gate == "profile" {
				p.Disabled = true
				p.Registration.DesiredState = "disabled"
				if err := textbridge.SaveProfile(f.dir, p); err != nil {
					t.Fatal(err)
				}
			} else {
				store, err := textbridge.OpenSenderStore(f.dir, p)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Disable(context.Background()); err != nil {
					t.Fatal(err)
				}
				store.Close()
			}
			f.mu.Lock()
			f.item.DesiredState = "disabled"
			f.item.Generation++
			f.mu.Unlock()
			if err := f.s.reconcile(context.Background(), f.c); err != nil {
				t.Fatal(err)
			}
			p, err := textbridge.LoadProfile(f.dir, p.Service)
			if err != nil || !p.Disabled || p.Registration.DesiredState != "disabled" {
				t.Fatal("partial disable did not repair sender profile", err)
			}
			store, err := textbridge.OpenSenderStore(f.dir, p)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			enabled, err := store.Enabled(context.Background())
			if err != nil || enabled {
				t.Fatal("partial disable did not repair sender store", err)
			}
			f.mu.Lock()
			claims := f.claims
			f.mu.Unlock()
			if claims != 0 {
				t.Fatal("disabled sender claimed installation")
			}
		})
	}
}

func TestTextServiceSenderDisableReopensPoisonedStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires filesystem write permissions to be enforced")
	}
	f, state, o := senderLifecycle(t)
	endpoint := f.start(t)
	awaitSenderSend(t, state, o.AskID)
	original := f.s.disableSender
	var failed *sender.Store
	calls := 0
	f.s.disableSender = func(store *sender.Store) error {
		calls++
		if calls == 1 {
			failed = store
			operations := filepath.Join(f.dir, "operations")
			if err := os.Chmod(operations, 0500); err != nil {
				t.Fatal(err)
			}
			err := original(store)
			if restoreErr := os.Chmod(operations, 0700); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if err == nil {
				t.Fatal("injected sender persist failure did not fail")
			}
			if _, loadErr := store.Enabled(context.Background()); !errors.Is(loadErr, sender.ErrInvalid) {
				t.Fatal("persist failure did not poison handle", loadErr)
			}
			return err
		}
		if store == failed {
			t.Fatal("retried disable on poisoned sender handle")
		}
		return original(store)
	}
	f.mu.Lock()
	f.item.DesiredState = "disabled"
	f.item.Generation++
	f.mu.Unlock()
	if err := f.s.reconcile(context.Background(), f.c); err == nil {
		t.Fatal("disable disk failure ignored")
	}
	textAwait(t, endpoint.closed)
	if unlock, err := textbridge.LockProfile(f.dir); err == nil {
		unlock()
		t.Fatal("failed disable released profile lock")
	}
	p, err := textbridge.LoadProfile(f.dir, f.profile.Service)
	if err != nil || !p.Disabled || p.Registration.DesiredState != "disabled" {
		t.Fatal("failed store disable lost profile gate", err)
	}
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal("transient disable failure wedged recovery", err)
	}
	if unlock, err := textbridge.LockProfile(f.dir); err != nil {
		t.Fatal("recovered disable retained profile lock", err)
	} else {
		unlock()
	}
	store, err := textbridge.OpenSenderStore(f.dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enabled, err := store.Enabled(context.Background())
	if err != nil || enabled {
		t.Fatal("recovered sender disable not durable", err)
	}
	if calls < 2 {
		t.Fatal("disable was not retried")
	}
}
