//go:build unix

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

type bridgeTestEndpoint struct {
	id      string
	done    chan struct{}
	once    sync.Once
	enabled atomic.Bool
}

func (e *bridgeTestEndpoint) PrincipalID() string { return e.id }
func (e *bridgeTestEndpoint) OnSharingMessage(func(context.Context, sdk.SharingMessage) error) {
	e.enabled.Store(true)
}
func (e *bridgeTestEndpoint) Done() <-chan struct{} { return e.done }
func (e *bridgeTestEndpoint) Close() error          { e.once.Do(func() { close(e.done) }); return nil }

type bridgeFixture struct {
	t                       *testing.T
	mu                      sync.Mutex
	installation            sharingBridgeInstallation
	present                 bool
	generation              int64
	owner                   sharingBridgeController
	lease                   time.Time
	leaseDuration           time.Duration
	claims, lists, connects int
	loseClaim, loseExchange bool
	staleProof              bool
	staleRenews             int
	staleClaims             int
	staleRecoveryLists      int
	connectFailures         int
	listStatus              int
	listFailures            int
	endpoints               []*bridgeTestEndpoint
}

func newBridgeFixture(t *testing.T) (*bridgeFixture, *sharingBridgeSupervisor) {
	t.Helper()
	f := &bridgeFixture{t: t, present: true, leaseDuration: 30 * time.Second, installation: sharingBridgeInstallation{ID: domain.NewID().String(), ServiceID: domain.NewID().String(), DesiredState: "running"}}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	s := newSharingBridgeSupervisor(&Daemon{Config: Config{ServerURL: server.URL, Credential: "host-test", StateDir: t.TempDir()}})
	s.retry = 5 * time.Millisecond
	s.renew = 20 * time.Millisecond
	s.connect = func(ctx context.Context, cfg sdk.Config) (sharingBridgeEndpoint, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.connects++
		if f.connectFailures > 0 {
			f.connectFailures--
			return nil, errors.New("temporary SDK connect failure")
		}
		if f.loseExchange {
			f.loseExchange = false
			return nil, errors.New("exchange response lost")
		}
		// Simulate the SDK's persisted durable credential, never a daemon-owned copy.
		dir := filepath.Join(cfg.StateDir, "principals", f.installation.ServiceID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "credential"), []byte("pgn_epd_v1_fixture"), 0600); err != nil {
			return nil, err
		}
		e := &bridgeTestEndpoint{id: f.installation.ServiceID, done: make(chan struct{})}
		f.endpoints = append(f.endpoints, e)
		return e, nil
	}
	s.admit(transport.HostSessionPayload{TenantID: "tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
	return f, s
}
func (f *bridgeFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer host-test" {
		http.Error(w, "", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		f.lists++
		if f.listStatus != 0 {
			http.Error(w, "", f.listStatus)
			return
		}
		if f.listFailures > 0 {
			f.listFailures--
			http.Error(w, "", http.StatusServiceUnavailable)
			return
		}
		if f.staleProof && f.staleClaims > 0 {
			f.staleRecoveryLists++
		}
		all := []sharingBridgeInstallation{}
		if f.present {
			v := f.installation
			v.CredentialGeneration = f.generation
			all = append(all, v)
		}
		_ = json.NewEncoder(w).Encode(all)
		return
	}
	if !f.present {
		http.Error(w, "", 404)
		return
	}
	if f.staleProof {
		if strings.HasSuffix(r.URL.Path, "/renew") {
			f.staleRenews++
		} else if strings.HasSuffix(r.URL.Path, "/claim") {
			f.staleClaims++
		}
		http.Error(w, "", 404)
		return
	}
	var in sharingBridgeController
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "", 400)
		return
	}
	if in.ExpectedGeneration != f.generation {
		http.Error(w, "", 409)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/renew") {
		if in.RunnerID != f.owner.RunnerID || !in.ConnectionEpoch.Equal(f.owner.ConnectionEpoch) || !time.Now().Before(f.lease) {
			http.Error(w, "", 409)
			return
		}
	} else {
		f.claims++
		f.generation++
		f.owner = in
		if f.loseClaim {
			f.loseClaim = false
			http.Error(w, "", 503)
			return
		}
	}
	f.lease = time.Now().Add(f.leaseDuration)
	out := sharingBridgeClaim{Generation: f.generation, LeaseExpiresAt: f.lease}
	if strings.HasSuffix(r.URL.Path, "/claim") {
		out.ActivationCredential = "pgn_act_v1_fixture"
	}
	_ = json.NewEncoder(w).Encode(out)
}
func startBridgeTest(t *testing.T, s *sharingBridgeSupervisor) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("supervisor did not stop")
		}
	})
	return cancel, done
}
func awaitBridge(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("bridge state did not converge")
}
func (f *bridgeFixture) ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.endpoints) == 0 {
		return false
	}
	endpoint := f.endpoints[len(f.endpoints)-1]
	select {
	case <-endpoint.Done():
		return false
	default:
		return endpoint.enabled.Load()
	}
}

func TestSharingBridgeStartupRestartAndNoIdlePolling(t *testing.T) {
	f, s := newBridgeFixture(t)
	cancel, done := startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	cancel()
	<-done
	s2 := newSharingBridgeSupervisor(s.daemon)
	s2.retry = s.retry
	s2.renew = s.renew
	s2.connect = s.connect
	s2.admit(transport.HostSessionPayload{TenantID: "tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
	startBridgeTest(t, s2)
	awaitBridge(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.endpoints) == 2 && f.endpoints[1].enabled.Load()
	})
	f.mu.Lock()
	f.present = false
	f.mu.Unlock()
	s2.signal()
	awaitBridge(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		select {
		case <-f.endpoints[1].Done():
			return true
		default:
			return false
		}
	})
	time.Sleep(30 * time.Millisecond)
	f.mu.Lock()
	before := f.lists
	f.mu.Unlock()
	time.Sleep(60 * time.Millisecond)
	f.mu.Lock()
	after := f.lists
	f.mu.Unlock()
	if before != after {
		t.Fatalf("idle list polling: %d -> %d", before, after)
	}
	if _, err := os.Stat(filepath.Join(s.daemon.StateDir, "sharing-bridges", f.installation.ID, "sdk")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed installation retained active SDK state")
	}
}
func TestSharingBridgeLostClaimAndExchangeResponses(t *testing.T) {
	for _, mode := range []string{"claim", "exchange"} {
		t.Run(mode, func(t *testing.T) {
			f, s := newBridgeFixture(t)
			f.loseClaim = mode == "claim"
			f.loseExchange = mode == "exchange"
			startBridgeTest(t, s)
			awaitBridge(t, f.ready)
			f.mu.Lock()
			claims := f.claims
			generation := f.generation
			f.mu.Unlock()
			if claims < 2 || generation < 2 {
				t.Fatalf("failed to rotate unreachable credential: claims=%d generation=%d", claims, generation)
			}
			b, err := os.ReadFile(filepath.Join(s.daemon.StateDir, "sharing-bridges", f.installation.ID, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "pgn_") {
				t.Fatal("credential leaked to controller journal")
			}
		})
	}
}
func TestSharingBridgeDuplicateLocalRunner(t *testing.T) {
	f, s := newBridgeFixture(t)
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	s2 := newSharingBridgeSupervisor(s.daemon)
	s2.connect = s.connect
	s2.admit(transport.HostSessionPayload{TenantID: "tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
	startBridgeTest(t, s2)
	time.Sleep(40 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claims != 1 || len(f.endpoints) != 1 {
		t.Fatalf("duplicate local endpoint: claims=%d endpoints=%d", f.claims, len(f.endpoints))
	}
}
func TestSharingBridgeReconnectRetainsEndpointAndStaleGenerationRecovers(t *testing.T) {
	f, s := newBridgeFixture(t)
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	f.mu.Lock()
	first := f.endpoints[0]
	f.mu.Unlock()
	s.disconnect()
	time.Sleep(40 * time.Millisecond)
	select {
	case <-first.Done():
		t.Fatal("brief host disconnect closed healthy endpoint")
	default:
	}
	s.admit(transport.HostSessionPayload{TenantID: "tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
	awaitBridge(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.endpoints) == 2 && f.endpoints[1].enabled.Load()
	})
	f.mu.Lock()
	f.generation++
	f.mu.Unlock()
	s.signal()
	awaitBridge(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.endpoints) == 3 && f.endpoints[2].enabled.Load()
	})
}
func TestSharingBridgeRevocationAndLeaseExpiryStopEndpoint(t *testing.T) {
	for _, mode := range []string{"revocation", "lease"} {
		t.Run(mode, func(t *testing.T) {
			f, s := newBridgeFixture(t)
			if mode == "lease" {
				f.leaseDuration = 300 * time.Millisecond
			}
			startBridgeTest(t, s)
			awaitBridge(t, f.ready)
			f.mu.Lock()
			endpoint := f.endpoints[0]
			if mode == "revocation" {
				f.present = false
			}
			f.mu.Unlock()
			if mode == "lease" {
				s.disconnect()
			} else {
				s.signal()
			}
			awaitBridge(t, func() bool {
				select {
				case <-endpoint.Done():
					return true
				default:
					return false
				}
			})
		})
	}
}
func TestSharingBridgeCapabilityAndDurableWake(t *testing.T) {
	f, s := newBridgeFixture(t)
	u := s.daemon.wsURL(context.Background())
	if !strings.Contains(u, "sdk_pair_bridge=sdk_pair_bridge_v1") {
		t.Fatal("missing bridge capability")
	}
	if err := s.recordWake(f.installation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.daemon.StateDir, "sharing-bridges", f.installation.ID, "reconcile.intent")); err != nil {
		t.Fatal(err)
	}
}

func TestSharingBridgeStaleRunnerProofDoesNotRetireLiveInstallation(t *testing.T) {
	f, s := newBridgeFixture(t)
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	f.mu.Lock()
	endpoint := f.endpoints[0]
	f.staleProof = true
	f.mu.Unlock()
	s.signal()
	// Observe both rejected requests and the successful authority check after
	// the claim rejection before checking that a nonterminal 404 preserves state.
	awaitBridge(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.staleRenews > 0 && f.staleClaims > 0 && f.staleRecoveryLists > 0
	})
	select {
	case <-endpoint.Done():
		t.Fatal("stale runner proof retired live bridge before lease expiry")
	default:
	}
	if _, err := os.Stat(filepath.Join(s.daemon.StateDir, "sharing-bridges", f.installation.ID, "sdk")); err != nil {
		t.Fatal("stale proof erased SDK state", err)
	}
	f.mu.Lock()
	f.staleProof = false
	f.mu.Unlock()
	s.signal()
}

func TestSharingBridgeRecoversAfterRepeatedConnectFailures(t *testing.T) {
	f, s := newBridgeFixture(t)
	f.connectFailures = 7
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connects != 8 {
		t.Fatalf("connect attempts = %d, want 8", f.connects)
	}
	if f.lists != 1 {
		t.Fatalf("recovery required an unrelated reconcile: list calls = %d", f.lists)
	}
}

func TestSharingBridgeUnsupportedRecoveryListStaysDormant(t *testing.T) {
	for _, trigger := range []string{"reconnect", "command"} {
		t.Run(trigger, func(t *testing.T) {
			f, s := newBridgeFixture(t)
			f.present = false
			f.listStatus = http.StatusNotFound
			startBridgeTest(t, s)
			awaitBridge(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lists >= 1 })
			time.Sleep(40 * time.Millisecond)
			f.mu.Lock()
			calls := f.lists
			f.mu.Unlock()
			if calls != 1 {
				t.Fatalf("unsupported recovery endpoint was polled %d times", calls)
			}
			if trigger == "reconnect" {
				s.disconnect()
				s.admit(transport.HostSessionPayload{TenantID: "tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
			} else if err := s.recordWake(f.installation.ID); err != nil {
				t.Fatal(err)
			}
			awaitBridge(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lists >= 2 })
			time.Sleep(40 * time.Millisecond)
			f.mu.Lock()
			calls = f.lists
			f.listStatus = 0
			f.mu.Unlock()
			if calls != 2 {
				t.Fatalf("explicit wake resumed idle polling: calls = %d", calls)
			}
			if err := s.recordWake(f.installation.ID); err != nil {
				t.Fatal(err)
			}
			awaitBridge(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lists >= 3 })
		})
	}
}

func TestSharingBridgeRecoveryListRetriesTransientErrors(t *testing.T) {
	f, s := newBridgeFixture(t)
	f.listFailures = 1
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lists != 2 {
		t.Fatalf("transient recovery list failure did not retry: calls = %d", f.lists)
	}
}

func TestSharingBridgeChangedMailboxHostBindingStopsEndpoint(t *testing.T) {
	f, s := newBridgeFixture(t)
	startBridgeTest(t, s)
	awaitBridge(t, f.ready)
	f.mu.Lock()
	endpoint := f.endpoints[0]
	f.mu.Unlock()
	s.admit(transport.HostSessionPayload{TenantID: "other-tenant", HostID: "host", RunnerID: domain.NewID().String(), RunnerEpoch: time.Now()})
	awaitBridge(t, func() bool {
		select {
		case <-endpoint.Done():
			return true
		default:
			return false
		}
	})
}
