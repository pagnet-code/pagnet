package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

func TestBrowserStandbyAppliedTupleAndJoin(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.a.HostID, f.a.Provider = stringIDForStandby(), "browser"
	f.c.renewInterval = time.Millisecond
	configs := make(chan sdk.ManagedBrowserStandbyConfig, 4)
	var joined atomic.Bool
	f.c.serve = func(ctx context.Context, config sdk.ManagedBrowserStandbyConfig) error {
		configs <- config
		<-ctx.Done()
		joined.Store(true)
		return ctx.Err()
	}
	var applied struct {
		CredentialID         string `json:"credentialId"`
		CredentialGeneration int64  `json:"credentialGeneration"`
	}
	polls := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/apply-ack") {
			if err := json.NewDecoder(r.Body).Decode(&applied); err != nil {
				t.Fatal(err)
			}
			select {
			case <-configs:
				t.Fatal("standby launched before apply acknowledgement")
			default:
			}
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-status") {
			polls++
			if polls == 3 {
				f.cancel()
			}
		}
		if r.Method == http.MethodDelete && !joined.Load() {
			t.Error("lease released before child joined")
		}
		return nil, false
	}
	f.run()
	if len(configs) != 1 {
		t.Fatalf("launched %d children", len(configs))
	}
	config := <-configs
	b := f.bindings[0]
	want := transport.ManagedBrowserStandbyTuple{ConnectionID: f.a.ID, BindingID: b.ID, NetworkID: b.NetworkID, PrincipalID: b.PrincipalID, HostID: f.a.HostID, Provider: f.a.Provider, DesiredRevision: 3, LeaseID: "00000000-0000-4000-8000-000000000001", InstanceID: f.c.instanceID, LeaseGeneration: 1, CredentialID: applied.CredentialID, CredentialGeneration: applied.CredentialGeneration, PolicyFingerprint: b.PolicyFingerprint}
	if !reflect.DeepEqual(config.ExpectedTuple, want) || config.ExpectedTuple.CredentialID == "" || config.BindingCredential != "private-test-value" || config.Server != f.c.serverURL {
		t.Fatal("incorrect immutable standby authority")
	}
	if !config.AuthorityDeadline.Equal(f.now.Add(30*time.Second - 5*time.Millisecond)) {
		t.Fatal("incorrect initial authority deadline")
	}
	if !f.released || !joined.Load() || len(f.c.slots) != 0 {
		t.Fatal("incomplete joined cleanup")
	}
}

func stringIDForStandby() string { return "00000000-0000-4000-8000-000000000002" }

func TestBrowserStandbyFreshCredentialRecovery(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport_exhaustion", true: "terminal"}[terminal], func(t *testing.T) {
			f := newBrowserBindingFixture(t, 1)
			f.a.HostID, f.a.Provider = stringIDForStandby(), "browser"
			configs := make(chan sdk.ManagedBrowserStandbyConfig, 8)
			f.c.serve = func(_ context.Context, config sdk.ManagedBrowserStandbyConfig) error {
				configs <- config
				if terminal {
					return sdk.ErrManagedBrowserStandbyUnauthorized
				}
				return sdk.ErrManagedBrowserStandbyTransport
			}
			f.hook = func(r *http.Request) (*http.Response, bool) {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/runtime-lease") && f.c.lease.Active {
					return browserBindingResponse(200, f.c.lease), true
				}
				return nil, false
			}
			f.run()
			want := 4
			if terminal {
				want = 1
			}
			if len(configs) != want || f.acks != want || f.rotations[f.bindings[0].ID] != want {
				t.Fatalf("launch/ack/rotation counts: %d/%d/%d", len(configs), f.acks, f.rotations[f.bindings[0].ID])
			}
			seen := map[string]bool{}
			for i := 1; i <= want; i++ {
				config := <-configs
				if config.ExpectedTuple.CredentialGeneration != int64(i) || seen[config.ExpectedTuple.CredentialID] {
					t.Fatal("reused attempted credential")
				}
				seen[config.ExpectedTuple.CredentialID] = true
				if !config.AuthorityDeadline.Equal(f.c.standbyUntil) && !f.c.standbyUntil.IsZero() {
					t.Fatal("extended recovery authority")
				}
			}
			if !f.released || len(f.c.slots) != 0 {
				t.Fatal("incomplete recovery cleanup")
			}
		})
	}
}

func TestBrowserStandbyAttemptedOnceAndImmutableDeadline(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.c.standbyUntil = f.now.Add(time.Second)
	f.c.wake = make(chan struct{}, 1)
	configs := make(chan sdk.ManagedBrowserStandbyConfig, 2)
	f.c.serve = func(ctx context.Context, config sdk.ManagedBrowserStandbyConfig) error {
		configs <- config
		<-ctx.Done()
		return ctx.Err()
	}
	slot := &browserBindingSlot{secret: []byte("private-test-value"), credentialID: stringIDForStandby(), generation: 1, expiresAt: f.now.Add(2 * time.Second)}
	f.c.startStandby(context.Background(), f.a, f.bindings[0], slot)
	first := <-configs
	f.c.authorityUntil = f.now.Add(time.Hour)
	f.c.startStandby(context.Background(), f.a, f.bindings[0], slot)
	slot.wipe()
	if len(configs) != 0 || !first.AuthorityDeadline.Equal(f.now.Add(time.Second)) || !slot.attempted || len(slot.secret) != 0 {
		t.Fatal("attempt reused or authority extended")
	}
}

func TestBrowserStandbyCanceledRecoveryBackoff(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.c.serve = func(context.Context, sdk.ManagedBrowserStandbyConfig) error {
		return sdk.ErrManagedBrowserStandbyTransport
	}
	f.c.wait = func(context.Context, time.Duration) bool { f.cancel(); return false }
	f.run()
	if f.rotations[f.bindings[0].ID] != 1 {
		t.Fatal("issued replacement after cancellation")
	}
}

func TestBrowserStandbyRecoveryAmbiguousIssuance(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	var calls atomic.Int32
	f.c.serve = func(context.Context, sdk.ManagedBrowserStandbyConfig) error {
		if calls.Add(1) == 1 {
			return sdk.ErrManagedBrowserStandbyTransport
		}
		return sdk.ErrManagedBrowserStandbyUnauthorized
	}
	ambiguous := false
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/runtime-lease") && f.c.lease.Active {
			return browserBindingResponse(200, f.c.lease), true
		}
		if strings.HasSuffix(r.URL.Path, "/endpoint-credential") && f.generations[f.bindings[0].ID] == 1 && !ambiguous {
			ambiguous = true
			f.generations[f.bindings[0].ID]++ // Issued remotely, response lost before secret installation.
			return browserBindingResponse(503, nil), true
		}
		return nil, false
	}
	f.run()
	if !ambiguous || calls.Load() != 2 || f.generations[f.bindings[0].ID] != 3 || f.acks != 2 {
		t.Fatal("ambiguous issuance was reused or not reconciled")
	}
}

func TestBrowserStandbyRotationJoinsBeforeIssuance(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.c.renewInterval = time.Millisecond
	configs := make(chan sdk.ManagedBrowserStandbyConfig, 4)
	var joined atomic.Int32
	f.c.serve = func(ctx context.Context, config sdk.ManagedBrowserStandbyConfig) error {
		configs <- config
		<-ctx.Done()
		joined.Add(1)
		return ctx.Err()
	}
	refreshed := false
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-status") && !refreshed {
			refreshed = true
			status := f.status(f.bindings[0])
			status.CredentialRefreshRequired = true
			return browserBindingResponse(200, map[string]any{"connectionId": f.a.ID, "desiredRevision": 3, "bindings": []browserBindingStatus{status}}), true
		}
		if strings.HasSuffix(r.URL.Path, "/endpoint-credential") && f.generations[f.bindings[0].ID] == 1 && joined.Load() != 1 {
			t.Error("rotation issued before old child joined")
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-status") && refreshed {
			f.cancel()
		}
		return nil, false
	}
	f.run()
	if len(configs) != 2 || joined.Load() != 2 {
		t.Fatalf("rotation children/joins: %d/%d", len(configs), joined.Load())
	}
}

func TestBrowserStandbyDeadlineRollover(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.c.serve = func(ctx context.Context, _ sdk.ManagedBrowserStandbyConfig) error { <-ctx.Done(); return ctx.Err() }
	claims := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runtime-lease") {
			claims++
			if claims == 2 {
				f.cancel()
			}
			lease := f.lease()
			lease.ExpiresAt = time.Now().Add(30 * time.Millisecond)
			return browserBindingResponse(200, lease), true
		}
		return nil, false
	}
	f.c.now = time.Now
	f.c.wait = browserBindingWait
	f.run()
	if claims != 2 || !f.released || f.acks != 2 {
		t.Fatalf("rollover claims/acks: %d/%d", claims, f.acks)
	}
}
