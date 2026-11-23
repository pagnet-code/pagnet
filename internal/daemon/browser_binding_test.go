package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
)

type browserBindingTransport func(*http.Request) (*http.Response, error)

func (f browserBindingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func browserBindingResponse(code int, v any) *http.Response {
	raw, _ := json.Marshal(v)
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{}}
}

type browserBindingFixture struct {
	t           *testing.T
	c           *browserBindingController
	a           browserAssignment
	now         time.Time
	bindings    []browserBindingMetadata
	generations map[string]int64
	rotations   map[string]int
	acks        int
	released    bool
	cancel      context.CancelFunc
	hook        func(*http.Request) (*http.Response, bool)
}

func newBrowserBindingFixture(t *testing.T, count int) *browserBindingFixture {
	f := &browserBindingFixture{t: t, now: time.Now(), generations: map[string]int64{}, rotations: map[string]int{}}
	f.a = browserAssignment{ID: string(domain.NewID()), DesiredRevision: 3, RuntimeMode: "managed"}
	for i := 0; i < count; i++ {
		n := browserAssignmentNetwork{NetworkID: string(domain.NewID()), Grants: []string{}, MessagingTargets: []string{}, Events: []string{}}
		raw, _ := json.Marshal(n)
		sum := sha256.Sum256(raw)
		b := browserBindingMetadata{ID: string(domain.NewID()), PrincipalID: string(domain.NewID()), NetworkID: n.NetworkID, DesiredRevision: 3, PolicyFingerprint: hex.EncodeToString(sum[:])}
		f.a.Networks = append(f.a.Networks, n)
		f.bindings = append(f.bindings, b)
	}
	f.c = &browserBindingController{serverURL: "https://binding.invalid", instanceID: uuid.NewString(), now: func() time.Time { return f.now }, retryDelay: time.Millisecond, renewInterval: 10 * time.Second, slots: map[string]*browserBindingSlot{}}
	f.c.wait = func(ctx context.Context, d time.Duration) bool {
		if ctx.Err() != nil {
			return false
		}
		f.now = f.now.Add(d)
		return true
	}
	f.c.client = &http.Client{Transport: browserBindingTransport(f.handle)}
	return f
}
func (f *browserBindingFixture) lease() browserBindingLease {
	return browserBindingLease{Generation: 1, Active: true, ExpiresAt: f.now.Add(30 * time.Second), LeaseID: "00000000-0000-4000-8000-000000000001", InstanceID: f.c.instanceID}
}
func (f *browserBindingFixture) status(b browserBindingMetadata) browserBindingStatus {
	return browserBindingStatus{BindingID: b.ID, DesiredRevision: 3, AppliedRevision: 3, PolicyFingerprint: b.PolicyFingerprint, Acknowledged: true, CredentialExpiresAt: f.now.Add(30 * time.Second)}
}
func (f *browserBindingFixture) handle(r *http.Request) (*http.Response, error) {
	if f.hook != nil {
		if out, ok := f.hook(r); ok {
			return out, nil
		}
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/runtime-lease"):
		if r.Method == http.MethodDelete {
			f.released = true
			return browserBindingResponse(200, nil), nil
		}
		if r.Method == http.MethodGet {
			return browserBindingResponse(200, browserBindingLease{}), nil
		}
		return browserBindingResponse(200, f.lease()), nil
	case strings.HasSuffix(path, "/runtime-lease/renew"):
		return browserBindingResponse(200, f.lease()), nil
	case strings.HasSuffix(path, "/bindings/reconcile"):
		items := append([]browserBindingMetadata(nil), f.bindings...)
		for i := range items {
			items[i].CredentialGeneration = f.generations[items[i].ID]
		}
		return browserBindingResponse(200, map[string]any{"items": items}), nil
	case strings.HasSuffix(path, "/endpoint-credential"):
		for _, b := range f.bindings {
			if strings.Contains(path, b.ID) {
				var req struct {
					Expected int64 `json:"expectedCredentialGeneration"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.Expected != f.generations[b.ID] {
					f.t.Error("incorrect credential CAS")
					return browserBindingResponse(409, nil), nil
				}
				f.generations[b.ID]++
				f.rotations[b.ID]++
				return browserBindingResponse(200, map[string]any{"credentialId": string(domain.NewID()), "credentialGeneration": f.generations[b.ID], "credential": "private-test-value", "expiresAt": f.c.lease.ExpiresAt}), nil
			}
		}
	case strings.HasSuffix(path, "/apply-ack"):
		f.acks++
		for _, b := range f.bindings {
			if strings.Contains(path, b.ID) {
				if s := f.c.slots[b.NetworkID]; s == nil || len(s.secret) == 0 {
					f.t.Error("ack before private installation")
				}
				status := f.status(b)
				status.CredentialExpiresAt = f.c.lease.ExpiresAt
				return browserBindingResponse(200, status), nil
			}
		}
	case strings.HasSuffix(path, "/runtime-status"):
		statuses := []browserBindingStatus{}
		for _, b := range f.bindings {
			statuses = append(statuses, f.status(b))
		}
		return browserBindingResponse(200, map[string]any{"connectionId": f.a.ID, "desiredRevision": 3, "bindings": statuses, "acknowledged": true, "executionReady": false}), nil
	}
	f.t.Error("unexpected request")
	return browserBindingResponse(404, nil), nil
}
func (f *browserBindingFixture) run() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	defer cancel()
	f.c.runBrowserBinding(ctx, f.a)
}
func TestBrowserBindingClaimAmbiguity(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	claims := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-lease") && r.Method == http.MethodPost {
			claims++
			var req struct {
				Expected int64  `json:"expectedGeneration"`
				Instance string `json:"instanceId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Expected != 0 || req.Instance != f.c.instanceID {
				t.Error("claim tuple changed")
			}
			if claims == 1 {
				return browserBindingResponse(503, nil), true
			}
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") {
			f.cancel()
			return browserBindingResponse(409, nil), true
		}
		return nil, false
	}
	f.run()
	if claims != 2 || f.acks != 1 {
		t.Fatalf("claims=%d acks=%d", claims, f.acks)
	}
}
func TestBrowserBindingStaleRevision(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/bindings/reconcile") {
			return browserBindingResponse(409, nil), true
		}
		return nil, false
	}
	f.run()
	if f.acks != 0 || !f.released {
		t.Fatal("stale revision acknowledged or lease not released")
	}
}
func TestBrowserBindingLostCredential(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	lost := false
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/endpoint-credential") && !lost {
			lost = true
			f.generations[f.bindings[0].ID]++
			return browserBindingResponse(503, nil), true
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") {
			f.cancel()
			return browserBindingResponse(409, nil), true
		}
		return nil, false
	}
	f.run()
	if f.generations[f.bindings[0].ID] != 2 || f.acks != 1 {
		t.Fatal("lost issuance was not recovered by CAS rotation")
	}
}
func TestBrowserBindingTwoNetworksDisconnectWipe(t *testing.T) {
	f := newBrowserBindingFixture(t, 2)
	var copies [][]byte
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") {
			for _, slot := range f.c.slots {
				copies = append(copies, slot.secret)
			}
			f.cancel()
			return browserBindingResponse(409, nil), true
		}
		if r.Method == http.MethodDelete {
			for _, slot := range f.c.slots {
				if len(slot.secret) != 0 {
					t.Error("release before wipe")
				}
			}
		}
		return nil, false
	}
	f.run()
	if f.acks != 2 || !f.released || len(f.c.slots) != 0 {
		t.Fatal("incomplete cleanup")
	}
	for _, raw := range copies {
		for _, b := range raw {
			if b != 0 {
				t.Fatal("secret memory retained")
			}
		}
	}
}
func TestBrowserBindingRenewRefreshAffected(t *testing.T) {
	f := newBrowserBindingFixture(t, 2)
	statuses := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-status") {
			statuses++
			if statuses > 1 {
				f.cancel()
				return browserBindingResponse(409, nil), true
			}
			first := f.status(f.bindings[0])
			first.CredentialRefreshRequired = true
			first.Acknowledged = false
			first.AppliedRevision = 0
			second := f.status(f.bindings[1])
			return browserBindingResponse(200, map[string]any{"connectionId": f.a.ID, "desiredRevision": 3, "bindings": []browserBindingStatus{first, second}}), true
		}
		return nil, false
	}
	f.run()
	if f.rotations[f.bindings[0].ID] != 2 || f.rotations[f.bindings[1].ID] != 1 {
		t.Fatal("renewal rotated unaffected binding")
	}
}
func TestBrowserBindingSecretRedaction(t *testing.T) {
	slot := &browserBindingSlot{secret: []byte("private-test-value")}
	for _, out := range []string{fmt.Sprint(slot), fmt.Sprintf("%+v", slot), fmt.Sprintf("%#v", slot), fmt.Sprintf("%+v", *slot), fmt.Sprintf("%#v", *slot), fmt.Sprintf("%#v", []browserBindingSlot{*slot})} {
		if strings.Contains(out, "private-test-value") || strings.Contains(out, "112") {
			t.Fatal("secret exposed")
		}
	}
	raw, _ := json.Marshal(slot)
	if string(raw) != "{}" {
		t.Fatal("slot serialized")
	}
	slot.wipe()
}
func TestBrowserBindingRejectsWrongPolicy(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.bindings[0].PolicyFingerprint = strings.Repeat("0", 64)
	f.run()
	if f.acks != 0 {
		t.Fatal("acknowledged different policy")
	}
}

func TestBrowserBindingReacquiresAfterExpiry(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	claims := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-lease") && r.Method == http.MethodPost {
			claims++
			if claims == 2 {
				f.cancel()
				return browserBindingResponse(403, nil), true
			}
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") {
			return browserBindingResponse(503, nil), true
		}
		return nil, false
	}
	f.c.retryDelay = 5 * time.Second
	f.run()
	if claims != 2 || !f.released || len(f.c.slots) != 0 {
		t.Fatal("expired lease did not recover and cancel cleanly")
	}
}
func TestBrowserBindingLostAckRetriesExact(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	var first string
	attempts := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/apply-ack") {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
			attempts++
			if attempts == 1 {
				first = string(raw)
				return browserBindingResponse(503, nil), true
			}
			if first != string(raw) {
				t.Error("ack tuple changed")
			}
		}
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") {
			f.cancel()
			return browserBindingResponse(409, nil), true
		}
		return nil, false
	}
	f.run()
	if attempts != 2 || f.rotations[f.bindings[0].ID] != 1 {
		t.Fatal("ack retry rotated credential")
	}
}
func TestBrowserBindingStatusCannotOutliveCredential(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	statuses := 0
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/runtime-status") {
			statuses++
			f.now = f.now.Add(25 * time.Second)
			f.cancel()
			return browserBindingResponse(200, map[string]any{}), true
		}
		return nil, false
	}
	f.run()
	if statuses != 1 || len(f.c.slots) != 0 {
		t.Fatal("expired status retained credentials")
	}
}

func TestBrowserBindingControllerRedaction(t *testing.T) {
	c := browserBindingController{credential: "private-host-value", slots: map[string]*browserBindingSlot{"network": {secret: []byte("private-test-value")}}}
	for _, v := range []any{c, &c, []browserBindingController{c}} {
		out := fmt.Sprintf("%#v %+v", v, v)
		if strings.Contains(out, "private-") {
			t.Fatal("controller exposed credential")
		}
	}
}
func TestBrowserBindingRejectsExecutionReady(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if strings.HasSuffix(r.URL.Path, "/apply-ack") {
			status := f.status(f.bindings[0])
			status.ExecutionReady = true
			return browserBindingResponse(200, status), true
		}
		return nil, false
	}
	f.run()
	if !f.released || len(f.c.slots) != 0 {
		t.Fatal("execution-ready response retained authority")
	}
}

func TestBrowserBindingCompetingLeaseWaitBounded(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	f.hook = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/runtime-lease") {
			return browserBindingResponse(200, browserBindingLease{Generation: 9, Active: true, ExpiresAt: f.now.Add(time.Hour)}), true
		}
		return nil, false
	}
	waits := 0
	f.c.wait = func(_ context.Context, delay time.Duration) bool {
		waits++
		if delay <= 0 || delay > 30*time.Second {
			t.Fatalf("competing lease wait out of bounds: %v", delay)
		}
		return false
	}
	if f.c.claim(context.Background(), "/connection") || waits != 1 {
		t.Fatal("competing holder was claimed or did not wait")
	}
}

func TestBrowserBindingLeaseHolderWireSchema(t *testing.T) {
	f := newBrowserBindingFixture(t, 1)
	renewals, releases := 0, 0
	f.c.client.Transport = browserBindingTransport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/runtime-lease/renew") || r.Method == http.MethodDelete {
			// The server rejects unknown request fields. In particular the
			// binding-only expectedDesiredRevision must never reach this API.
			var holder struct {
				InstanceID string `json:"instanceId"`
				LeaseID    string `json:"leaseId"`
				Generation int64  `json:"generation"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&holder); err != nil {
				t.Fatalf("invalid lease-holder request schema: %v", err)
			}
			if holder.InstanceID != f.c.instanceID || holder.LeaseID != f.lease().LeaseID || holder.Generation != 1 {
				t.Fatal("lease-holder request changed the confirmed tuple")
			}
			if r.Method == http.MethodDelete {
				releases++
			} else {
				renewals++
				f.cancel()
			}
		}
		return f.handle(r)
	})
	f.run()
	if renewals != 1 || releases != 1 {
		t.Fatalf("expected one renewal and release, got %d and %d", renewals, releases)
	}
}
