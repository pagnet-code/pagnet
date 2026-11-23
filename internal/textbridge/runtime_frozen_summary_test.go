package textbridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/sdk"
)

const runtimeSummaryProject = "76c06585-246a-429e-92da-1b9cb420ce47"

func runtimeSummaryFixture(t *testing.T, expired bool) (string, Profile, *ledger.Store, *runtimeConnection, FrozenSummaryApproval, string) {
	t.Helper()
	dir, p, store, conn := runtimeFixture(t)
	source := filepath.Join(dir, "instructions")
	if err := os.WriteFile(source, []byte("captured owner instructions"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	expiry := now.Add(time.Hour)
	if expired {
		now = now.Add(-2 * time.Hour)
		expiry = now.Add(time.Hour)
	}
	a, err := CreateFrozenSummaryApproval(dir, FrozenSummaryInput{Profile: p, ProjectIDs: []string{runtimeSummaryProject}, InstructionFile: source, CallsPerDay: p.Limits.CallsPerDay, ExpiresAt: expiry}, now)
	if err != nil {
		t.Fatal(err)
	}
	p.FrozenSummaryApprovalID = a.ID
	if err := os.Remove(filepath.Join(dir, "profile.json")); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	return dir, p, store, conn, a, source
}

func runtimeSummaryConfig(t *testing.T, dir string, p Profile, conn *runtimeConnection, client Provider, instructions string) RuntimeConfig {
	t.Helper()
	config := runtimeConfig(t, dir, p, conn, client)
	config.Connect = func(_ context.Context, c sdk.Config) (RuntimeConnection, error) {
		if c.Server != p.Server || c.Credential != p.Credential || c.ExpectedPrincipalID != p.Service || c.StateDir != filepath.Join(dir, "sdk") {
			t.Error("snapshot runtime lost endpoint binding")
		}
		return conn, nil
	}
	config.NewProvider = func(provider.Config) (Provider, error) {
		t.Error("selected runtime called generic provider factory")
		return client, nil
	}
	config.NewSnapshotProvider = func(c provider.Config, captured string) (Provider, error) {
		if c.BaseURL != p.ProviderOrigin || c.Model != p.Model || c.APIKey != "provider-secret" || captured != instructions {
			t.Error("snapshot factory lost captured provider configuration or instructions")
		}
		return client, nil
	}
	config.Enabled = func(string) bool { return true }
	return config
}

func TestRunProfileFrozenSummaryRejectsInactiveStartup(t *testing.T) {
	for _, change := range []string{"missing approval", "expired approval", "disabled approval", "disabled saved profile", "changed saved provider", "missing saved profile"} {
		t.Run(change, func(t *testing.T) {
			dir, p, store, conn, a, _ := runtimeSummaryFixture(t, change == "expired approval")
			switch change {
			case "missing approval":
				if err := os.Remove(filepath.Join(dir, "frozen-summaries", a.ID+".json")); err != nil {
					t.Fatal(err)
				}
			case "disabled approval":
				if err := DisableFrozenSummaryApproval(dir, a.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled saved profile", "changed saved provider":
				current := p
				if change == "disabled saved profile" {
					current.Disabled = true
				} else {
					current.Model = "changed"
				}
				if err := SaveProfile(dir, current); err != nil {
					t.Fatal(err)
				}
			case "missing saved profile":
				if err := os.Remove(filepath.Join(dir, "profile.json")); err != nil {
					t.Fatal(err)
				}
			}
			config := runtimeSummaryConfig(t, dir, p, conn, &fakeProvider{}, a.Instructions)
			config.NewSnapshotProvider = func(provider.Config, string) (Provider, error) {
				t.Error("inactive approval reached snapshot factory")
				return &fakeProvider{}, nil
			}
			config.Connect = func(context.Context, sdk.Config) (RuntimeConnection, error) {
				t.Error("inactive approval reached connection")
				return conn, boundaryError
			}
			if err := RunProfile(context.Background(), dir, p, store, config); err == nil {
				t.Fatal("inactive approval started runtime")
			}
			if conn.message != nil || conn.ready != nil {
				t.Fatal("inactive approval installed callbacks")
			}
		})
	}
}

func runtimeSummaryAsk(project string) sdk.SharingProjectMessage {
	return sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{ProjectID: project, ID: "ask", Kind: "ASK", SenderPrincipalID: "sender"}, Plaintext: []byte("question"), Wire: []byte("authenticated wire")}
}

func TestRunProfileFrozenSummaryUsesCapturedInstructionsAndFingerprint(t *testing.T) {
	dir, p, store, conn, a, source := runtimeSummaryFixture(t, false)
	plan, err := ResolveFrozenSummary(dir, a.ID, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("changed source is never reread"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &fakeProvider{complete: func() (string, error) {
		disableCtx, disableCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer disableCancel()
		if err := DisableProfile(disableCtx, dir, p.Service); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("provider call did not hold policy lock: %v", err)
		}
		cancel()
		return "answer", nil
	}}
	conn.Transport = &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: runtimeSummaryProject, State: "active", EndpointProved: true}}
	config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
	conn.onReady = func() {
		lockCtx, lockCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer lockCancel()
		unlock, err := LockProfilePolicy(lockCtx, dir)
		if unlock != nil {
			unlock()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("callback registration did not hold policy lock: %v", err)
		}
		if err := conn.message(context.Background(), runtimeSummaryAsk(runtimeSummaryProject)); err != nil {
			t.Error(err)
		}
		conn.ready(runtimeSummaryProject)
	}
	if err := RunProfile(ctx, dir, p, store, config); err != nil {
		t.Fatal(err)
	}
	job, err := store.Get(context.Background(), runtimeSummaryProject, "ask")
	if err != nil || job.Data.ProviderConfigFingerprint != plan.Fingerprint() || job.Data.ProviderConfigFingerprint == p.Fingerprint || client.calls != 1 || job.Phase != ledger.OutputReady {
		t.Fatalf("snapshot dispatch lost approval binding: phase=%s calls=%d err=%v", job.Phase, client.calls, err)
	}
}

func TestRunProfileFrozenSummaryFencesQueuedWork(t *testing.T) {
	for _, change := range []string{"changed key", "changed saved provider", "disabled profile", "disabled approval", "unapproved project", "wrong fingerprint", "readiness closed"} {
		t.Run(change, func(t *testing.T) {
			dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
			client := &fakeProvider{}
			project := runtimeSummaryProject
			if change == "unapproved project" {
				project = "c280dbe7-48af-4635-823c-f2444660a05c"
			}
			tr := &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: project, State: "active", EndpointProved: true}}
			conn.Transport = tr
			config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
			ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
			defer cancel()
			var ready atomic.Bool
			config.Enabled = func(string) bool { return ready.Load() }
			registered := make(chan struct{})
			changed := make(chan struct{})
			conn.onReady = func() {
				if change == "wrong fingerprint" {
					message := runtimeSummaryAsk(project)
					header, _ := json.Marshal(message.Header)
					if _, err := store.Insert(context.Background(), project, "ask", ledger.Data{Header: header, PredecessorWire: message.Wire, WireDigest: digest(message.Wire), Input: message.Plaintext, ProviderConfigFingerprint: p.Fingerprint}); err != nil {
						t.Error(err)
					}
				} else if err := conn.message(context.Background(), runtimeSummaryAsk(project)); err != nil {
					t.Error(err)
				}
				close(registered)
			}
			go func() {
				defer close(changed)
				select {
				case <-registered:
				case <-ctx.Done():
					return
				}
				// Wait for startup to release the policy lock after registering
				// callbacks. Dispatch remains fenced until the mutation finishes.
				unlock, err := LockProfilePolicy(ctx, dir)
				if err != nil {
					t.Error(err)
					return
				}
				unlock()
				switch change {
				case "changed key":
					if err := os.WriteFile(p.KeyFile, []byte("changed-key"), 0600); err != nil {
						t.Error(err)
					}
				case "changed saved provider", "disabled profile":
					current := p
					if change == "disabled profile" {
						current.Disabled = true
					} else {
						current.Model = "changed"
					}
					if err := SaveProfile(dir, current); err != nil {
						t.Error(err)
					}
				case "disabled approval":
					if err := DisableFrozenSummaryApproval(dir, a.ID); err != nil {
						t.Error(err)
					}
				}
				ready.Store(change != "readiness closed")
				conn.ready(project)
			}()
			err := RunProfile(ctx, dir, p, store, config)
			runtimeAwait(t, changed, "queued policy mutation did not finish")
			if err != nil {
				t.Fatal(err)
			}
			job, err := store.Get(context.Background(), project, "ask")
			if err != nil || job.Phase != ledger.Queued || client.calls != 0 || tr.prepares != 0 || tr.sends != 0 {
				t.Fatalf("ineligible queued work dispatched: phase=%s calls=%d err=%v", job.Phase, client.calls, err)
			}
			budget, err := store.BudgetSnapshot(context.Background())
			if err != nil || budget.Used != 0 || len(budget.Active) != 0 {
				t.Fatal("ineligible work consumed provider budget")
			}
		})
	}
}

func TestRunProfileFrozenSummaryRetirementFencesPreparedReply(t *testing.T) {
	dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
	client := &fakeProvider{}
	tr := &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: runtimeSummaryProject, State: "active", EndpointProved: true}, receiptErr: boundaryError}
	tr.onReceipt = func() {
		if err := DisableFrozenSummaryApproval(dir, a.ID); err != nil {
			t.Error(err)
		}
	}
	conn.Transport = tr
	config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
	conn.onReady = func() {
		if err := conn.message(context.Background(), runtimeSummaryAsk(runtimeSummaryProject)); err != nil {
			t.Error(err)
		}
		conn.ready(runtimeSummaryProject)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := RunProfile(ctx, dir, p, store, config); err != nil {
		t.Fatal(err)
	}
	job, err := store.Get(context.Background(), runtimeSummaryProject, "ask")
	if err != nil || job.Phase != ledger.ReplyPrepared || client.calls != 1 || tr.prepares != 1 || tr.receipts == 0 || tr.sends != 0 {
		t.Fatalf("retirement did not fence prepared reply: phase=%s calls=%d prepares=%d receipts=%d sends=%d err=%v", job.Phase, client.calls, tr.prepares, tr.receipts, tr.sends, err)
	}
}

func TestRunProfileFrozenSummaryFactoryFailureDoesNotFallback(t *testing.T) {
	dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
	config := runtimeSummaryConfig(t, dir, p, conn, &fakeProvider{}, a.Instructions)
	calls := 0
	config.NewSnapshotProvider = func(provider.Config, string) (Provider, error) {
		calls++
		return nil, boundaryError
	}
	config.Connect = func(context.Context, sdk.Config) (RuntimeConnection, error) {
		t.Error("snapshot factory failure reached connection")
		return nil, boundaryError
	}
	if err := RunProfile(context.Background(), dir, p, store, config); err == nil || calls != 1 {
		t.Fatalf("snapshot factory failure was ignored: calls=%d err=%v", calls, err)
	}
}

func TestRunProfileFrozenSummaryDisableDuringConnect(t *testing.T) {
	dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
	client := &fakeProvider{}
	tr := &fakeTransport{}
	conn.Transport = tr
	config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
	connecting := make(chan struct{})
	release := make(chan struct{})
	config.Connect = func(context.Context, sdk.Config) (RuntimeConnection, error) {
		close(connecting)
		<-release
		return conn, nil
	}
	config.Authorize = func(context.Context, RuntimeConnection) error {
		t.Error("profile disabled during connect reached authorization")
		return boundaryError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- RunProfile(ctx, dir, p, store, config) }()
	runtimeAwait(t, connecting, "runtime did not reach blocked connect")
	if err := DisableProfile(context.Background(), dir, p.Service); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("profile disabled during connect started runtime")
		}
	case <-ctx.Done():
		t.Fatal("runtime did not reject profile disabled during connect")
	}
	if conn.message != nil || conn.ready != nil || client.calls != 0 {
		t.Fatal("profile disabled during connect installed callbacks or dispatched")
	}
	runtimeAwait(t, conn.closed, "runtime did not close disabled connection")
}

func TestRunProfileFrozenSummaryRevalidatesAfterBlockedStatus(t *testing.T) {
	for _, change := range []string{"expiry", "key rotation"} {
		t.Run(change, func(t *testing.T) {
			dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
			if change == "expiry" {
				a.ExpiresAt = time.Now().Add(750 * time.Millisecond)
				if err := SavePrivateJSON(filepath.Join(dir, "frozen-summaries"), a.ID+".json", a); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client := &fakeProvider{complete: func() (string, error) { cancel(); return "answer", nil }}
			tr := &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: runtimeSummaryProject, State: "active", EndpointProved: true}}
			blocked := make(chan struct{})
			release := make(chan struct{})
			statusCalls := 0
			tr.onStatus = func() {
				statusCalls++
				// The second status lookup runs inside DispatchGate, after its
				// initial policy validation and while policy.lock is held.
				if statusCalls == 2 {
					close(blocked)
					<-release
				}
			}
			conn.Transport = tr
			config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
			config.OnError = func(error) { cancel() }
			conn.onReady = func() {
				if err := conn.message(context.Background(), runtimeSummaryAsk(runtimeSummaryProject)); err != nil {
					t.Error(err)
				}
				conn.ready(runtimeSummaryProject)
			}
			result := make(chan error, 1)
			go func() { result <- RunProfile(ctx, dir, p, store, config) }()
			runtimeAwait(t, blocked, "runtime did not reach status lookup inside dispatch gate")
			if change == "expiry" {
				<-time.After(time.Until(a.ExpiresAt) + 20*time.Millisecond)
			} else if err := os.WriteFile(p.KeyFile, []byte("externally-rotated-key"), 0600); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("runtime did not finish after blocked status was released")
			}
			if client.calls != 0 || tr.prepares != 0 || tr.sends != 0 {
				t.Fatal("policy changed during status lookup reached a side effect")
			}
			budget, err := store.BudgetSnapshot(context.Background())
			if err != nil || budget.Used != 0 || len(budget.Active) != 0 {
				t.Fatal("policy changed during status lookup consumed provider budget")
			}
		})
	}
}

func TestRunProfileFrozenSummaryDisableDuringProviderSuppressesReply(t *testing.T) {
	dir, p, store, conn, a, _ := runtimeSummaryFixture(t, false)
	entered := make(chan struct{})
	release := make(chan struct{})
	disabled := make(chan struct{})
	disableResult := make(chan error, 1)
	denied := make(chan error, 1)
	var completed atomic.Bool
	client := &fakeProvider{complete: func() (string, error) {
		close(entered)
		<-release
		completed.Store(true)
		return "answer", nil
	}}
	tr := &fakeTransport{store: store, status: sdk.SharingProjectStatus{ProjectID: runtimeSummaryProject, State: "active", EndpointProved: true}}
	// The first status lookup after provider success runs before the next gate.
	// Let the waiting disable commit there, without canceling the runtime.
	tr.onStatus = func() {
		if completed.Load() {
			<-disabled
		}
	}
	conn.Transport = tr
	config := runtimeSummaryConfig(t, dir, p, conn, client, a.Instructions)
	config.OnError = func(err error) {
		select {
		case denied <- err:
		default:
		}
	}
	conn.onReady = func() {
		if err := conn.message(context.Background(), runtimeSummaryAsk(runtimeSummaryProject)); err != nil {
			t.Error(err)
		}
		conn.ready(runtimeSummaryProject)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- RunProfile(ctx, dir, p, store, config) }()
	runtimeAwait(t, entered, "provider did not start")
	go func() {
		disableResult <- DisableProfile(ctx, dir, p.Service)
		close(disabled)
	}()
	probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Millisecond)
	unlock, err := LockProfilePolicy(probeCtx, dir)
	probeCancel()
	if unlock != nil {
		unlock()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("provider did not retain policy lock: %v", err)
	}
	select {
	case <-disabled:
		t.Error("disable completed while provider held policy lock")
	default:
	}
	close(release)
	runtimeAwait(t, disabled, "disable did not complete after provider returned")
	if err := <-disableResult; err != nil {
		t.Fatal(err)
	}
	select {
	case <-denied:
	case <-ctx.Done():
		t.Fatal("disabled policy did not reject reply preparation")
	}
	if ctx.Err() != nil {
		t.Fatal("reply fence depended on cancellation")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	job, err := store.Get(context.Background(), runtimeSummaryProject, "ask")
	if err != nil || job.Phase != ledger.OutputReady || client.calls != 1 || tr.prepares != 0 || tr.sends != 0 {
		t.Fatalf("disabled responder replied after success: phase=%s calls=%d prepares=%d sends=%d err=%v", job.Phase, client.calls, tr.prepares, tr.sends, err)
	}
}
