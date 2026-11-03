package textbridge

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
)

type claimHookLedger struct {
	Ledger
	afterClaim func()
}

func (s claimHookLedger) ClaimProvider(ctx context.Context, job ledger.Job, now time.Time) (ledger.Job, string, error) {
	claimed, token, err := s.Ledger.ClaimProvider(ctx, job, now)
	if err == nil {
		s.afterClaim()
	}
	return claimed, token, err
}

func TestDispatchGateHoldsThroughEffectsAndDeduplicates(t *testing.T) {
	b, s, tr, p, m := setup(t)
	inside := false
	var actions []DispatchAction
	b.config.DispatchGate = func(ctx context.Context, action DispatchAction, scope DispatchScope, dispatch func() error) error {
		if scope != (DispatchScope{"project", "ask", "fixed-owner-config"}) {
			t.Fatalf("scope=%+v", scope)
		}
		inside = true
		defer func() { inside = false }()
		actions = append(actions, action)
		return dispatch()
	}
	check := func() {
		if !inside {
			t.Fatal("side effect escaped gate")
		}
	}
	b.store = claimHookLedger{Ledger: s, afterClaim: check}
	p.complete = func() (string, error) { check(); return "answer", nil }
	tr.onPrepare, tr.onSend = check, check
	accept(t, b, m)
	accept(t, b, m)
	process(t, b, s)
	process(t, b, s)
	if stored(t, s).Phase != ledger.Admitted || p.calls != 1 || tr.prepares != 1 || tr.sends != 1 || len(actions) != 3 || actions[0] != DispatchProvider || actions[1] != DispatchPrepareReply || actions[2] != DispatchSendReply {
		t.Fatalf("actions=%v calls=%d prepares=%d sends=%d", actions, p.calls, tr.prepares, tr.sends)
	}
}

func TestDispatchGateRechecksBeforeClaim(t *testing.T) {
	for _, change := range []string{"disable", "revoke", "fingerprint", "project", "deny"} {
		t.Run(change, func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			accept(t, b, m)
			b.config.DispatchGate = func(ctx context.Context, action DispatchAction, scope DispatchScope, dispatch func() error) error {
				switch change {
				case "disable":
					b.config.Enabled = func(string) bool { return false }
				case "revoke":
					if _, err := s.Revoke(ctx, stored(t, s)); err != nil {
						t.Fatal(err)
					}
				case "fingerprint":
					b.config.ProviderConfigFingerprint = "replacement"
				case "project":
					tr.status.State = "closed"
				case "deny":
					return nil
				}
				return dispatch()
			}
			process(t, b, s)
			budget, err := s.BudgetSnapshot(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if stored(t, s).Phase != ledger.Queued || p.calls != 0 || tr.prepares != 0 || budget.Used != 0 {
				t.Fatal("denied job consumed a claim or dispatched")
			}
		})
	}
}

func TestDispatchGateDenialAfterClaimRetainsReservation(t *testing.T) {
	for _, change := range []string{"disable", "revoke", "fingerprint"} {
		t.Run(change, func(t *testing.T) {
			b, s, tr, p, m := setup(t)
			accept(t, b, m)
			b.config.DispatchGate = func(_ context.Context, _ DispatchAction, _ DispatchScope, dispatch func() error) error {
				return dispatch()
			}
			b.store = claimHookLedger{Ledger: s, afterClaim: func() {
				switch change {
				case "disable":
					b.config.Enabled = func(string) bool { return false }
				case "revoke":
					if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
						t.Fatal(err)
					}
				case "fingerprint":
					b.config.ProviderConfigFingerprint = "replacement"
				}
			}}
			process(t, b, s)
			b.config.Enabled = func(string) bool { return true }
			b.config.ProviderConfigFingerprint = "fixed-owner-config"
			process(t, b, s)
			budget, err := s.BudgetSnapshot(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if stored(t, s).Phase != ledger.ProviderStarted || budget.Used != 1 || len(budget.Active) != 1 || p.calls != 0 || tr.prepares != 0 {
				t.Fatal("post-claim denial replayed or refunded reservation")
			}
		})
	}
}

func TestDispatchGateRevokedDuringProviderDoesNotReply(t *testing.T) {
	b, s, tr, p, m := setup(t)
	var enabled atomic.Bool
	enabled.Store(true)
	b.config.Enabled = func(string) bool { return enabled.Load() }
	b.config.DispatchGate = func(_ context.Context, _ DispatchAction, _ DispatchScope, dispatch func() error) error {
		return dispatch()
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	p.complete = func() (string, error) { close(started); <-release; return "answer", nil }
	accept(t, b, m)
	job := stored(t, s)
	go func() { done <- b.process(testContext, job) }()
	<-started
	enabled.Store(false)
	if _, err := s.Revoke(testContext, stored(t, s)); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 || tr.prepares != 0 || tr.sends != 0 || stored(t, s).Phase != ledger.OutputReady {
		t.Fatal("revoked provider output reached reply")
	}
}

func TestDispatchGateRechecksPreparedReplyAndReconcilesReceipt(t *testing.T) {
	b, s, tr, p, m := setup(t)
	replyPrepared(t, b, s, tr, m)
	b.config.DispatchGate = func(ctx context.Context, action DispatchAction, _ DispatchScope, dispatch func() error) error {
		if action != DispatchSendReply {
			t.Fatal(action)
		}
		if _, err := s.Revoke(ctx, stored(t, s)); err != nil {
			t.Fatal(err)
		}
		return dispatch()
	}
	process(t, b, s)
	if tr.sends != 0 || p.calls != 0 || stored(t, s).Phase != ledger.ReplyPrepared {
		t.Fatal("revoked prepared reply sent")
	}
	tr.receiptErr = nil
	tr.receipt = receiptFor(tr.prepared.ID, tr.prepared.Wire)
	b.config.DispatchGate = func(context.Context, DispatchAction, DispatchScope, func() error) error {
		t.Fatal("receipt reconciliation entered dispatch gate")
		return nil
	}
	process(t, b, s)
	if stored(t, s).Phase != ledger.Admitted || tr.sends != 0 {
		t.Fatal("receipt did not reconcile without sending")
	}
}

func TestDispatchGateLegacyNilPreservesDispatch(t *testing.T) {
	b, s, tr, p, m := setup(t)
	accept(t, b, m)
	accept(t, b, m)
	process(t, b, s)
	process(t, b, s)
	if stored(t, s).Phase != ledger.Admitted || p.calls != 1 || tr.prepares != 1 || tr.sends != 1 {
		t.Fatal("legacy dispatch changed")
	}
}

func TestDispatchGateHoldsPolicyLockDuringProvider(t *testing.T) {
	b, s, tr, p, m := setup(t)
	var policy sync.Mutex
	enabled := true
	b.config.DispatchGate = func(_ context.Context, action DispatchAction, _ DispatchScope, dispatch func() error) error {
		policy.Lock()
		defer policy.Unlock()
		if !enabled || action != DispatchProvider {
			return nil
		}
		return dispatch()
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	p.complete = func() (string, error) { close(started); <-release; return "answer", nil }
	accept(t, b, m)
	job := stored(t, s)
	go func() { done <- b.process(testContext, job) }()
	<-started
	attempting, revoked := make(chan struct{}), make(chan struct{})
	go func() {
		close(attempting)
		policy.Lock()
		enabled = false
		policy.Unlock()
		close(revoked)
	}()
	<-attempting
	select {
	case <-revoked:
		t.Fatal("policy changed while provider gate held")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-revoked
	if p.calls != 1 || tr.prepares != 0 || tr.sends != 0 {
		t.Fatal("provider gate or reply denial failed")
	}
}

func TestDispatchGateRechecksBeforeReplyPreparation(t *testing.T) {
	b, s, tr, p, m := setup(t)
	outputReady(t, b, s, m)
	b.config.DispatchGate = func(ctx context.Context, action DispatchAction, _ DispatchScope, dispatch func() error) error {
		if action != DispatchPrepareReply {
			t.Fatal(action)
		}
		if _, err := s.Revoke(ctx, stored(t, s)); err != nil {
			t.Fatal(err)
		}
		return dispatch()
	}
	process(t, b, s)
	if stored(t, s).Phase != ledger.OutputReady || p.calls != 0 || tr.prepares != 0 || tr.sends != 0 {
		t.Fatal("revoked output prepared a reply")
	}
}
