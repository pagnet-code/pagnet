//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type settledBridgeDriver struct {
	session.Driver
	live atomic.Bool
}

func (d *settledBridgeDriver) Live(string) bool { return d.live.Load() }

func settledBridgeFixture(t *testing.T) (*SessionOwner, BridgeCall, int64) {
	t.Helper()
	j, _ := testJournal(t)
	l := lease(t, j)
	spec := NativeSpec{NetworkID: "fixed-network", TenantID: j.scope.TenantID, Kind: "worker"}
	owner := &SessionOwner{journal: j, manager: session.NewManager(), generation: "original-generation", origin: json.RawMessage(`{"original":"immutable"}`), spec: spec, relay: newRelayBroker(j.scope, spec)}
	driver := &settledBridgeDriver{}
	driver.live.Store(true)
	owner.driver = driver
	sess := owner.manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	sess.NativeID = "original-session"
	owner.manager.ObserveNativeActivity(sess.InstanceID, session.SessionEvent{Type: session.EventIdle})
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: owner.generation, NativeSessionID: sess.NativeID, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: "notice"}
	if _, _, err := j.Admit(t.Context(), l, 1, source.SourceCommandID, "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.BindNativeTurn(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`UPDATE worker_turn_sources SET started=1 WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	owner.candidateTurnSource = source
	owner.relay.bindLease(l)
	owner.relay.bindNative(owner.generation)
	if err := owner.relay.admit(l, Admission{Scope: j.scope, TenantID: spec.TenantID, NetworkID: spec.NetworkID, Kind: spec.Kind, NativeAdmissionID: "current-admission", RunnerID: "current-runner", RunnerEpoch: time.Now(), BootID: "current-boot"}); err != nil {
		t.Fatal(err)
	}
	return owner, BridgeCall{Scope: j.scope, NativeGeneration: owner.generation, NativeSessionID: sess.NativeID, Origin: append(json.RawMessage(nil), owner.origin...), Tool: "network_task_get", Args: json.RawMessage(`{"taskId":"known-task"}`), TurnSource: &source}, l
}
func pollSettledBridge(t *testing.T, o *SessionOwner, l int64) *BridgeCall {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		call, err := o.relay.poll(l)
		if err != nil {
			t.Fatal(err)
		}
		if call != nil {
			return call
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("original relay was not enqueued")
	return nil
}
func finishSettledFixture(t *testing.T, o *SessionOwner) {
	t.Helper()
	if _, err := o.journal.db.Exec(`UPDATE worker_turn_sources SET completed=1 WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	if err := o.journal.Settle(t.Context(), 1, "completed", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
}
func TestBridgeSampledNonTaskSettlementRefreshesOnceWithFreshCorrelation(t *testing.T) {
	for _, again := range []bool{false, true} {
		t.Run(map[bool]string{false: "successful_endpoint", true: "second_refusal_is_final"}[again], func(t *testing.T) {
			o, call, l := settledBridgeFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan BridgeResult, 1)
			go func() { done <- o.forwardBridgeCall(ctx, call) }()
			first := pollSettledBridge(t, o, l)
			if first.TurnSource == nil || first.TurnSource.InputKind != "notice" {
				t.Fatal("did not sample actual running notice")
			}
			finishSettledFixture(t, o)
			if err := o.relay.complete(l, BridgeResult{ID: first.ID, Error: "not applied", ErrorCode: "source_settled", Retryable: true}); err != nil {
				t.Fatal(err)
			}
			second := pollSettledBridge(t, o, l)
			if !o.bridgeSourceMu.TryLock() {
				t.Fatal("retry held admission fence while awaiting network")
			}
			o.bridgeSourceMu.Unlock()
			if second.ID == first.ID || second.TurnSource != nil || second.Scope != first.Scope || second.NativeGeneration != first.NativeGeneration || second.NativeSessionID != first.NativeSessionID || !bytes.Equal(second.Origin, first.Origin) || !bytes.Equal(second.Args, first.Args) || second.Tool != first.Tool {
				t.Fatal("retry changed original endpoint scope or reused correlation")
			}
			reply := BridgeResult{ID: second.ID, OK: true, Result: json.RawMessage(`{"safe":true}`)}
			if again {
				reply = BridgeResult{ID: second.ID, Error: "not applied", ErrorCode: "source_settled", Retryable: true}
			}
			if err := o.relay.complete(l, reply); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.OK == again {
				t.Fatal("wrong bounded endpoint result")
			}
			if extra, err := o.relay.poll(l); err != nil || extra != nil {
				t.Fatal("refusal retried more than once")
			}
			var intents int
			if err := o.journal.db.QueryRow(`SELECT COUNT(*) FROM worker_intent`).Scan(&intents); err != nil || intents != 1 {
				t.Fatal("tool refresh synthesized native intent")
			}
		})
	}
}
func TestBridgeSettledRefusalCannotBroadenMissingUncertainOrTaskAuthority(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *SessionOwner, *BridgeCall, *BridgeResult)
	}{
		{"generic_failure", func(_ *testing.T, _ *SessionOwner, _ *BridgeCall, r *BridgeResult) { r.ErrorCode = "" }},
		{"not_retryable", func(_ *testing.T, _ *SessionOwner, _ *BridgeCall, r *BridgeResult) { r.Retryable = false }},
		{"ambiguous_result", func(_ *testing.T, _ *SessionOwner, _ *BridgeCall, r *BridgeResult) { r.Result = json.RawMessage(`{}`) }},
		{"task", func(_ *testing.T, _ *SessionOwner, c *BridgeCall, _ *BridgeResult) { c.TurnSource.InputKind = "task" }},
		{"task_binding", func(_ *testing.T, _ *SessionOwner, c *BridgeCall, _ *BridgeResult) {
			c.TurnSource.SourceTask = &transport.NativeTaskSource{}
		}},
		{"foreign_session", func(_ *testing.T, _ *SessionOwner, c *BridgeCall, _ *BridgeResult) {
			c.NativeSessionID = "foreign-session"
		}},
		{"foreign_origin", func(_ *testing.T, _ *SessionOwner, c *BridgeCall, _ *BridgeResult) {
			c.Origin = json.RawMessage(`{"original":"foreign"}`)
		}},
		{"representative", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) { o.spec.Kind = "representative" }},
		{"no_fixed_network", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) { o.spec.NetworkID = "" }},
		{"missing_row", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			_, err := o.journal.db.Exec(`DELETE FROM worker_turn_sources`)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"uncertain", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			_, err := o.journal.db.Exec(`UPDATE worker_intent SET state='uncertain'`)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"not_completed", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			_, err := o.journal.db.Exec(`UPDATE worker_turn_sources SET completed=0`)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"never_started", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			_, err := o.journal.db.Exec(`UPDATE worker_turn_sources SET started=0`)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign_command", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			_, err := o.journal.db.Exec(`UPDATE worker_turn_sources SET source_command='foreign'`)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"new_candidate", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			o.mu.Lock()
			o.candidateTurnSource.Sequence = 2
			o.mu.Unlock()
		}},
		{"new_admitted_task", func(t *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			if _, _, err := o.journal.Admit(t.Context(), o.relay.lease, 2, "new-task", "prompt", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{"new_generation", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			o.mu.Lock()
			o.generation = "replacement"
			o.mu.Unlock()
		}},
		{"native_busy", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			o.manager.ObserveNativeActivity(o.journal.scope.InstanceID, session.SessionEvent{Type: session.EventBusy})
		}},
		{"endpoint_dead", func(_ *testing.T, o *SessionOwner, _ *BridgeCall, _ *BridgeResult) {
			o.driver.(*settledBridgeDriver).live.Store(false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, call, l := settledBridgeFixture(t)
			finishSettledFixture(t, o)
			reply := BridgeResult{Error: "not applied", ErrorCode: "source_settled", Retryable: true}
			tc.mutate(t, o, &call, &reply)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			done := make(chan BridgeResult, 1)
			go func() { done <- o.forwardBridgeCall(ctx, call) }()
			first := pollSettledBridge(t, o, l)
			reply.ID = first.ID
			if err := o.relay.complete(l, reply); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-done:
				if got.OK {
					t.Fatal("unsafe authority accepted")
				}
			case <-ctx.Done():
				t.Fatal("unsafe source produced a second pending operation")
			}
			if extra, err := o.relay.poll(l); err != nil || extra != nil {
				t.Fatal("unsafe source became endpoint authority")
			}
		})
	}
}
