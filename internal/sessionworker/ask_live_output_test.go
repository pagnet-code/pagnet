//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestBoundAskOutputAndPlanStayLiveThroughCompletionAndRetirement(t *testing.T) {
	for _, batched := range []bool{false, true} {
		for _, terminal := range []string{session.EventTurnCompleted, session.EventTurnFailed} {
			t.Run(terminal+map[bool]string{false: "/single", true: "/batch"}[batched], func(t *testing.T) {
				ctx := context.Background()
				j, _ := testJournal(t)
				a := lease(t, j)
				p, _ := retiredFixture(t, j, "ask-origin", "ask-generation")
				if _, _, err := j.Admit(ctx, a, 1, "ask-intent", "prompt", json.RawMessage(`{}`)); err != nil {
					t.Fatal(err)
				}
				source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: p.generation, NativeSessionID: "ask-session", SourceCommandID: "ask-command", SourceAdmissionID: "ask-admission", InputKind: "ask"}
				if err := j.BindNativeTurn(ctx, source); err != nil {
					t.Fatal(err)
				}
				manager := session.NewManager()
				sess := manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
				owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{29}, 32), manager: manager, generation: p.generation}
				observe, _, batch := owner.nativeCapturedSourceObservers(j.scope.InstanceID, p, p.generation, p.origin)
				started := session.SessionEvent{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID}
				if err := observe(started); err != nil {
					t.Fatal(err)
				}
				sess.LastActivity = time.Unix(123, 0)
				text := strings.Repeat("live ask output €", 5000)
				if batched {
					text = strings.Repeat("live ask output €", 1500)
				}
				events := []session.SessionEvent{{Type: session.EventTurnOutput, NativeOutput: true, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, Output: text}}
				if batched {
					events = append(events, events[0])
					events[1].Output = "second ask output"
					if err := batch(events); err != nil {
						t.Fatal(err)
					}
				} else if err := observe(events[0]); err != nil {
					t.Fatal(err)
				}
				plan := &session.PlanSnapshot{Source: "codex", Entries: []session.PlanEntry{{Text: "live ask plan", Status: "in_progress"}}}
				if err := observe(session.SessionEvent{Type: session.EventPlanUpdated, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, Plan: plan}); err != nil {
					t.Fatal(err)
				}
				if !sess.LastActivity.After(time.Unix(123, 0)) {
					t.Fatal("live ask callbacks did not refresh activity")
				}
				for _, table := range []string{"worker_output_spools", "worker_output_deltas"} {
					if sourceCount(t, j, table) != 0 {
						t.Fatal("ask retained output in", table)
					}
				}
				if sourceCount(t, j, "worker_observations") != 1 || sourceCount(t, j, "worker_source_captures") != 1 {
					t.Fatal("ask retained unsupported output or plan capture")
				}
				page, err := owner.outputReplay().Replay("", 0, 64)
				if err != nil || page.Gap {
					t.Fatal("live replay unavailable", err)
				}
				var replayed strings.Builder
				var gotPlan bool
				for _, record := range page.Records {
					var event session.SessionEvent
					if err := json.Unmarshal(record.Data, &event); err != nil {
						t.Fatal(err)
					}
					replayed.WriteString(event.Output)
					gotPlan = gotPlan || event.Plan != nil && event.Plan.Entries[0].Text == plan.Entries[0].Text
				}
				want := text
				if batched {
					want += events[1].Output
				}
				if replayed.String() != want || !gotPlan {
					t.Fatal("live ask output or plan lost")
				}
				finished := started
				finished.Type, finished.Output = terminal, "final ask answer"
				if err := observe(finished); err != nil {
					t.Fatal(err)
				}
				pending, err := j.PendingObservationsForLease(ctx, a, 32)
				if err != nil || len(pending) != 2 {
					t.Fatal("ask lifecycle delivery lost", len(pending), err)
				}
				wantTerminal := transport.MsgRuntimeTurnCompleted
				if terminal == session.EventTurnFailed {
					wantTerminal = transport.MsgRuntimeTurnFailed
				}
				if NativeSourceType(pending[0]) != transport.MsgRuntimeTurnStarted || NativeSourceType(pending[1]) != wantTerminal {
					t.Fatal("ask lifecycle became undeliverable")
				}
				if err := j.retireNativeSource(ctx, p); err != nil {
					t.Fatal(err)
				}
				if err := batch(events); !errors.Is(err, ErrFenced) {
					t.Fatal("retired ask callback bypassed fencing", err)
				}
				for _, observation := range pending {
					if err := j.AcknowledgeObservation(ctx, a, observation.ID, observation.SourceDigest); err != nil {
						t.Fatal(err)
					}
				}
				if err := j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
					t.Fatal(err)
				}
				if err := j.Acknowledge(ctx, a, 1); err != nil {
					t.Fatal(err)
				}
				for _, table := range []string{"worker_observations", "worker_source_captures", "worker_turn_sources", "worker_source_stream", "worker_source_registration"} {
					if sourceCount(t, j, table) != 0 {
						t.Fatal("completed ask prevented source release in", table)
					}
				}
			})
		}
	}
}
