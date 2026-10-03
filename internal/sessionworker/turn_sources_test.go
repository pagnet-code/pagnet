package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func admitTurnSource(t *testing.T, j *Journal, lease, sequence int64, command, admission string) NativeTurnSource {
	t.Helper()
	if _, _, err := j.Admit(context.Background(), lease, sequence, logicalWorkerTurn(sequence), "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	source := NativeTurnSource{Sequence: sequence, LogicalTurnID: logicalWorkerTurn(sequence), NativeGeneration: "native-generation", NativeSessionID: "native-session", SourceCommandID: command, SourceAdmissionID: admission}
	if err := j.BindNativeTurn(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	return source
}
func journalSourceEvent(t *testing.T, j *Journal, event session.SessionEvent) NativeObservation {
	t.Helper()
	source, unavailable, err := j.NativeEventSource(context.Background(), "native-generation", event)
	if err != nil {
		t.Fatal(err)
	}
	observation := NativeObservation{ID: time.Now().Format("150405.000000000"), NativeGeneration: "native-generation", NativeSessionID: event.SessionID, Origin: json.RawMessage(`{"id":"activation"}`), ObservedAt: time.Now().UTC(), Event: event, TurnSource: source, SourceUnavailable: unavailable}
	observation.SourceDigest, _ = observationDigest(observation)
	if err = j.JournalObservation(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestTurnSourceResolutionUsesOriginalAdmissionAcrossController(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	original := admitTurnSource(t, j, a, 1, "source-command-A", "source-admission-A")
	started := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventInteractionStarted, SessionID: original.NativeSessionID, TurnID: original.LogicalTurnID, Interaction: &session.InteractionEvent{NativeInteractionID: "native-choice"}})
	completed := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventTurnCompleted, SessionID: original.NativeSessionID, TurnID: original.LogicalTurnID})
	if err := j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.Acknowledge(ctx, a, 1); err != nil {
		t.Fatal(err)
	}
	b := lease(t, j)
	newest := admitTurnSource(t, j, b, 2, "source-command-B", "source-admission-B")
	resolved := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventInteractionResolved, SessionID: original.NativeSessionID, TurnID: newest.LogicalTurnID, Interaction: &session.InteractionEvent{NativeInteractionID: "native-choice", Resolved: true}})
	if resolved.TurnSource == nil || *resolved.TurnSource != original {
		t.Fatal("old native resolution inherited newest delivery/controller admission")
	}
	human, unavailable, err := j.NativeEventSource(ctx, "native-generation", session.SessionEvent{SessionID: original.NativeSessionID, TurnID: "human-native-turn"})
	if err != nil || human != nil || unavailable {
		t.Fatal("human native activity was assigned fabricated source command")
	}
	humanStarted := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventInteractionStarted, SessionID: original.NativeSessionID, TurnID: "human-native-turn", Interaction: &session.InteractionEvent{NativeInteractionID: "human-choice"}})
	humanResolved := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventInteractionResolved, SessionID: original.NativeSessionID, TurnID: newest.LogicalTurnID, Interaction: &session.InteractionEvent{NativeInteractionID: "human-choice", Resolved: true}})
	if humanStarted.TurnSource != nil || humanResolved.TurnSource != nil || humanResolved.SourceUnavailable {
		t.Fatal("human interaction resolution inherited current machine delivery")
	}
	// Source remains while exact immutable observations still need it.
	if err = j.BindNativeTurn(ctx, newest); err != nil {
		t.Fatal(err)
	}
	source, _, err := j.NativeEventSource(ctx, "native-generation", completed.Event)
	if err != nil || source == nil || *source != original {
		t.Fatal("retired command discarded unacknowledged source evidence")
	}
	for _, observation := range []NativeObservation{started, completed, resolved, humanStarted, humanResolved} {
		if err = j.AcknowledgeObservation(ctx, b, observation.ID, observation.SourceDigest); err != nil {
			t.Fatal(err)
		}
	}
	_ = admitTurnSource(t, j, b, 3, "source-command-C", "source-admission-C")
	retired, unavailable, err := j.NativeEventSource(ctx, "native-generation", completed.Event)
	if err != nil || retired != nil || !unavailable {
		t.Fatal("retired native source inferred fresh admission")
	}
	var retained int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_turn_sources`).Scan(&retained); err != nil || retained != 2 {
		t.Fatal("source mappings not reclaimed safely", retained, err)
	}
}

type provenanceSubmitDriver struct {
	session.Driver
	effects atomic.Int32
}

func (d *provenanceSubmitDriver) Submit(context.Context, *session.RuntimeSession, session.SubmitRequest, chan<- session.SessionEvent) error {
	d.effects.Add(1)
	return nil
}
func TestNativeSubmitCannotPrecedeSourceCommit(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	if _, _, err := j.Admit(ctx, current, 1, "intent", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`CREATE TRIGGER reject_turn_source BEFORE INSERT ON worker_turn_sources BEGIN SELECT RAISE(ABORT,'source unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	driver := &provenanceSubmitDriver{}
	owner := &SessionOwner{journal: j, generation: "generation", candidateTurnSource: NativeTurnSource{Sequence: 1, SourceCommandID: "command-A", SourceAdmissionID: "admission-A"}}
	wrapped := &ownedDriver{Driver: driver, owner: owner}
	req := session.SubmitRequest{TurnID: logicalWorkerTurn(1), Kind: session.SubmitPrompt}
	native := &session.RuntimeSession{NativeID: "native-session"}
	if wrapped.Submit(ctx, native, req, nil) == nil || driver.effects.Load() != 0 {
		t.Fatal("native work consumed before immutable source commit")
	}
	if _, err := j.db.Exec(`DROP TRIGGER reject_turn_source`); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Submit(ctx, native, req, nil); err != nil || driver.effects.Load() != 1 {
		t.Fatal("source-backed submit unavailable", err)
	}
	changed := owner.candidateTurnSource
	changed.SourceAdmissionID = "newest-B"
	changed.NativeGeneration = "generation"
	changed.NativeSessionID = "native-session"
	changed.LogicalTurnID = req.TurnID
	if err := j.BindNativeTurn(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("immutable source tuple overwritten")
	}
}

func TestPreparedNativeSourceLookupCancellationNeverCachesAuthority(t *testing.T) {
	j, dir := testJournal(t)
	original := admitTurnSource(t, j, lease(t, j), 1, "source-command-A", "source-admission-A")
	event := session.SessionEvent{Type: session.EventTurnOutput, SessionID: original.NativeSessionID, TurnID: original.LogicalTurnID, NativeOutput: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := j.NativeEventSource(ctx, original.NativeGeneration, event); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prepared lookup returned authority", err)
	}
	actual, _, err := j.NativeEventSource(context.Background(), original.NativeGeneration, event)
	if err != nil || actual == nil || *actual != original {
		t.Fatal("cancellation poisoned subsequent exact source lookup", err)
	}
	event.SessionID = "foreign-session"
	if _, _, err := j.NativeEventSource(context.Background(), original.NativeGeneration, event); !errors.Is(err, ErrConflict) {
		t.Fatal("prepared lookup cached authority across native sessions", err)
	}
	event.SessionID = original.NativeSessionID
	// Physical row removal is test pressure: a prepared query caches its plan,
	// never an earlier authorization result or source tuple.
	if _, err := j.db.Exec(`DELETE FROM worker_turn_sources WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	actual, unavailable, err := j.NativeEventSource(context.Background(), original.NativeGeneration, event)
	if err != nil || actual != nil || !unavailable {
		t.Fatal("prepared lookup returned deleted source authority", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, j.scope)
	if err != nil {
		t.Fatal("prepared statements prevented durable reopen", err)
	}
	defer reopened.Close()
	actual, unavailable, err = reopened.NativeEventSource(context.Background(), original.NativeGeneration, event)
	if err != nil || actual != nil || !unavailable {
		t.Fatal("reopened prepared lookup fabricated deleted source", err)
	}
}
