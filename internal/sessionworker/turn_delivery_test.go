//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestOriginalInputKindBoundBeforeNativeCaptureAndNeverRelabelled(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	if _, _, err := j.Admit(ctx, a, 1, "original-prompt-intent", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "native-generation", NativeSessionID: "native-session", SourceCommandID: "original-command-A", SourceAdmissionID: "original-admission-A", InputKind: "task"}
	if err := j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	if err := j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal("exact original accepted source replay conflicted", err)
	}
	observed := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventTurnStarted, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID})
	if observed.TurnSource == nil || observed.TurnSource.InputKind != "task" {
		t.Fatal("original operation classification missing before capture")
	}
	changed := source
	changed.InputKind = "user_input"
	if err := j.BindNativeTurn(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("accepted original input kind was rewritten")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	page, err := j.PendingObservationsForLease(ctx, lease(t, j), 32)
	if err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	if page[0].TurnSource.InputKind != source.InputKind || page[0].SourceDigest != observed.SourceDigest || page[0].SourceSequence != 1 {
		t.Fatal("reconnect rewrote original captured turn identity")
	}
	digest, err := observationDigest(page[0])
	if err != nil || digest != observed.SourceDigest {
		t.Fatal("sequence delivery metadata changed original capture digest")
	}
}

func TestOriginalBoundTurnsShareLifecycleSequenceAndHumanTurnsStayUnbound(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	if _, _, err := j.Admit(ctx, a, 1, "original-prompt-intent", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "native-generation", NativeSessionID: "native-session", SourceCommandID: "command-A", SourceAdmissionID: "admission-A", InputKind: "task"}
	if err := j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	for _, event := range []session.SessionEvent{
		{Type: session.EventSessionStarted, SessionID: source.NativeSessionID},
		{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID},
		{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID},
		{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: "tui-human-original"},
		{Type: session.EventIdle, SessionID: source.NativeSessionID},
	} {
		journalSourceEvent(t, j, event)
	}
	page, err := j.PendingObservations(ctx, 32)
	if err != nil || len(page) != 5 {
		t.Fatal(err)
	}
	for i, want := range []int64{1, 2, 3, 0, 4} {
		if page[i].SourceSequence != want {
			t.Fatalf("sourceSequence[%d]=%d want%d", i, page[i].SourceSequence, want)
		}
	}
	if page[3].TurnSource != nil || NativeSourceType(page[3]) != "" {
		t.Fatal("human turn borrowed a controller command or stream sequence")
	}
}

func TestLegacyCapturedTurnInputKindStaysAbsentAndDigestStable(t *testing.T) {
	j, dir := testJournal(t)
	a := lease(t, j)
	source := admitTurnSource(t, j, a, 1, "legacy-command-A", "legacy-admission-A")
	observed := journalSourceEvent(t, j, session.SessionEvent{Type: session.EventTurnCompleted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID})
	original, _ := json.Marshal(observed)
	// Reproduce the previous SQLite schema; migration must not infer a kind.
	if _, err := j.db.Exec(`ALTER TABLE worker_turn_sources DROP COLUMN input_kind`); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	page, err := j.PendingObservations(context.Background(), 32)
	if err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	actual, _ := json.Marshal(page[0])
	if string(actual) != string(original) || page[0].SourceSequence != 0 || NativeSourceType(page[0]) != "" {
		t.Fatal("legacy committed capture was relabelled to enable delivery")
	}
}

func TestUnsupportedTurnClassificationDoesNotAllocateSourceSequence(t *testing.T) {
	for _, change := range []func(*NativeObservation){
		func(o *NativeObservation) { o.SourceUnavailable = true }, func(o *NativeObservation) { o.TurnSource = nil }, func(o *NativeObservation) { o.TurnSource.InputKind = "vendor-private-free-text" }, func(o *NativeObservation) { o.TurnSource.NativeSessionID = "new-session-B" }, func(o *NativeObservation) { o.TurnSource.SourceAdmissionID = "" }, func(o *NativeObservation) { o.Event.TurnID = "other" },
	} {
		o := NativeObservation{ObservedAt: time.Now().UTC(), NativeGeneration: "generation-A", NativeSessionID: "session-A", Event: session.SessionEvent{Type: session.EventTurnFailed, TurnID: logicalWorkerTurn(1), SessionID: "session-A"}, TurnSource: &NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "generation-A", NativeSessionID: "session-A", SourceCommandID: "command-A", SourceAdmissionID: "admission-A", InputKind: "task"}}
		change(&o)
		if NativeSourceType(o) != "" {
			t.Fatal("unsupported original turn consumed durable stream sequence")
		}
	}
}
