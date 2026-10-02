package sessionworker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDecodedTaskDescriptorRetainsOriginalTurnSource(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	if _, _, err := j.Admit(ctx, current, 1, logicalWorkerTurn(1), "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "generation", NativeSessionID: "session", SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: "original-task", InputAAD: e2ee.AAD{TenantID: "tenant", NetworkID: "network", ObjectType: e2ee.ObjectTypeTask, ObjectID: "original-task", KeyEpochID: "original-epoch"}}}
	if err := j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	event := session.SessionEvent{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID}
	decoded, unavailable, err := j.NativeEventSource(ctx, source.NativeGeneration, event)
	if err != nil || unavailable || decoded == nil {
		t.Fatal(err, unavailable)
	}
	if decoded.SourceTask == source.SourceTask {
		t.Fatal("fixture did not exercise independently decoded descriptor")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	observation := NativeObservation{NativeGeneration: source.NativeGeneration, Event: event, TurnSource: decoded}
	if err = retainNativeEventSource(ctx, tx, observation); err != nil {
		t.Fatal("equivalent original descriptor rejected", err)
	}
	decoded.SourceTask.InputAAD.KeyEpochID = "foreign-epoch"
	if err = retainNativeEventSource(ctx, tx, observation); err != ErrConflict {
		t.Fatal("mutated original descriptor accepted", err)
	}
}
