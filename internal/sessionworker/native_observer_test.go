package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"testing"
	"time"
)

func TestReviewOldResolvedObserverCannotRemoveReplacementApproval(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{42}, 32), manager: manager, generation: "old-generation", origin: json.RawMessage(`{"id":"old-origin"}`), pending: map[string]*nativeApproval{}}
	callback := owner.nativeEventObserver(j.scope.InstanceID)
	conn, err := j.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		done <- callback(session.SessionEvent{Type: session.EventInteractionResolved, SessionID: "old-session", TurnID: "human", Interaction: &session.InteractionEvent{NativeInteractionID: "reused-native-choice", Resolved: true}})
	}()
	// Reserving the only DB connection holds the callback inside NativeEventSource,
	// after its first generation read. The journal mutex proves it reached that gate.
	blocked := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !j.mu.TryLock() {
			blocked = true
			break
		}
		j.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	if !blocked {
		t.Fatal("observer did not reach source lookup gate")
	}
	replacement := &nativeApproval{inspection: &Inspection{NativeGeneration: "new-generation", NativeSessionID: "new-session", NativeInteractionID: "reused-native-choice"}}
	owner.mu.Lock()
	owner.generation = "new-generation"
	owner.origin = json.RawMessage(`{"id":"new-origin"}`)
	owner.pending["reused-native-choice"] = replacement
	owner.mu.Unlock()
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback stuck")
	}
	owner.mu.Lock()
	survived := owner.pending["reused-native-choice"] == replacement
	owner.mu.Unlock()
	if !survived {
		t.Fatal("old resolved observer deleted the replacement generation's pending approval")
	}
}
