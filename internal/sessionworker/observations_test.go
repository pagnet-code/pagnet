//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/domain"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestNativeSourceObservationDurableRetryAndControllerAcknowledgement(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	originalTime := time.Now().UTC().Add(-time.Hour)
	source := NativeObservation{ID: "original-observation", NativeGeneration: "native-generation", NativeSessionID: "native-session", Origin: json.RawMessage(`{"id":"immutable-origin"}`), ObservedAt: originalTime, Event: session.SessionEvent{Type: session.EventTurnStarted, SessionID: "native-session"}}
	source.SourceDigest, _ = observationDigest(source)
	if err := j.JournalObservation(ctx, source); err != nil {
		t.Fatal(err)
	}
	if err := j.JournalObservation(ctx, source); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.PendingObservations(ctx, 32)
	if err != nil || len(page) != 1 || page[0].ID != source.ID || page[0].SourceDigest != source.SourceDigest || !page[0].ObservedAt.Equal(originalTime) {
		t.Fatalf("original source replaced: %+v %v", page, err)
	}
	changed := source
	changed.ObservedAt = time.Now().UTC()
	changed.SourceDigest, _ = observationDigest(changed)
	if err := reopened.JournalObservation(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry renewed observation: %v", err)
	}
	if err := reopened.AcknowledgeObservation(ctx, lease(t, reopened), source.ID, changed.SourceDigest); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong-source ACK accepted: %v", err)
	}
	if err := reopened.AcknowledgeObservation(ctx, lease(t, reopened), source.ID, source.SourceDigest); err != nil {
		t.Fatal(err)
	}
	page, err = reopened.PendingObservations(ctx, 32)
	if err != nil || len(page) != 0 {
		t.Fatalf("ACK not committed: %+v %v", page, err)
	}
}

func TestNativeInteractionIdentityFollowsSemanticActivation(t *testing.T) {
	scope := testScope()
	a := nativeInteractionIdentity(scope, json.RawMessage(`{"id":"server-origin","commandId":"original"}`), "native-generation", "native-session", "native-permission")
	b := nativeInteractionIdentity(scope, json.RawMessage(`{"commandId":"original","id":"server-origin"}`), "native-generation", "native-session", "native-permission")
	if a == "" || a != b {
		t.Fatalf("JSON field ordering replaced semantic identity: %q %q", a, b)
	}
	for _, changed := range []string{
		nativeInteractionIdentity(scope, json.RawMessage(`{"id":"different-origin"}`), "native-generation", "native-session", "native-permission"),
		nativeInteractionIdentity(scope, json.RawMessage(`{"id":"server-origin"}`), "different-generation", "native-session", "native-permission"),
		nativeInteractionIdentity(scope, json.RawMessage(`{"id":"server-origin"}`), "native-generation", "different-session", "native-permission"),
		nativeInteractionIdentity(scope, json.RawMessage(`{"id":"server-origin"}`), "native-generation", "native-session", "different-permission"),
	} {
		if changed == a {
			t.Fatal("different native activation inherited interaction identity")
		}
	}
}

func TestNativeObserverBackpressureRetainsOriginalEvent(t *testing.T) {
	j, _ := testJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx, err := j.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var first NativeObservation
	for i := 0; i < maxPendingObservations; i++ {
		observation := NativeObservation{ID: fmt.Sprintf("queued-%d", i), NativeGeneration: "generation", NativeSessionID: "native-session", Origin: json.RawMessage(`{"id":"origin"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventIdle, SessionID: "native-session"}}
		observation.SourceDigest, _ = observationDigest(observation)
		raw, _ := json.Marshal(observation)
		if _, err = tx.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, observation.ID, observation.SourceDigest, raw, len(raw)); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if i == 0 {
			first = observation
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: make([]byte, 32), manager: manager, generation: "generation", origin: json.RawMessage(`{"id":"origin"}`), pending: map[string]*nativeApproval{}}
	observer := owner.nativeEventObserver(j.scope.InstanceID)
	started := time.Now().UTC()
	completed := make(chan error, 1)
	go func() {
		completed <- observer(session.SessionEvent{Type: session.EventTurnStarted, SessionID: "native-session", TurnID: "actual-turn"})
	}()
	select {
	case err := <-completed:
		t.Fatalf("full journal falsely acknowledged native event: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	released := time.Now().UTC()
	if err = j.AcknowledgeObservation(ctx, lease(t, j), first.ID, first.SourceDigest); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native source stayed paused after durable capacity available")
	}
	var raw []byte
	if err = j.db.QueryRow(`SELECT payload FROM worker_observations ORDER BY sequence DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var actual NativeObservation
	if err = json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	if actual.Event.TurnID != "actual-turn" || actual.ObservedAt.Before(started) || !actual.ObservedAt.Before(released) {
		t.Fatal("backpressure replaced or renewed original native event")
	}
}

func TestObservationAcknowledgementFencesInsideJournalMutation(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	observation := NativeObservation{ID: "retained-source", NativeGeneration: "generation", Origin: json.RawMessage(`{"id":"original-authority"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventIdle}}
	observation.SourceDigest, _ = observationDigest(observation)
	if err := j.JournalObservation(ctx, observation); err != nil {
		t.Fatal(err)
	}
	old := lease(t, j)
	// This reproduces the exact unsafe interleaving: preflight passed, then a
	// replacement controller acquired ownership before the destructive receipt.
	if err := j.CurrentLease(ctx, old); err != nil {
		t.Fatal(err)
	}
	current := lease(t, j)
	if err := j.AcknowledgeObservation(ctx, old, observation.ID, observation.SourceDigest); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale controller dropped source evidence: %v", err)
	}
	page, err := j.PendingObservations(ctx, 32)
	if err != nil || len(page) != 1 {
		t.Fatalf("stale ACK retired evidence: %+v %v", page, err)
	}
	if err := j.AcknowledgeObservation(ctx, current, observation.ID, observation.SourceDigest); err != nil {
		t.Fatal(err)
	}
}
