//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestOriginalLifecycleSequenceSurvivesRetryACKRestart(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	add := func(j *Journal, id, origin, event string) NativeObservation {
		t.Helper()
		o := NativeObservation{ID: id, Origin: json.RawMessage(`{"id":"` + origin + `"}`), NativeGeneration: "native", NativeSessionID: "session", ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: event, SessionID: "session"}}
		o.SourceDigest, _ = observationDigest(o)
		if err := j.JournalObservation(ctx, o); err != nil {
			t.Fatal(err)
		}
		if err := j.JournalObservation(ctx, o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	first := add(j, "first", "A", session.EventSessionStarted)
	if err := j.pinSourceRetry(first.ID, first.SourceDigest); err != nil {
		t.Fatal(err)
	}
	add(j, "turn", "A", session.EventTurnStarted)
	second := add(j, "second", "A", session.EventBusy)
	add(j, "other", "B", session.EventIdle)
	page, err := j.PendingObservations(ctx, 32)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int64{1, 0, 2, 1} {
		if page[i].SourceSequence != want {
			t.Fatalf("sequence[%d]=%d want %d", i, page[i].SourceSequence, want)
		}
		if digest, _ := observationDigest(page[i]); digest != page[i].SourceDigest {
			t.Fatal("delivery sequence changed original capture digest")
		}
	}
	leaseID := lease(t, j)
	for _, o := range []NativeObservation{first, second} {
		if err = j.AcknowledgeObservation(ctx, leaseID, o.ID, o.SourceDigest); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.JournalObservation(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	add(j, "third", "A", session.EventIdle)
	page, err = j.PendingObservationsForLease(ctx, lease(t, j), 32)
	if err != nil {
		t.Fatal(err)
	}
	if page[len(page)-1].SourceSequence != 3 {
		t.Fatalf("ACK/restart reset source ordinal: %+v", page)
	}
}

func TestOriginalLifecycleSequenceCorruptionFailsClosed(t *testing.T) {
	for _, corruption := range []string{"missing_mapping", "watermark_backwards", "origin_transplant"} {
		t.Run(corruption, func(t *testing.T) {
			j, dir := testJournal(t)
			o := NativeObservation{ID: "observed", Origin: json.RawMessage(`{"id":"A"}`), NativeGeneration: "native", NativeSessionID: "actual", ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy}}
			o.SourceDigest, _ = observationDigest(o)
			if err := j.JournalObservation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			query := `DELETE FROM worker_observation_sequence`
			if corruption == "watermark_backwards" {
				query = `UPDATE worker_observation_sequence SET source_sequence=2`
			}
			if corruption == "origin_transplant" {
				query = `UPDATE worker_observation_sequence SET origin_id='B'`
			}
			if _, err := j.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			j.Close()
			reopened, err := OpenJournal(dir, testScope())
			if err == nil {
				reopened.Close()
				t.Fatal("corrupt source stream silently repaired or reused")
			}
		})
	}
}
