//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func TestPinnedNativeProducerAmbiguousCommitAfterACKDoesNotResurrect(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	o := NativeObservation{ID: "original-callback", Origin: json.RawMessage(`{"id":"A"}`), NativeGeneration: "native", NativeSessionID: "actual", ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy}}
	o.SourceDigest, _ = observationDigest(o)
	if err := j.pinSourceRetry(o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if err := j.JournalObservation(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := j.AcknowledgeObservation(ctx, lease(t, j), o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	var concurrent sync.WaitGroup
	for i := 0; i < 16; i++ {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			if err := j.JournalObservation(ctx, o); err != nil {
				t.Error(err)
			}
		}()
	}
	concurrent.Wait()
	changed := o
	changed.ObservedAt = changed.ObservedAt.Add(time.Second)
	changed.SourceDigest, _ = observationDigest(changed)
	if err := j.JournalObservation(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("pinned original digest rewritten: %v", err)
	}
	page, err := j.PendingObservations(ctx, 32)
	if err != nil || len(page) != 0 {
		t.Fatalf("ambiguous commit resurrected source: %+v %v", page, err)
	}
	var last int64
	if err = j.db.QueryRow(`SELECT last_sequence FROM worker_source_stream WHERE origin_id='A'`).Scan(&last); err != nil || last != 1 {
		t.Fatalf("retry consumed sequence: %d %v", last, err)
	}
	j.releaseSourceRetry(o.ID, o.SourceDigest)
	j.mu.Lock()
	pins := len(j.sourceRetries)
	j.mu.Unlock()
	if pins != 0 {
		t.Fatal("callback release retained lifetime tombstone")
	}
	next := o
	next.ID = "new-native-callback"
	next.SourceDigest, _ = observationDigest(next)
	if err = j.pinSourceRetry(next.ID, next.SourceDigest); err != nil {
		t.Fatal(err)
	}
	defer j.releaseSourceRetry(next.ID, next.SourceDigest)
	if err = j.JournalObservation(ctx, next); err != nil {
		t.Fatal(err)
	}
	page, err = j.PendingObservations(ctx, 32)
	if err != nil || len(page) != 1 || page[0].SourceSequence != 2 {
		t.Fatalf("new producer lost contiguous sequence: %+v %v", page, err)
	}
}
