//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pagnet-code/pagnet/internal/session"
	"testing"
	"time"
)

func TestObservationCursorPreservesIdentityAcrossACKAppendAndLeaseReplacement(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	add := func(i int) NativeObservation {
		t.Helper()
		o := NativeObservation{ID: fmt.Sprintf("source-%d", i), NativeGeneration: "native", Origin: json.RawMessage(`{"id":"A"}`), ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated}}
		o.SourceDigest, _ = observationDigest(o)
		if err := j.JournalObservation(ctx, o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	originals := make([]NativeObservation, 70)
	for i := range originals {
		originals[i] = add(i)
	}
	first, err := j.ObservationPageForLease(ctx, a, 0, 32)
	if err != nil || len(first.Observations) != 32 || first.NextCursor != 32 || !first.More {
		t.Fatal("first bounded cursor page missing", err)
	}
	for _, o := range first.Observations {
		if digest, _ := observationDigest(o); digest != o.SourceDigest {
			t.Fatal("cursor changed original digest")
		}
	}
	if err = j.AcknowledgeObservation(ctx, a, originals[0].ID, originals[0].SourceDigest); err != nil {
		t.Fatal(err)
	}
	b := lease(t, j)
	if _, err = j.ObservationPageForLease(ctx, a, first.NextCursor, 32); err != ErrFenced {
		t.Fatal("cursor bypassed replaced controller lease", err)
	}
	second, err := j.ObservationPageForLease(ctx, b, first.NextCursor, 32)
	if err != nil || len(second.Observations) != 32 || second.Observations[0].ID != originals[32].ID || second.NextCursor != 64 || !second.More {
		t.Fatal("ACK/replacement shifted immutable row cursor", err)
	}
	add(70)
	third, err := j.ObservationPageForLease(ctx, b, second.NextCursor, 32)
	if err != nil || len(third.Observations) != 7 || third.NextCursor != 71 || third.More {
		t.Fatal("append lost cursor tail", err)
	}
	if _, err = j.ObservationPageForLease(ctx, b, -1, 32); err == nil {
		t.Fatal("negative cursor accepted")
	}
	beyond, err := j.ObservationPageForLease(ctx, b, 1000, 32)
	if err != nil || len(beyond.Observations) != 0 || beyond.More {
		t.Fatal("exhausted cursor failed", err)
	}
}
