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

func TestNativeSourceTimePreservesOriginalCaptureAndExactStoragePrecision(t *testing.T) {
	original := time.Date(2026, 10, 2, 12, 34, 56, 123456789, time.FixedZone("original", 3600))
	canonical := nativeSourceTime(original)
	if canonical.Location() != time.UTC || canonical.Nanosecond() != 123456000 || nativeSourceTime(canonical) != canonical {
		t.Fatal("source clock is not canonical and stable")
	}
	f, proof := originalDeleteFixture(t, false)
	defer f.journal.Close()
	// Real source capture must already be canonical before immutable receipt creation.
	// JSON and PostgreSQL timestamptz precision then retain exact proof identity.
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var replay = *proof
	if err = json.Unmarshal(raw, &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.StoppedObservedAt.Equal(proof.StoppedObservedAt) {
		t.Fatal("proof changed")
	}
	if original.Nanosecond() != 123456789 {
		t.Fatal("original event timestamp rewritten")
	}
}

func TestNativeObserverCapturesCanonicalTimestampBeforeDigest(t *testing.T) {
	j, _ := testJournal(t)
	defer j.Close()
	ctx := context.Background()
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{42}, 32), manager: manager, generation: "original", origin: json.RawMessage(`{"id":"original-origin"}`), pending: map[string]*nativeApproval{}}
	if err := owner.nativeEventObserver(j.scope.InstanceID)(session.SessionEvent{Type: session.EventSessionStarted, SessionID: "original-session"}); err != nil {
		t.Fatal(err)
	}
	observations, err := j.PendingObservations(ctx, 8)
	if err != nil || len(observations) != 1 {
		t.Fatal(observations, err)
	}
	o := observations[0]
	if o.ObservedAt.Nanosecond()%1000 != 0 {
		t.Fatal("observer captured lossy source timestamp")
	}
	digest, err := observationDigest(o)
	if err != nil || digest != o.SourceDigest {
		t.Fatal("timestamp was rewritten after original digest")
	}
}
