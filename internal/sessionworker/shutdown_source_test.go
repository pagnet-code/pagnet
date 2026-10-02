//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestActualNativeShutdownWithFullOrdinaryOutboxRetainsOriginalEOFOnReopen(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "b", "bin", "native")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary(t, root, binary, "./cmd/pagnet-fake-runtime", "")
	j, dir := testJournal(t)
	owner, err := NewSessionOwner(context.Background(), j, NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), NetworkID: uuid.NewString(), NetworkTenantID: j.scope.TenantID, TenantID: j.scope.TenantID, Kind: "worker"}, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "actual-original-generation"
	owner.origin = json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"actual-original-generation"}`)
	owner.sess.Env = owner.launchEnvironment("fixture-only-nonce")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = owner.driver.Activate(ctx, owner.sess, make(chan session.SessionEvent, 64)); err != nil {
		t.Fatal(err)
	}
	originalSID := owner.sess.NativeID
	if originalSID == "" || owner.supervisor.EndpointPID(j.scope.InstanceID) == nil {
		t.Fatal("fixture has no genuine native session/process")
	}
	var producer *nativeSourceProducer
	j.mu.Lock()
	for p := range j.sourceProducers {
		producer = p
	}
	j.mu.Unlock()
	if producer == nil {
		t.Fatal("actual reader never registered original append capability")
	}
	// Row pressure is synthetic; the native reader/process and final EOF are real.
	// NORMAL avoids thousands of irrelevant fsyncs; restore FULL before shutdown.
	if _, err = j.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		t.Fatal(err)
	}
	ordinary := 0
	for {
		observed := NativeObservation{ID: uuid.NewString(), NativeGeneration: producer.generation, NativeSessionID: originalSID, Origin: producer.origin, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: originalSID}}
		observed.SourceDigest, _ = observationDigest(observed)
		err = j.journalCapturedObservation(context.Background(), producer, observed, nil)
		if errors.Is(err, ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ordinary++
		if ordinary > maxPendingObservations {
			t.Fatal("ordinary quota unbounded")
		}
	}
	if ordinary != maxPendingObservations-2 {
		t.Fatalf("unexpected reserved ordinary rows %d", ordinary)
	}
	if _, err = j.db.Exec(`PRAGMA synchronous=FULL`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	done := make(chan struct{})
	go func() { owner.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("full ordinary outbox hung owner shutdown")
	}
	if time.Since(started) > 10*time.Second {
		t.Fatal("full ordinary outbox hung owner shutdown")
	}
	if owner.supervisor.EndpointPID(j.scope.InstanceID) != nil {
		t.Fatal("shutdown reported completion while original process alive")
	}
	if !producer.closed {
		t.Fatal("owner shutdown did not close old producer capability")
	}
	var stopped NativeObservation
	// The page API has a bounded32 response; use SQLite's original immutable row
	// to inspect the final record without modifying its source bytes.
	var raw []byte
	if err = j.db.QueryRow(`SELECT payload FROM worker_observations WHERE json_extract(payload,'$.event.Type')=? OR json_extract(payload,'$.event.type')=?`, session.EventSessionStopped, session.EventSessionStopped).Scan(&raw); err != nil {
		t.Fatal("genuine EOF not durable at full ordinary quota", err)
	}
	if err = json.Unmarshal(raw, &stopped); err != nil {
		t.Fatal(err)
	}
	if stopped.NativeSessionID != originalSID || stopped.Capture == nil || stopped.SourceDigest == "" {
		t.Fatal("shutdown rewrote original native EOF")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	var recovered []byte
	if err = j.db.QueryRow(`SELECT payload FROM worker_observations WHERE id=?`, stopped.ID).Scan(&recovered); err != nil || !bytes.Equal(raw, recovered) {
		t.Fatal("reopen rewrote original EOF", err)
	}
	late := stopped
	late.ID = uuid.NewString()
	late.Capture = nil
	late.SourceDigest, _ = observationDigest(late)
	if err = j.journalCapturedObservation(context.Background(), producer, late, nil); !errors.Is(err, ErrFenced) {
		t.Fatal("old reader survived shutdown/reopen", err)
	}
}

func TestCancelledProducerEOFUsesReservedBytesWithinExistingQuota(t *testing.T) {
	j, _ := testJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	manager := session.NewManager()
	manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	origin := json.RawMessage(`{"id":"` + uuid.NewString() + `"}`)
	producer, err := j.registerNativeSource(ctx, "original-generation", origin)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: key, manager: manager, generation: producer.generation, origin: origin, pending: map[string]*nativeApproval{}}
	build := func(n int) (NativeObservation, []byte) {
		o := NativeObservation{ID: uuid.NewString(), NativeGeneration: producer.generation, NativeSessionID: "actual-source-session", Origin: origin, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: "actual-source-session"}}
		source := NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: o.NativeSessionID, Output: string(bytes.Repeat([]byte("x"), n))}}
		var encoded []byte
		o.Capture, encoded, err = sealNativeCapture(key, j.scope, j.dir, o, source)
		if err != nil {
			t.Fatal(err)
		}
		o.SourceDigest, err = observationDigest(o)
		if err != nil {
			t.Fatal(err)
		}
		return o, encoded
	}
	for {
		var total int
		if err = j.db.QueryRow(`SELECT COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures) FROM worker_observations`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		remaining := maxPendingObservationBytes - sourceStopReserveBytes - total
		if remaining < 4096 {
			break
		}
		small, encoded := build(1)
		raw, _ := json.Marshal(small)
		size := min(maxPrivateSourceBytes-2048, remaining-len(raw)-len(encoded)+1)
		o, cipher := build(size)
		raw, _ = json.Marshal(o)
		if excess := len(raw) + len(cipher) - remaining; excess > 0 {
			o, cipher = build(size - excess)
		}
		if err = j.journalCapturedObservation(context.Background(), producer, o, cipher); err != nil {
			t.Fatal(err)
		}
	}
	small, encoded := build(4096)
	if err = j.journalCapturedObservation(ctx, producer, small, encoded); !errors.Is(err, ErrFull) {
		t.Fatal("ordinary capture consumed final reserved EOF bytes", err)
	}
	callback := nativeObserverRegistration(owner.nativeSourceObserver(j.scope.InstanceID, producer), func() {
		if err := j.retireNativeSource(context.Background(), producer); err != nil {
			t.Error(err)
		}
	})
	cancel()
	if err = callback.Observe(session.SessionEvent{Type: session.EventSessionStopped, SessionID: "actual-source-session"}); err != nil {
		t.Fatal("cancelled original execution dropped reserved EOF", err)
	}
	callback.Retire()
	if err = callback.Observe(session.SessionEvent{Type: session.EventSessionStopped, SessionID: "actual-source-session"}); !errors.Is(err, ErrFenced) {
		t.Fatal("late EOF callback survived retirement", err)
	}
	var total, count int
	if err = j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures) FROM worker_observations`).Scan(&count, &total); err != nil || total > maxPendingObservationBytes || count > maxPendingObservations {
		t.Fatal("EOF added an unbounded reserve queue", err)
	}
	var stopped int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_observations WHERE json_extract(payload,'$.event.Type')=?`, session.EventSessionStopped).Scan(&stopped); err != nil || stopped != 1 {
		t.Fatal("reserved original EOF was not durable", err)
	}
}
