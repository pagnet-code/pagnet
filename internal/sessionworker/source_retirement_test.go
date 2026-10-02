//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func retiredFixture(t *testing.T, j *Journal, origin, generation string) (*nativeSourceProducer, NativeObservation) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"id": origin, "nativeGeneration": generation})
	p, err := j.registerNativeSource(context.Background(), generation, raw)
	if err != nil {
		t.Fatal(err)
	}
	o := NativeObservation{ID: "event-" + origin, NativeGeneration: generation, NativeSessionID: "actual", Origin: raw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventBusy, SessionID: "actual"}}
	o.SourceDigest, _ = observationDigest(o)
	return p, o
}
func sourceCount(t *testing.T, j *Journal, table string) int {
	t.Helper()
	var n int
	if err := j.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func TestRegisteredNativeSourceMoreThan4096SettledGenerations(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	// This checks storage cardinality, not power-loss durability. Reopen and
	// uncertain-COMMIT tests retain production FULL fsync separately.
	if _, err := j.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxPendingObservations+16; i++ {
		p, o := retiredFixture(t, j, fmt.Sprintf("origin-%d", i), fmt.Sprintf("generation-%d", i))
		if err := j.journalCapturedObservation(ctx, p, o, nil); err != nil {
			t.Fatalf("settled generation %d lifetime-blocked: %v", i, err)
		}
		if err := j.retireNativeSource(ctx, p); err != nil {
			t.Fatal(err)
		}
		if sourceCount(t, j, "worker_source_stream") != 1 {
			t.Fatal("pending evidence lost watermark")
		}
		if err := j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
			t.Fatal(err)
		}
		if sourceCount(t, j, "worker_source_stream") != 0 || sourceCount(t, j, "worker_source_registration") != 0 {
			t.Fatal("settled generation retained lifetime tombstone")
		}
		if err := j.journalCapturedObservation(ctx, p, o, nil); !errors.Is(err, ErrFenced) {
			t.Fatal("retired producer resurrected reclaimed origin", err)
		}
		if err := j.JournalObservation(ctx, o); !errors.Is(err, ErrFenced) {
			t.Fatal("unregistered append bypassed production capability", err)
		}
	}
	if sourceCount(t, j, "worker_source_registration_protocol") != 1 {
		t.Fatal("registration protocol marker unbounded")
	}
}
func TestNativeRetirementWaitsOriginalCaptureAndAmbiguousProducerCommit(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	p, o := retiredFixture(t, j, "A", "native")
	capture := NativeSourceCapture{Format: NativeSourceCaptureFormat, Event: o.Event}
	ref, cipher, err := sealNativeCapture(bytes.Repeat([]byte{9}, 32), j.scope, j.dir, o, capture)
	if err != nil {
		t.Fatal(err)
	}
	o.Capture = ref
	o.SourceDigest, _ = observationDigest(o)
	if err = j.pinSourceRetry(o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if err = j.journalCapturedObservation(ctx, p, o, cipher); err != nil {
		t.Fatal(err)
	}
	// Simulate an uncertain original COMMIT return and a concurrent backend ACK.
	if err = j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if err = j.journalCapturedObservation(ctx, p, o, cipher); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_observations") != 0 || sourceCount(t, j, "worker_source_stream") != 1 {
		t.Fatal("ambiguous producer retry resurrected or lost ordinal")
	}
	if err = j.retireNativeSource(ctx, p); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_stream") != 1 {
		t.Fatal("retirement ignored original retry pin")
	}
	j.releaseSourceRetry(o.ID, o.SourceDigest)
	if sourceCount(t, j, "worker_source_stream") != 0 || sourceCount(t, j, "worker_source_captures") != 0 {
		t.Fatal("quiesced producer retained evidence after real ACK")
	}
	if err = j.journalCapturedObservation(ctx, p, o, cipher); !errors.Is(err, ErrFenced) {
		t.Fatal("old callback appended after retirement", err)
	}
}
func TestNativeRegistrationRetireWaitsConcurrentReaderAndResolver(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	m := session.NewManager()
	m.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{42}, 32), manager: m, generation: "native", origin: json.RawMessage(`{"id":"A","nativeGeneration":"native"}`), pending: map[string]*nativeApproval{}}
	registration := owner.nativeEventRegistration(j.scope.InstanceID)
	connection, err := j.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	callbacks := make(chan error, 2)
	go func() {
		callbacks <- registration.Observe(session.SessionEvent{Type: session.EventBusy, SessionID: "native-session"})
	}()
	// Reserving SQLite's sole connection holds the original reader callback
	// inside source lookup after its registration gate is acquired.
	deadline := time.Now().Add(time.Second)
	for j.mu.TryLock() {
		j.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("native callback did not enter source lookup")
		}
		time.Sleep(time.Millisecond)
	}
	resolverEntered := make(chan struct{})
	go func() {
		close(resolverEntered)
		callbacks <- registration.Observe(session.SessionEvent{Type: session.EventIdle, SessionID: "native-session"})
	}()
	<-resolverEntered
	retired := make(chan struct{})
	go func() { registration.Retire(); close(retired) }()
	select {
	case <-retired:
		t.Fatal("registration retired with original callback in flight")
	case <-time.After(20 * time.Millisecond):
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err = <-callbacks:
			if err != nil && !errors.Is(err, ErrFenced) {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("original callback blocked")
		}
	}
	select {
	case <-retired:
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not quiesce")
	}
	if err = registration.Observe(session.SessionEvent{Type: session.EventBusy, SessionID: "native-session"}); !errors.Is(err, ErrFenced) {
		t.Fatal("old reader capability survived retirement", err)
	}
	pending, err := j.PendingObservations(ctx, 32)
	if err != nil || len(pending) < 1 {
		t.Fatal("retirement lost original callback evidence", err)
	}
	a := lease(t, j)
	for _, o := range pending {
		if err = j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
			t.Fatal(err)
		}
	}
	if sourceCount(t, j, "worker_source_stream") != 0 {
		t.Fatal("quiesced original callback watermark leaked")
	}
	var concurrent sync.WaitGroup
	for i := 0; i < 8; i++ {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			registration.Retire()
			if err := registration.Observe(session.SessionEvent{}); !errors.Is(err, ErrFenced) {
				t.Error("retired resolver revived capability")
			}
		}()
	}
	concurrent.Wait()
}
func TestNativeRegisteredReopenRetainsPendingSourceAndFencesOldCapabilities(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	p, o := retiredFixture(t, j, "A", "native")
	if err := j.journalCapturedObservation(ctx, p, o, nil); err != nil {
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
	if sourceCount(t, j, "worker_source_stream") != 1 {
		t.Fatal("reopen forgot original pending watermark")
	}
	if err = j.JournalObservation(ctx, o); !errors.Is(err, ErrFenced) {
		t.Fatal("reopened journal admitted unregistered original writer", err)
	}
	if err = j.journalCapturedObservation(ctx, p, o, nil); !errors.Is(err, ErrFenced) {
		t.Fatal("reopen accepted old worker memory capability", err)
	}
	if _, err = j.registerNativeSource(ctx, "native", o.Origin); !errors.Is(err, ErrConflict) {
		t.Fatal("reopen resumed quiesced original generation", err)
	}
	pending, err := j.PendingObservations(ctx, 32)
	if err != nil || len(pending) != 1 || pending[0].SourceSequence != 1 || pending[0].SourceDigest != o.SourceDigest {
		t.Fatal("reopen rewrote original evidence", err)
	}
	if err = j.AcknowledgeObservation(ctx, lease(t, j), o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_stream") != 0 || sourceCount(t, j, "worker_source_registration") != 0 {
		t.Fatal("dead worker callback watermark retained after original ACK")
	}
	var last int64
	if err = j.db.QueryRow(`SELECT last_sequence FROM worker_source_stream WHERE origin_id='A'`).Scan(&last); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("retired original stream remained")
	}
}
func TestNativeRetirementRequiresCompletedTurnAndOriginalIntentACK(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprint(completed), func(t *testing.T) {
			j, _ := testJournal(t)
			ctx := context.Background()
			a := lease(t, j)
			p, o := retiredFixture(t, j, "A", "native")
			if _, _, err := j.Admit(ctx, a, 1, "original-intent", "prompt", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			turn := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: p.generation, NativeSessionID: o.NativeSessionID, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: "task"}
			if err := j.BindNativeTurn(ctx, turn); err != nil {
				t.Fatal(err)
			}
			o.TurnSource = &turn
			o.Event.TurnID = turn.LogicalTurnID
			o.Event.Type = session.EventTurnStarted
			if completed {
				o.Event.Type = session.EventTurnCompleted
			}
			o.SourceDigest, _ = observationDigest(o)
			if err := j.journalCapturedObservation(ctx, p, o, nil); err != nil {
				t.Fatal(err)
			}
			if err := j.retireNativeSource(ctx, p); err != nil {
				t.Fatal(err)
			}
			if err := j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
				t.Fatal(err)
			}
			if sourceCount(t, j, "worker_source_stream") != 1 || sourceCount(t, j, "worker_turn_sources") != 1 {
				t.Fatal("source ACK ignored original unACKed turn outcome")
			}
			if err := j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := j.Acknowledge(ctx, a, 1); err != nil {
				t.Fatal(err)
			}
			want := 1
			if completed {
				want = 0
			}
			if sourceCount(t, j, "worker_source_stream") != want || sourceCount(t, j, "worker_turn_sources") != want {
				t.Fatal("retirement fabricated native completion or ignored original outcome ACK")
			}
		})
	}
}
func TestNativeRetirementRequiresOriginalActivationOutcomeACK(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	p, o := retiredFixture(t, j, "A", "native")
	if _, _, err := j.Admit(ctx, a, 1, "activation", "activate", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.Settle(ctx, 1, "completed", json.RawMessage(`{"nativeGeneration":"native"}`)); err != nil {
		t.Fatal(err)
	}
	if err := j.journalCapturedObservation(ctx, p, o, nil); err != nil {
		t.Fatal(err)
	}
	if err := j.retireNativeSource(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_stream") != 1 {
		t.Fatal("unACKed original activation outcome lost generation")
	}
	if err := j.Acknowledge(ctx, a, 1); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_stream") != 0 {
		t.Fatal("settled original activation retained lifetime watermark")
	}
}
func TestNativeRetirementKeepsUnresolvedInteractionAndOrphanEvidence(t *testing.T) {
	for _, reference := range []string{"interaction", "capture", "content"} {
		t.Run(reference, func(t *testing.T) {
			j, _ := testJournal(t)
			ctx := context.Background()
			a := lease(t, j)
			p, o := retiredFixture(t, j, "A", "native")
			if err := j.journalCapturedObservation(ctx, p, o, nil); err != nil {
				t.Fatal(err)
			}
			query := `INSERT INTO worker_interaction_sources VALUES('native','unresolved','actual','')`
			if reference == "capture" {
				query = `INSERT INTO worker_source_captures VALUES('unresolved',X'00',1)`
			}
			if reference == "content" {
				query = `INSERT INTO worker_content_fragments VALUES('unresolved','content',0,X'00',1)`
			}
			if _, err := j.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if err := j.retireNativeSource(ctx, p); err != nil {
				t.Fatal(err)
			}
			if err := j.AcknowledgeObservation(ctx, a, o.ID, o.SourceDigest); err != nil {
				t.Fatal(err)
			}
			if sourceCount(t, j, "worker_source_stream") != 1 || sourceCount(t, j, "worker_source_registration") != 1 {
				t.Fatal("unresolved private reference lost generation watermark")
			}
		})
	}
}
func TestNativeRegistrationWaitsEveryConcurrentReaderAndResolverCallback(t *testing.T) {
	entered := make(chan string, 2)
	readerRelease := make(chan struct{})
	resolverRelease := make(chan struct{})
	closed := make(chan struct{})
	calls := 0
	registration := nativeObserverRegistration(func(event session.SessionEvent) error {
		entered <- event.Type
		if event.Type == session.EventBusy {
			<-readerRelease
		} else {
			<-resolverRelease
		}
		return nil
	}, func() { calls++; close(closed) })
	results := make(chan error, 2)
	go func() { results <- registration.Observe(session.SessionEvent{Type: session.EventBusy}) }()
	go func() { results <- registration.Observe(session.SessionEvent{Type: session.EventInteractionResolved}) }()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("concurrent reader/resolver did not enter original registration")
		}
	}
	returned := make(chan struct{})
	go func() { registration.Retire(); close(returned) }()
	select {
	case <-closed:
		t.Fatal("retirement closed in-flight original reader/resolver")
	case <-time.After(10 * time.Millisecond):
	}
	close(readerRelease)
	<-results
	select {
	case <-closed:
		t.Fatal("retirement ignored in-flight original resolver")
	case <-time.After(10 * time.Millisecond):
	}
	close(resolverRelease)
	<-results
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("quiesced registration did not retire")
	}
	if calls != 1 {
		t.Fatal("original registration retired more than once")
	}
	if err := registration.Observe(session.SessionEvent{Type: session.EventInteractionResolved}); !errors.Is(err, ErrFenced) {
		t.Fatal("closed resolver callback entered original source", err)
	}
	registration.Retire()
	if calls != 1 {
		t.Fatal("retirement was not idempotent")
	}
}
func TestNativeRegistrationCannotReopenRetiredOriginalBirth(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	m := session.NewManager()
	m.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{42}, 32), manager: m, generation: "native", origin: json.RawMessage(`{"id":"A","nativeGeneration":"native"}`), pending: map[string]*nativeApproval{}}
	original := owner.nativeEventRegistration(j.scope.InstanceID)
	if err := original.Observe(session.SessionEvent{Type: session.EventBusy, SessionID: "actual"}); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingObservations(ctx, 32)
	if err != nil || len(pending) != 1 {
		t.Fatal("original registered source absent", err)
	}
	if err = j.AcknowledgeObservation(ctx, lease(t, j), pending[0].ID, pending[0].SourceDigest); err != nil {
		t.Fatal(err)
	}
	original.Retire()
	if sourceCount(t, j, "worker_source_stream") != 0 {
		t.Fatal("original settled stream not reclaimed")
	}
	replacement := owner.nativeEventRegistration(j.scope.InstanceID)
	if err = replacement.Observe(session.SessionEvent{Type: session.EventBusy, SessionID: "actual"}); !errors.Is(err, ErrFenced) {
		t.Fatal("old endpoint factory recreated reclaimed original birth", err)
	}
	if sourceCount(t, j, "worker_source_stream") != 0 || sourceCount(t, j, "worker_source_registration") != 0 {
		t.Fatal("old birth factory resurrected original stream")
	}
}
