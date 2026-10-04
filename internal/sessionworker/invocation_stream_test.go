package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type invocationStreamFixture struct {
	j        *Journal
	o        *SessionOwner
	source   NativeTurnSource
	epochKey [32]byte
	lease    int64
	req      InvocationStreamRequest
	emit     session.NativeEventObserver
	retire   func()
}

func newInvocationStreamFixture(t *testing.T) *invocationStreamFixture {
	t.Helper()
	ctx := context.Background()
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatal(err)
	}
	ring := hostcrypto.NewKeyring(uuid.NewString())
	epoch, err := ring.Activate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keydir := t.TempDir()
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "original-generation", NativeSessionID: "original-session", SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), InputKind: "invocation", SourceInvocation: &transport.NativeInvocationSource{InvocationID: id, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: ring.NetworkID, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: id, KeyEpochID: epoch.ID}}}
	o := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{3}, 32), manager: session.NewManager(), generation: source.NativeGeneration, origin: json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"original-generation"}`), spec: NativeSpec{NetworkID: ring.NetworkID, NetworkTenantID: scope.TenantID, NetworkStateDir: keydir}, pending: map[string]*nativeApproval{}}
	o.manager.Session(scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	current := lease(t, j)
	if _, _, err = j.Admit(ctx, current, 1, source.SourceCommandID, "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.reserveTerminalTx(ctx, tx, 1, "prompt"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	o.pinOriginalTaskContent(source)
	key, available := o.originalTaskContentPin(&source)
	if !available {
		t.Fatal("no original key")
	}
	if err = j.beginInvocationStream(ctx, o.captureKey, source, o.origin, key); err != nil {
		t.Fatal(err)
	}
	registration := o.nativeEventRegistration(scope.InstanceID)
	f := &invocationStreamFixture{j: j, o: o, source: source, epochKey: key, lease: current, req: InvocationStreamRequest{Source: invocationIdentity(source)}, emit: registration.Observe, retire: registration.Retire}
	t.Cleanup(func() { f.retire(); o.nativeObserverWG.Wait(); _ = f.j.Close() })
	return f
}
func (f *invocationStreamFixture) event(t *testing.T, kind, text string) {
	t.Helper()
	if err := f.emit(session.SessionEvent{Type: kind, NativeOutput: kind == session.EventTurnOutput, SessionID: f.source.NativeSessionID, TurnID: f.source.LogicalTurnID, Output: text}); err != nil {
		t.Fatal(err)
	}
}
func (f *invocationStreamFixture) subscribe(t *testing.T) {
	t.Helper()
	sub, err := f.j.subscribeInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req)
	if err != nil {
		t.Fatal(err)
	}
	f.req.SubscriptionID = sub.ID
}
func (f *invocationStreamFixture) projection(t *testing.T) *InvocationStreamProjection {
	t.Helper()
	if err := f.o.projectInvocationStreams(context.Background()); err != nil {
		t.Fatal(err)
	}
	p, err := f.j.readInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f *invocationStreamFixture) open(t *testing.T, p *InvocationStreamProjection) InvocationStreamRange {
	t.Helper()
	r, err := OpenInvocationStreamProjection(*p, f.source, f.j.scope.InstanceID, f.epochKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *invocationStreamFixture) ack(t *testing.T, p *InvocationStreamProjection) {
	t.Helper()
	f.req.ProjectionOrdinal = p.Ordinal
	f.req.Digest = p.Digest
	if err := f.j.ackInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req); err != nil {
		t.Fatal(err)
	}
}

func TestInvocationStreamSmallOriginalOutputBeforeCompletionAndExactCredit(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnStarted, "")
	f.event(t, session.EventTurnOutput, "original private text €")
	p := f.projection(t)
	if p == nil {
		t.Fatal("subthreshold original text not projected")
	}
	r := f.open(t, p)
	if string(r.Data) != "original private text €" || r.Terminal != nil || r.Proof.DeltaCount != 1 {
		t.Fatal("invented completion or changed original output")
	}
	f.event(t, session.EventTurnOutput, " continued")
	if next := f.projection(t); !reflect.DeepEqual(p, next) {
		t.Fatal("unacknowledged ciphertext replaced")
	}
	bad := f.req
	bad.ProjectionOrdinal = p.Ordinal
	bad.Digest = "foreign"
	if err := f.j.ackInvocationStream(context.Background(), f.o.captureKey, f.lease, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("forged ACK accepted", err)
	}
	f.ack(t, p)
	f.ack(t, p)
	next := f.projection(t)
	if next == nil || next.Ordinal != 2 || string(f.open(t, next).Data) != " continued" {
		t.Fatal("exact ACK skipped or replayed bytes")
	}
	f.ack(t, next)
	f.event(t, session.EventTurnCompleted, "")
	terminal := f.projection(t)
	tr := f.open(t, terminal)
	if tr.Terminal == nil || tr.Terminal.Event.Type != session.EventTurnCompleted || tr.Terminal.SourceSequence == 0 || len(tr.Data) != 0 {
		t.Fatal("missing actual committed terminal")
	}
	f.ack(t, terminal)
	if err := f.j.unsubscribeInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req); err != nil {
		t.Fatal(err)
	}
	if n := sourceCount(t, f.j, "worker_invocation_stream_deltas"); n != 0 {
		t.Fatal("ACK retained delivered frames", n)
	}
	var capacity int
	if err := f.j.db.QueryRow(`SELECT bytes FROM worker_invocation_stream_capacity`).Scan(&capacity); err != nil || capacity != 0 {
		t.Fatal("capacity refund", err, capacity)
	}
	if n := sourceCount(t, f.j, "worker_turn_sources"); n != 1 {
		t.Fatal("stream ACK erased source authority")
	}
}
func TestInvocationStreamNoDeltaGenuineTerminalUsesOriginalPinnedEpoch(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	if err := os.Rename(f.o.spec.NetworkStateDir, f.o.spec.NetworkStateDir+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	f.event(t, session.EventTurnStarted, "")
	f.event(t, session.EventTurnCompleted, "")
	p := f.projection(t)
	if p == nil {
		t.Fatal("final-only native source not delivered")
	}
	r := f.open(t, p)
	if len(r.Data) != 0 || r.Terminal == nil || r.Proof.DeltaCount != 0 || r.Proof.StreamID != "" || p.AAD.KeyEpochID != f.source.SourceInvocation.InputAAD.KeyEpochID {
		t.Fatal("fabricated output or reconnect-key substitution")
	}
	f.ack(t, p)
}
func TestInvocationStreamReopenLostAckAndLeaseFencing(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnOutput, "captured before reconnect")
	p := f.projection(t)
	oldReq, oldLease := f.req, f.lease
	f.retire()
	f.o.nativeObserverWG.Wait()
	if err := f.j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(f.j.dir, f.j.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.j = j
	f.o.journal = j
	f.lease = lease(t, j)
	f.subscribe(t)
	if _, err = j.readInvocationStream(context.Background(), f.o.captureKey, oldLease, oldReq); !errors.Is(err, ErrFenced) {
		t.Fatal("old lease retained consumer authority", err)
	}
	if recovered := f.projection(t); !reflect.DeepEqual(recovered, p) {
		t.Fatal("reopen changed original pending ciphertext")
	}
	f.ack(t, p)
	// Lose the successful ACK response, then reopen again and repeat that exact ACK.
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(j.dir, j.scope)
	if err != nil {
		t.Fatal(err)
	}
	f.j = j
	f.o.journal = j
	f.lease = lease(t, j)
	f.subscribe(t)
	f.ack(t, p)
	if next := f.projection(t); next != nil {
		t.Fatal("lost ACK response replayed original bytes")
	}
}
func TestInvocationStreamExpiryAndDeletionFence(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnOutput, "original retained output")
	_ = f.projection(t)
	if _, err := f.j.db.Exec(`DELETE FROM worker_turn_sources WHERE sequence=1`); err == nil {
		t.Fatal("pending ledger source deleted")
	}
	if _, err := f.j.db.Exec(`UPDATE worker_invocation_stream_subscriptions SET expires_at=?`, time.Now().Add(-time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.j.subscribeInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req); !errors.Is(err, ErrInvocationStreamExpired) {
		t.Fatal("expired consumer resurrected", err)
	}
	if err := f.o.projectInvocationStreams(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := sourceCount(t, f.j, "worker_invocation_stream_deltas"); n != 0 {
		t.Fatal("expired delivery retained delta quota")
	}
	if n := sourceCount(t, f.j, "worker_turn_sources"); n != 1 {
		t.Fatal("expiry erased original proof")
	}
	if _, err := f.j.db.Exec(`DELETE FROM worker_turn_sources WHERE sequence=1`); err != nil {
		t.Fatal("closed ledger prevents authorized source cleanup", err)
	}
	if n := sourceCount(t, f.j, "worker_invocation_streams"); n != 0 {
		t.Fatal("deleted source left orphan checkpoint")
	}
}

func TestInvocationStreamWindowExhaustionDoesNotCancelOriginalNativeCapture(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnStarted, "")
	// Simulate a configured finite window using a transaction-local reservation
	// fence. Counters still equal the actual retained encrypted rows throughout.
	if _, err := f.j.db.Exec(`CREATE TRIGGER stream_test_small_window BEFORE UPDATE ON worker_invocation_stream_capacity WHEN NEW.rows>2 BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	f.event(t, session.EventTurnOutput, "first")
	pending := f.projection(t)
	f.event(t, session.EventTurnOutput, "second")
	f.event(t, session.EventTurnOutput, "third exceeds auxiliary delivery only")
	if actual := f.projection(t); !reflect.DeepEqual(actual, pending) {
		t.Fatal("exhaustion replaced already pending original cipher")
	}
	f.ack(t, pending)
	gap := f.projection(t)
	r := f.open(t, gap)
	if r.DeliveryError != "delivery_window_exhausted" || len(r.Data) != 0 || r.Terminal != nil || r.ByteOffset != 5 {
		t.Fatal("delivery loss fabricated business outcome or cursor")
	}
	f.ack(t, gap)
	f.event(t, session.EventTurnOutput, "fourth native output remains capturable")
	f.event(t, session.EventTurnCompleted, "")
	var observations []NativeObservation
	observations, err := f.j.PendingObservations(context.Background(), 32)
	if err != nil {
		t.Fatal(err)
	}
	foundFinal, foundOutput := false, false
	for _, o := range observations {
		foundFinal = foundFinal || o.Event.Type == session.EventTurnCompleted
		foundOutput = foundOutput || o.OutputContent != nil
	}
	if !foundFinal || !foundOutput {
		t.Fatal("auxiliary exhaustion lost genuine original output/final")
	}
	tx, err := f.j.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	h, err := f.j.readInvocationCheckpoint(context.Background(), tx, f.o.captureKey, f.req.Source)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(h.Key)
	if h.Terminal == nil || h.Terminal.Event.Type != session.EventTurnCompleted || h.Terminal.SourceSequence == 0 || h.Cursor.Bytes != 5 {
		t.Fatal("final receipt/cursor lost after delivery failed")
	}
}

func TestInvocationStreamProjectionRollbackAndUTF8PartialFrame(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	text := string(bytes.Repeat([]byte("€"), 30000))
	f.event(t, session.EventTurnOutput, text)
	if _, err := f.j.db.Exec(`CREATE TRIGGER stream_test_projection_fail BEFORE UPDATE ON worker_invocation_streams BEGIN SELECT RAISE(ABORT,'projection commit failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.o.projectInvocationStreams(context.Background()); err == nil {
		t.Fatal("failed projection published")
	}
	if p, err := f.j.readInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req); err != nil || p != nil {
		t.Fatal("failed projection escaped FULL boundary", err)
	}
	if _, err := f.j.db.Exec(`DROP TRIGGER stream_test_projection_fail`); err != nil {
		t.Fatal(err)
	}
	first := f.projection(t)
	a := f.open(t, first)
	f.ack(t, first)
	second := f.projection(t)
	b := f.open(t, second)
	f.ack(t, second)
	if !utf8.Valid(a.Data) || !utf8.Valid(b.Data) || string(append(a.Data, b.Data...)) != text || b.ByteOffset != int64(len(a.Data)) {
		t.Fatal("partial frame changed UTF8/cursor or duplicated bytes")
	}
	if sourceCount(t, f.j, "worker_invocation_stream_deltas") != 0 {
		t.Fatal("last partial-frame ACK retained deltas")
	}
}

func TestInvocationStreamTimerProjectsOriginalLowVolumeWithoutSyntheticEvent(t *testing.T) {
	f := newInvocationStreamFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.o.ctx = ctx
	f.o.runInvocationStreamTimer()
	defer func() { cancel(); f.o.wg.Wait() }()
	f.subscribe(t)
	before := sourceCount(t, f.j, "worker_observations")
	f.event(t, session.EventTurnOutput, "real original small delta")
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		p, err := f.j.readInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req)
		if err != nil {
			t.Fatal(err)
		}
		if p != nil {
			r := f.open(t, p)
			if string(r.Data) != "real original small delta" || r.Terminal != nil {
				t.Fatal("timer fabricated text/completion")
			}
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("worker timer did not flush committed subthreshold bytes")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if after := sourceCount(t, f.j, "worker_observations"); after != before {
		t.Fatal("stream projection consumed ordinary native observation quota", before, after)
	}
}
func TestInvocationStreamProtectedIdentityAndCurrentLease(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnOutput, "original")
	bad := f.req
	bad.Source.SourceAdmissionID = uuid.NewString()
	if _, err := f.j.subscribeInvocationStream(context.Background(), f.o.captureKey, f.lease, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("relabelled original admission accepted", err)
	}
	p := f.projection(t)
	if _, err := OpenInvocationStreamProjection(*p, f.source, uuid.NewString(), f.epochKey); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign instance decrypted projection", err)
	}
	old := f.lease
	f.lease = lease(t, f.j)
	if _, err := f.j.invocationStreamStatus(context.Background(), f.o.captureKey, old, f.req); !errors.Is(err, ErrFenced) {
		t.Fatal("old controller status authorized", err)
	}
	if _, err := f.j.invocationStreamStatus(context.Background(), f.o.captureKey, f.lease, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign source status authorized", err)
	}
	if response := f.o.controllerRequest(context.Background(), old, Request{Type: "invocation_read", InvocationStream: &f.req}); response.Error == "" {
		t.Fatal("private read RPC bypassed lease fence")
	}
}

func TestInvocationStreamACKAndExpiryPermitOnlySettledOwnershipRetirement(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "ack", true: "expiry"}[expired], func(t *testing.T) {
			f := newInvocationStreamFixture(t)
			f.subscribe(t)
			f.event(t, session.EventTurnStarted, "")
			f.event(t, session.EventTurnCompleted, "")
			pending := f.projection(t)
			ctx := context.Background()
			if err := f.j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			observations, err := f.j.PendingObservations(ctx, 32)
			if err != nil {
				t.Fatal(err)
			}
			f.retire()
			f.o.nativeObserverWG.Wait()
			for _, observation := range observations {
				if err = f.j.AcknowledgeObservation(ctx, f.lease, observation.ID, observation.SourceDigest); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.j.Acknowledge(ctx, f.lease, 1); err != nil {
				t.Fatal(err)
			}
			if sourceCount(t, f.j, "worker_turn_sources") != 1 {
				t.Fatal("ordinary ACK dropped pending stream source")
			}
			ownership := transport.NativeWorkerOwnership{ID: uuid.NewString(), InstanceID: f.j.scope.InstanceID, OwnershipGeneration: f.j.scope.Generation, Runtime: "fake-persistent", OriginalAdmissionID: uuid.NewString(), State: "active", ProfileFingerprint: string(bytes.Repeat([]byte("a"), 64))}
			if err = f.j.BindDispatchOwnership(ctx, f.lease, ownership, ownership.Runtime, ownership.ProfileFingerprint); err != nil {
				t.Fatal(err)
			}
			ownership.State = "retired"
			if err = f.j.CommitOwnershipRetirement(ctx, f.lease, ownership); !errors.Is(err, ErrConflict) {
				t.Fatal("retired owner with retained stream proof", err)
			}
			if expired {
				if _, err = f.j.db.Exec(`UPDATE worker_invocation_stream_subscriptions SET expires_at=?`, time.Now().Add(-time.Second).UnixNano()); err != nil {
					t.Fatal(err)
				}
				if err = f.o.projectInvocationStreams(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				f.ack(t, pending)
			}
			if sourceCount(t, f.j, "worker_turn_sources") != 0 || sourceCount(t, f.j, "worker_invocation_streams") != 0 || sourceCount(t, f.j, "worker_invocation_stream_subscriptions") != 0 {
				t.Fatal("settled delivery left original-source or ledger orphans")
			}
			if err = f.j.CommitOwnershipRetirement(ctx, f.lease, ownership); err != nil {
				t.Fatal("fully proven settled owner cannot retire", err)
			}
		})
	}
}

func TestInvocationStreamDeliveryCancellationKeepsGenuineStoppedReceipt(t *testing.T) {
	f := newInvocationStreamFixture(t)
	f.subscribe(t)
	f.event(t, session.EventTurnStarted, "")
	if err := f.j.unsubscribeInvocationStream(context.Background(), f.o.captureKey, f.lease, f.req); err != nil {
		t.Fatal(err)
	}
	state, err := f.j.invocationStreamStatus(context.Background(), f.o.captureKey, f.lease, f.req)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Closed || state.DeliveryError != "consumer_cancelled" || state.Terminal != nil {
		t.Fatal("delivery cancellation fabricated native outcome")
	}
	f.event(t, session.EventSessionStopped, "")
	state, err = f.j.invocationStreamStatus(context.Background(), f.o.captureKey, f.lease, f.req)
	if err != nil {
		t.Fatal(err)
	}
	if state.Terminal == nil || state.Terminal.Event.Type != session.EventSessionStopped || state.Terminal.SourceSequence == 0 || state.Terminal.NativeSessionID != f.source.NativeSessionID {
		t.Fatal("closed delivery lost subsequent genuine original stopped receipt")
	}
}
