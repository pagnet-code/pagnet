//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

type resourceFixture struct {
	journal     *Journal
	dir         string
	lease       int64
	producer    *nativeSourceProducer
	observation NativeObservation
	receipt     transport.NativeObservationReceiptPayload
	proof       transport.NativeDispatchProof
	key         []byte
	payload     json.RawMessage
}

func acceptedResourceFixture(t *testing.T) resourceFixture {
	t.Helper()
	j, dir := testJournal(t)
	l := lease(t, j)
	own := dispatchOwnership(t, j, l)
	proof := dispatchProof(own, 1)
	admission := &Admission{Scope: j.scope, NativeAdmissionID: proof.SourceAdmissionID, RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID, Kind: "worker", NetworkID: "original-network"}
	payload := json.RawMessage(`{"inputKind":"task","input":"private original task"}`)
	out, run, err := j.admitDispatch(t.Context(), l, 0, proof.SourceCommandID, "prompt", payload, func() (*Admission, error) { return admission, nil }, &proof)
	if err != nil || !run {
		t.Fatal(out, run, err)
	}
	source := NativeTurnSource{Sequence: out.Sequence, LogicalTurnID: logicalWorkerTurn(out.Sequence), NativeGeneration: "original-native", NativeSessionID: "original-session", SourceCommandID: proof.SourceCommandID, SourceAdmissionID: proof.SourceAdmissionID, InputKind: "task"}
	if err = j.BindNativeTurn(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	origin := transport.NativeObservationOrigin{ID: domain.NewID().String(), TenantID: j.scope.TenantID, HostID: j.scope.HostID, InstanceID: j.scope.InstanceID, Runtime: "fake-persistent", NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, CommandID: domain.NewID().String(), NativeAdmissionID: domain.NewID().String(), RunnerID: proof.SourceRunnerID, RunnerEpoch: proof.SourceRunnerEpoch, BootID: proof.SourceBootID}
	raw, _ := json.Marshal(origin)
	p, err := j.registerNativeSource(t.Context(), source.NativeGeneration, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.recordNativeResourceInterruption(t.Context(), p, source, transport.NativeResourceOutputLimit); err != nil {
		t.Fatal(err)
	}
	marker, err := j.nativeResourceInterruption(t.Context(), source.NativeGeneration)
	if err != nil {
		t.Fatal(err)
	}
	o := NativeObservation{ID: domain.NewID().String(), NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, Origin: raw, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventSessionStopped, SessionID: source.NativeSessionID}, ResourceInterruption: marker}
	o.SourceDigest, _ = observationDigest(o)
	if err = j.journalCapturedObservation(t.Context(), p, o, nil); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingObservations(t.Context(), 32)
	if err != nil || len(pending) != 1 {
		t.Fatal(pending, err)
	}
	o = pending[0]
	wire, err := NativeBackendObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	receipt := transport.NativeObservationReceiptPayload{ObservationID: o.ID, OriginID: wire.OriginID, Digest: wire.Digest, Disposition: "committed"}
	return resourceFixture{j, dir, l, p, o, receipt, proof, bytes.Repeat([]byte{7}, 32), payload}
}
func (f resourceFixture) ack(t *testing.T) error {
	t.Helper()
	return f.journal.acknowledgeObservation(t.Context(), f.lease, f.observation.ID, f.observation.SourceDigest, &f.receipt, f.key)
}
func TestResourceInterruptionRequiresExactCommittedOriginalEOF(t *testing.T) {
	for _, negative := range []string{"live-reader", "missing-receipt", "staged", "expired", "foreign-origin", "wrong-digest", "different-marker", "missing-marker", "wrong-command", "unknown-admission", "pending-output"} {
		t.Run(negative, func(t *testing.T) {
			f := acceptedResourceFixture(t)
			j := f.journal
			if negative != "live-reader" {
				if err := j.retireNativeSource(t.Context(), f.producer); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.Settle(t.Context(), 1, "uncertain", json.RawMessage(`{"error":"native operation failed"}`)); err != nil {
				t.Fatal(err)
			}
			r := &f.receipt
			switch negative {
			case "missing-receipt":
				r = nil
			case "staged":
				r.Disposition = "staged"
			case "expired":
				r.Disposition = "expired"
			case "foreign-origin":
				r.OriginID = domain.NewID().String()
			case "wrong-digest":
				r.Digest = string(bytes.Repeat([]byte{'a'}, 64))
			case "different-marker":
				j.db.Exec(`UPDATE worker_resource_interruptions SET payload=json_set(payload,'$.cause','capture_limit')`)
			case "missing-marker":
				j.db.Exec(`DELETE FROM worker_resource_interruptions`)
			case "wrong-command":
				j.db.Exec(`UPDATE worker_turn_sources SET source_command='foreign'`)
			case "unknown-admission":
				j.db.Exec(`UPDATE worker_intent_admission SET admission=json_set(admission,'$.nativeAdmissionId','foreign')`)
			case "pending-output":
				// Uncommitted earlier output cannot be erased by a later EOF receipt.
				pending := f.observation
				pending.ID = domain.NewID().String()
				pending.ResourceInterruption = nil
				pending.Event = session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, SessionID: pending.NativeSessionID, TurnID: logicalWorkerTurn(1)}
				pending.TurnSource = &NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: pending.NativeGeneration, NativeSessionID: pending.NativeSessionID, SourceCommandID: f.proof.SourceCommandID, SourceAdmissionID: f.proof.SourceAdmissionID, InputKind: "task"}
				pending.SourceDigest, _ = observationDigest(pending)
				raw, _ := json.Marshal(pending)
				if _, err := j.db.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, pending.ID, pending.SourceDigest, raw, len(raw)); err != nil {
					t.Fatal(err)
				}
			}
			if err := j.acknowledgeObservation(t.Context(), f.lease, f.observation.ID, f.observation.SourceDigest, r, f.key); err == nil {
				t.Fatal("unproven resource interruption settled", negative)
			}
			out, err := j.Outcome(t.Context(), 1)
			if err != nil || out.State != "uncertain" {
				t.Fatal("uncertainty changed", out, err)
			}
			if sourceCount(t, j, "worker_resource_settlements") != 0 || sourceCount(t, j, "worker_observations") == 0 {
				t.Fatal("original evidence removed")
			}
		})
	}
}
func TestResourceInterruptionAtomicRollbackLostReplyReopenAndNoReplay(t *testing.T) {
	f := acceptedResourceFixture(t)
	j := f.journal
	if err := j.retireNativeSource(t.Context(), f.producer); err != nil {
		t.Fatal(err)
	}
	if err := j.Settle(t.Context(), 1, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`CREATE TRIGGER fail_resource_ack BEFORE DELETE ON worker_observations BEGIN SELECT RAISE(ABORT,'rollback resource receipt'); END`); err != nil {
		t.Fatal(err)
	}
	if err := f.ack(t); err == nil {
		t.Fatal("failed transaction acknowledged")
	}
	out, _ := j.Outcome(t.Context(), 1)
	if out.State != "uncertain" || sourceCount(t, j, "worker_resource_settlements") != 0 || sourceCount(t, j, "worker_resource_interruptions") != 1 {
		t.Fatal("rollback lost original", out)
	}
	j.db.Exec(`DROP TRIGGER fail_resource_ack`)
	if err := f.ack(t); err != nil {
		t.Fatal(err)
	}
	if err := j.Settle(t.Context(), 1, "uncertain", json.RawMessage(`{"error":"late native result"}`)); err != nil {
		t.Fatal("late finish overwrote proof", err)
	}
	// COMMIT reply is deliberately lost; a fresh controller replays the exact ACK.
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(filepath.Clean(f.dir), testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.journal = reopened
	f.lease = lease(t, reopened)
	if err = f.ack(t); err != nil {
		t.Fatal("lost reply did not replay", err)
	}
	out, err = reopened.Outcome(t.Context(), 1)
	if err != nil || out.State != ResourceInterrupted {
		t.Fatal(out, err)
	}
	if _, run, err := reopened.admitDispatch(t.Context(), f.lease, 0, f.proof.SourceCommandID, "prompt", f.payload, nil, &f.proof); err != nil || run {
		t.Fatal("interrupted effect replayed", run, err)
	}
	if sourceCount(t, reopened, "worker_resource_settlements") != 1 || sourceCount(t, reopened, "worker_resource_interruptions") != 0 {
		t.Fatal("proof not bounded/preserved")
	}
	if err = reopened.Acknowledge(t.Context(), f.lease, 1); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, reopened, "worker_resource_settlements") != 1 {
		t.Fatal("outcome ACK erased cloudfloor evidence")
	}
	if err = reopened.RetireDispatches(t.Context(), f.lease, 1); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, reopened, "worker_resource_settlements") != 0 {
		t.Fatal("retired evidence retained lifetime tombstone")
	}
}
func TestResourceInterruptionReceiptRaceCannotBeOverwrittenByLateFinish(t *testing.T) {
	for i := 0; i < 12; i++ {
		f := acceptedResourceFixture(t)
		if err := f.journal.retireNativeSource(t.Context(), f.producer); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		errs := make(chan error, 2)
		go func() { defer wg.Done(); errs <- f.ack(t) }()
		go func() { defer wg.Done(); errs <- f.journal.Settle(t.Context(), 1, "uncertain", nil) }()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		out, err := f.journal.Outcome(t.Context(), 1)
		if err != nil || out.State != ResourceInterrupted {
			t.Fatal(out, err)
		}
	}
}
func TestGenericSettlementCannotInventResourceInterruption(t *testing.T) {
	j, _ := testJournal(t)
	l := lease(t, j)
	if _, run, err := j.Admit(t.Context(), l, 1, "original", "prompt", json.RawMessage(`{}`)); err != nil || !run {
		t.Fatal(err)
	}
	if err := j.Settle(t.Context(), 1, ResourceInterrupted, nil); err == nil {
		t.Fatal("generic source invented proof")
	}
	if err := j.Settle(t.Context(), 1, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if err := j.AcknowledgeObservation(t.Context(), l, "unknown", string(bytes.Repeat([]byte{'a'}, 64))); err != nil && !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestResourceInterruptionRetirementWaitsOriginalLocalFinish(t *testing.T) {
	f := acceptedResourceFixture(t)
	if err := f.journal.retireNativeSource(t.Context(), f.producer); err != nil {
		t.Fatal(err)
	}
	if err := f.ack(t); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.Acknowledge(t.Context(), f.lease, 1); err == nil {
		t.Fatal("outcome ACK outran original local finish")
	}
	if err := f.journal.RetireDispatches(t.Context(), f.lease, 1); err == nil {
		t.Fatal("cloudfloor outran original local finish")
	}
	if err := f.journal.Settle(t.Context(), 1, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.Acknowledge(t.Context(), f.lease, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.RetireDispatches(t.Context(), f.lease, 1); err != nil {
		t.Fatal(err)
	}
}
