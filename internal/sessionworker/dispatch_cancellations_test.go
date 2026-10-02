//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"reflect"
	"sync"
	"testing"
	"time"
)

func cancellationFixture(t *testing.T) (*Journal, string, int64, transport.NativeDispatchCancellationProposal) {
	t.Helper()
	j, dir := testJournal(t)
	a := lease(t, j)
	o := transport.NativeWorkerOwnership{ID: domain.NewID().String(), InstanceID: j.scope.InstanceID, OwnershipGeneration: j.scope.Generation, State: "active"}
	raw, _ := json.Marshal(o)
	for _, query := range []string{`CREATE TABLE worker_dispatch_meta(singleton INTEGER PRIMARY KEY,ownership TEXT,last_sequence INTEGER,retired INTEGER)`, `CREATE TABLE worker_dispatches(dispatch_sequence INTEGER PRIMARY KEY,operation_sequence INTEGER,command_id TEXT,proof BLOB,state TEXT)`} {
		if _, err := j.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.db.Exec(`INSERT INTO worker_dispatch_meta VALUES(1,?,0,0)`, string(raw)); err != nil {
		t.Fatal(err)
	}
	p := transport.NativeDispatchCancellationProposal{InstanceID: j.scope.InstanceID, CommandType: "host.agent_input", Reason: "expired", Proof: transport.NativeDispatchProof{OwnershipID: o.ID, OwnershipGeneration: j.scope.Generation, DispatchSequence: 1, SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), SourceRunnerID: domain.NewID().String(), SourceRunnerEpoch: time.Now().UTC(), SourceBootID: domain.NewID().String()}}
	return j, dir, a, p
}
func cancellationReceipt(r DispatchCancellationPreparation) transport.NativeDispatchCancelledPayload {
	p := r.Proposal.Proof
	return transport.NativeDispatchCancelledPayload{RequestID: r.Request.RequestID, PreparationID: r.Request.PreparationID, InstanceID: r.Request.InstanceID, Proof: &p, Disposition: "cancelled"}
}
func TestDispatchCancellationDurablePrepareFinalizeAndBoundedRetirement(t *testing.T) {
	j, dir, a, p := cancellationFixture(t)
	ctx := context.Background()
	prep, err := j.PrepareDispatchCancellation(ctx, a, p)
	if err != nil {
		t.Fatal(err)
	}
	same, err := j.PrepareDispatchCancellation(ctx, a, p)
	if err != nil || !reflect.DeepEqual(prep, same) {
		t.Fatal("lost prepare response changed original", err)
	}
	if _, effect, err := j.Admit(ctx, a, 1, p.Proof.SourceCommandID, "prompt", json.RawMessage(`{}`)); err == nil || effect {
		t.Fatal("late original input crossed cancellation fence")
	}
	tx, _ := j.db.BeginTx(ctx, nil)
	err = CheckDispatchCancellationTx(ctx, tx, p.Proof)
	tx.Rollback()
	if !errors.Is(err, ErrConflict) {
		t.Fatal("owned ordinal bypassed fence", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	b := lease(t, j)
	same, err = j.PrepareDispatchCancellation(ctx, b, p)
	if err != nil || !reflect.DeepEqual(prep, same) {
		t.Fatal("reopen lost original prepare", err)
	}
	valid := cancellationReceipt(prep)
	for _, field := range []string{"prep", "request", "instance", "command", "admission", "ordinal", "disposition"} {
		bad := valid
		proof := *valid.Proof
		bad.Proof = &proof
		switch field {
		case "prep":
			bad.PreparationID = domain.NewID().String()
		case "request":
			bad.RequestID = domain.NewID().String()
		case "instance":
			bad.InstanceID = "foreign"
		case "command":
			proof.SourceCommandID = domain.NewID().String()
		case "admission":
			proof.SourceAdmissionID = domain.NewID().String()
		case "ordinal":
			proof.DispatchSequence++
		case "disposition":
			bad.Disposition = "proposed"
		}
		if err = j.FinalizeDispatchCancellation(ctx, b, bad); err == nil {
			t.Fatal("false finalize accepted", field)
		}
	}
	tx, _ = j.db.BeginTx(ctx, nil)
	tx.Exec(`UPDATE worker_dispatch_meta SET retired=1`)
	err = RetireDispatchCancellationsTx(ctx, tx, p.Proof.OwnershipID, 1)
	tx.Rollback()
	if !errors.Is(err, ErrConflict) {
		t.Fatal("prepared uncertainty reclaimed", err)
	}
	if err = j.FinalizeDispatchCancellation(ctx, a, valid); !errors.Is(err, ErrFenced) {
		t.Fatal("stale finalize accepted", err)
	}
	if err = j.FinalizeDispatchCancellation(ctx, b, valid); err != nil {
		t.Fatal(err)
	}
	if err = j.FinalizeDispatchCancellation(ctx, b, valid); err != nil {
		t.Fatal(err)
	}
	// More than the active metadata bound can settle over the ownership lifetime.
	for seq := int64(1); seq <= 140; seq++ {
		if seq > 1 {
			p.Proof.DispatchSequence = seq
			p.Proof.SourceCommandID = domain.NewID().String()
			prep, err = j.PrepareDispatchCancellation(ctx, b, p)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.FinalizeDispatchCancellation(ctx, b, cancellationReceipt(prep)); err != nil {
				t.Fatal(err)
			}
		}
		tx, _ = j.db.BeginTx(ctx, nil)
		tx.Exec(`UPDATE worker_dispatch_meta SET last_sequence=?,retired=?`, seq, seq)
		if err = RetireDispatchCancellationsTx(ctx, tx, p.Proof.OwnershipID, seq); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var intents, markers int
	j.db.QueryRow(`SELECT COUNT(*) FROM worker_intent`).Scan(&intents)
	j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatch_cancellations`).Scan(&markers)
	if intents != 0 || markers != 0 {
		t.Fatal("cancellation invented native outcomes or lifetime tombstones")
	}
	if _, err = j.PrepareDispatchCancellation(ctx, b, p); !errors.Is(err, ErrConflict) {
		t.Fatal("retired original ordinal resurrected", err)
	}
}
func TestDispatchCancellationRefusesAcceptedAndUncertainMapping(t *testing.T) {
	for _, state := range []string{"admitted", "completed", "failed", "uncertain"} {
		t.Run(state, func(t *testing.T) {
			j, _, a, p := cancellationFixture(t)
			defer j.Close()
			_, _, err := j.Admit(t.Context(), a, 1, p.Proof.SourceCommandID, "prompt", json.RawMessage(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			j.db.Exec(`UPDATE worker_intent SET state=?`, state)
			if _, err = j.PrepareDispatchCancellation(t.Context(), a, p); !errors.Is(err, ErrConflict) {
				t.Fatal("accepted effect cancelled", state, err)
			}
		})
	}
	t.Run("ordinal", func(t *testing.T) {
		j, _, a, p := cancellationFixture(t)
		defer j.Close()
		j.db.Exec(`INSERT INTO worker_dispatches VALUES(1,1,'other',NULL,'uncertain')`)
		if _, err := j.PrepareDispatchCancellation(t.Context(), a, p); !errors.Is(err, ErrConflict) {
			t.Fatal("occupied ordinal cancelled", err)
		}
	})
}
func TestDispatchCancellationRacesAdmissionAndFailedPrepareCommit(t *testing.T) {
	for i := 0; i < 20; i++ {
		j, _, a, p := cancellationFixture(t)
		var wg sync.WaitGroup
		wg.Add(2)
		var prepared, effect bool
		go func() {
			defer wg.Done()
			_, err := j.PrepareDispatchCancellation(t.Context(), a, p)
			prepared = err == nil
		}()
		go func() {
			defer wg.Done()
			_, execute, err := j.Admit(t.Context(), a, 1, p.Proof.SourceCommandID, "prompt", json.RawMessage(`{}`))
			effect = err == nil && execute
		}()
		wg.Wait()
		if prepared == effect {
			t.Fatal("prepare/admit not linear", prepared, effect)
		}
		j.Close()
	}
	j, _, a, p := cancellationFixture(t)
	defer j.Close()
	j.db.Exec(`CREATE TRIGGER fail_prepare BEFORE INSERT ON worker_dispatch_cancellations BEGIN SELECT RAISE(ABORT,'isolated failure'); END`)
	if _, err := j.PrepareDispatchCancellation(t.Context(), a, p); err == nil {
		t.Fatal("failed commit created prep")
	}
	j.db.Exec(`DROP TRIGGER fail_prepare`)
	if _, effect, err := j.Admit(t.Context(), a, 1, p.Proof.SourceCommandID, "prompt", json.RawMessage(`{}`)); err != nil || !effect {
		t.Fatal("failed marker fenced unaccepted input", err)
	}
}
