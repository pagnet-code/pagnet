package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/pagnet-code/pagnet/transport"
)

// CommitOwnershipRetirement fences every later local intent before an owned
// worker can exit or its private files can be collected. Backend retirement is
// required; neither a missing PID nor a cloud deletion request is that proof.
func (j *Journal) CommitOwnershipRetirement(ctx context.Context, lease int64, proof transport.NativeWorkerOwnership) error {
	if proof.State != "retired" || proof.LastDispatchSequence != proof.RetiredFloor || proof.InstanceID != j.scope.InstanceID || proof.OwnershipGeneration != j.scope.Generation {
		return ErrConflict
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return err
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_ownership_retirement WHERE singleton=1`).Scan(&previous)
	if err == nil {
		if !reflect.DeepEqual(previous, raw) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}
	var original string
	var last, floor int64
	if err = tx.QueryRowContext(ctx, `SELECT ownership,last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&original, &last, &floor); err != nil {
		return err
	}
	var bound transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(original), &bound) != nil {
		return ErrConflict
	}
	normalized := proof
	normalized.State = "active"
	normalized.LastDispatchSequence = 0
	normalized.RetiredFloor = 0
	if !reflect.DeepEqual(bound, normalized) || last != proof.LastDispatchSequence || floor != proof.RetiredFloor {
		return ErrConflict
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_intent) OR EXISTS(SELECT 1 FROM worker_dispatches) OR EXISTS(SELECT 1 FROM worker_dispatch_cancellations) OR EXISTS(SELECT 1 FROM worker_observations) OR EXISTS(SELECT 1 FROM worker_turn_sources) OR EXISTS(SELECT 1 FROM worker_source_registration WHERE quiesced=0)`).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_ownership_retirement VALUES(1,?)`, raw); err != nil {
		return err
	}
	return tx.Commit()
}

func (o *SessionOwner) prepareOwnershipRetirement(ctx context.Context, lease int64, proof *transport.NativeWorkerOwnership) error {
	if proof == nil {
		return ErrConflict
	}
	snapshot := o.Snapshot()
	if snapshot.IdentityPending || snapshot.PID != 0 || snapshot.HasTerminal || len(snapshot.Pending) != 0 {
		return ErrNativeBusy
	}
	o.relay.mu.Lock()
	pending := len(o.relay.pending) != 0 || o.relay.activation != nil
	o.relay.mu.Unlock()
	if pending {
		return ErrNativeBusy
	}
	if err := o.journal.CommitOwnershipRetirement(ctx, lease, *proof); err != nil {
		return err
	}
	o.mu.Lock()
	o.closing = true
	o.mu.Unlock()
	return nil
}
