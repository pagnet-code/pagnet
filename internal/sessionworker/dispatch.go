package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrDispatchGap = errors.New("earlier native dispatch must arrive first")

func (j *Journal) initializeDispatches() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_dispatch_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),ownership TEXT NOT NULL,last_sequence INTEGER NOT NULL,retired INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_dispatches(dispatch_sequence INTEGER PRIMARY KEY,operation_sequence INTEGER NOT NULL UNIQUE,command_id TEXT NOT NULL UNIQUE,proof BLOB NOT NULL,state TEXT NOT NULL DEFAULT 'admitted')`,
		`CREATE TRIGGER IF NOT EXISTS worker_dispatch_settle AFTER UPDATE OF state ON worker_intent BEGIN UPDATE worker_dispatches SET state=NEW.state WHERE operation_sequence=NEW.sequence; END`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	var last, retired, count int64
	err := j.db.QueryRow(`SELECT last_sequence,retired,(SELECT COUNT(*) FROM worker_dispatches) FROM worker_dispatch_meta WHERE singleton=1`).Scan(&last, &retired, &count)
	if errors.Is(err, sql.ErrNoRows) {
		var orphaned int
		if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatches`).Scan(&orphaned); err != nil {
			return err
		}
		if orphaned != 0 {
			return ErrConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if last < retired || retired < 0 || last-retired != count || count > maxCommands {
		return ErrConflict
	}
	var invalid int
	var ownership string
	if err = j.db.QueryRow(`SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownership); err != nil {
		return err
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownership), &o) != nil || o.InstanceID != j.scope.InstanceID || o.OwnershipGeneration != j.scope.Generation {
		return ErrConflict
	}
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatches WHERE dispatch_sequence<=? OR dispatch_sequence>? OR operation_sequence<=0 OR operation_sequence>=(SELECT next_sequence FROM worker_meta WHERE singleton=1) OR state NOT IN ('admitted','completed','failed','uncertain') OR json_extract(proof,'$.ownershipId') IS NOT ? OR json_extract(proof,'$.ownershipGeneration') IS NOT ? OR json_extract(proof,'$.dispatchSequence') IS NOT dispatch_sequence OR json_extract(proof,'$.sourceCommandId') IS NOT command_id`, retired, last, o.ID, j.scope.Generation).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return ErrConflict
	}
	return nil
}

// BindDispatchOwnership pins server ownership to this exact worker profile.
// Transport replacement cannot bind a different ownership to the same worker.
func (j *Journal) BindDispatchOwnership(ctx context.Context, lease int64, o transport.NativeWorkerOwnership, runtime, profileFingerprint string) error {
	if _, err := domain.ParseID(o.ID); err != nil {
		return ErrConflict
	}
	if _, err := domain.ParseID(o.OriginalAdmissionID); err != nil {
		return ErrConflict
	}
	if o.InstanceID != j.scope.InstanceID || o.OwnershipGeneration != j.scope.Generation || o.Runtime != runtime || o.ProfileFingerprint != profileFingerprint || len(profileFingerprint) != 64 || o.State != "active" {
		return ErrConflict
	}
	// Sequence counters are mutable server metadata, never local allocation input.
	o.LastDispatchSequence, o.RetiredFloor = 0, 0
	raw, err := json.Marshal(o)
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
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT ownership FROM worker_dispatch_meta WHERE singleton=1`).Scan(&existing)
	if err == nil {
		if existing != string(raw) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var unbound int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_intent WHERE kind IN ('activate','prompt')`).Scan(&unbound); err != nil {
		return err
	}
	if unbound != 0 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_dispatch_meta VALUES(1,?,0,0)`, string(raw))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// prepareDispatchTx allocates the local operation ordinal and original server
// dispatch proof inside the same transaction as admission, before any effect.
func (j *Journal) prepareDispatchTx(ctx context.Context, tx *sql.Tx, next, requested int64, command string, p transport.NativeDispatchProof) (int64, bool, error) {
	if p.OwnershipGeneration != j.scope.Generation || p.DispatchSequence <= 0 || p.DispatchSequence == 9223372036854775807 || p.SourceCommandID != command || p.SourceRunnerEpoch.IsZero() || p.SourceBootID == "" || len(p.SourceBootID) > 256 {
		return 0, false, ErrConflict
	}
	for _, id := range []string{p.OwnershipID, p.SourceCommandID, p.SourceAdmissionID, p.SourceRunnerID} {
		if _, err := domain.ParseID(id); err != nil {
			return 0, false, ErrConflict
		}
	}
	var ownership string
	var last, floor int64
	if err := tx.QueryRowContext(ctx, `SELECT ownership,last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&ownership, &last, &floor); err != nil {
		return 0, false, ErrConflict
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(ownership), &o) != nil || o.ID != p.OwnershipID {
		return 0, false, ErrConflict
	}
	if p.DispatchSequence <= floor {
		return 0, false, ErrRetired
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return 0, false, err
	}
	var sequence int64
	var original []byte
	err = tx.QueryRowContext(ctx, `SELECT operation_sequence,proof FROM worker_dispatches WHERE dispatch_sequence=?`, p.DispatchSequence).Scan(&sequence, &original)
	if err == nil {
		if string(original) != string(raw) || (requested != 0 && requested != sequence) {
			return 0, false, ErrConflict
		}
		return sequence, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	if p.DispatchSequence > last+1 {
		return 0, false, ErrDispatchGap
	}
	if p.DispatchSequence != last+1 || (requested != 0 && requested != next) {
		return 0, false, ErrConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_dispatches`).Scan(&count); err != nil {
		return 0, false, err
	}
	if count >= maxCommands {
		return 0, false, ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_dispatches(dispatch_sequence,operation_sequence,command_id,proof) VALUES(?,?,?,?)`, p.DispatchSequence, next, command, raw); err != nil {
		return 0, false, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_dispatch_meta SET last_sequence=? WHERE singleton=1`, p.DispatchSequence); err != nil {
		return 0, false, err
	}
	return next, true, nil
}

// RetireDispatches follows the matching backend retirement COMMIT. A worker
// rejects premature pruning even from its authenticated controller: outcomes
// must be settled and acknowledged, with all original turn evidence drained.
func (j *Journal) RetireDispatches(ctx context.Context, lease, floor int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, operationFloor, err := checkLease(ctx, tx, lease)
	if err != nil {
		return err
	}
	var last, old int64
	if err = tx.QueryRowContext(ctx, `SELECT last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&last, &old); err != nil {
		return err
	}
	if floor < old || floor > last {
		return ErrConflict
	}
	var unsafe int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_dispatches d WHERE dispatch_sequence<=? AND (state NOT IN ('completed','failed') OR operation_sequence>? OR EXISTS(SELECT 1 FROM worker_turn_sources t WHERE t.sequence=d.operation_sequence) OR EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.turnSource.sequence')=d.operation_sequence))`, floor, operationFloor).Scan(&unsafe); err != nil {
		return err
	}
	if unsafe != 0 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_dispatches WHERE dispatch_sequence<=?`, floor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_dispatch_meta SET retired=? WHERE singleton=1`, floor); err != nil {
		return err
	}
	return tx.Commit()
}
