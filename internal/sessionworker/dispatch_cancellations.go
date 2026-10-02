package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// DispatchCancellationPreparation is not an intent or native outcome. The
// original proposal is pinned before asking the backend to cancel its ordinal.
type DispatchCancellationPreparation struct {
	Request  transport.NativeDispatchCancelPayload        `json:"request"`
	Proposal transport.NativeDispatchCancellationProposal `json:"proposal"`
	State    string                                       `json:"state"`
}

func (j *Journal) initializeDispatchCancellations() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_dispatch_cancellations(dispatch_sequence INTEGER PRIMARY KEY,command_id TEXT NOT NULL UNIQUE,preparation_id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL,state TEXT NOT NULL CHECK(state IN ('prepared','finalized')))`)
	if err != nil {
		return err
	}
	// This fence also covers an accidental legacy admission without a dispatch
	// proof. The ordinal fence is checked by the owned dispatch transaction.
	_, err = j.db.Exec(`CREATE TRIGGER IF NOT EXISTS worker_cancel_fence BEFORE INSERT ON worker_intent WHEN EXISTS(SELECT 1 FROM worker_dispatch_cancellations WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'original dispatch cancellation fence'); END`)
	if err != nil {
		return err
	}
	var count int
	if err = j.db.QueryRow(`SELECT COUNT(*) FROM worker_dispatch_cancellations`).Scan(&count); err != nil {
		return err
	}
	if count > maxCommands {
		return ErrFull
	}
	rows, err := j.db.Query(`SELECT dispatch_sequence,command_id,preparation_id,payload,state FROM worker_dispatch_cancellations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var records []DispatchCancellationPreparation
	for rows.Next() {
		var seq int64
		var command, prep, state string
		var raw []byte
		var record DispatchCancellationPreparation
		if err = rows.Scan(&seq, &command, &prep, &raw, &state); err != nil {
			return err
		}
		if len(raw) > 16384 || json.Unmarshal(raw, &record) != nil || record.Request.DispatchSequence != seq || record.Request.SourceCommandID != command || record.Request.PreparationID != prep || record.State != state || !validCancellationPreparation(j.scope, record) {
			return ErrConflict
		}
		records = append(records, record)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	tx, err := j.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, record := range records {
		if err = checkCancellationOwnershipTx(context.Background(), tx, j.scope, record.Proposal.Proof, false); err != nil {
			return err
		}
		if err = checkNeverAcceptedDispatchTx(context.Background(), tx, record.Proposal.Proof); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func validCancellationPreparation(scope Scope, r DispatchCancellationPreparation) bool {
	p := r.Proposal.Proof
	q := r.Request
	if r.State != "prepared" && r.State != "finalized" {
		return false
	}
	if p.OwnershipGeneration != scope.Generation || p.DispatchSequence <= 0 || p.DispatchSequence == 9223372036854775807 || p.SourceRunnerEpoch.IsZero() || p.SourceBootID == "" || len(p.SourceBootID) > 256 || len(r.Proposal.Reason) == 0 || len(r.Proposal.Reason) > 128 || len(r.Proposal.CommandType) == 0 || len(r.Proposal.CommandType) > 128 {
		return false
	}
	for _, id := range []string{p.OwnershipID, p.SourceCommandID, p.SourceAdmissionID, p.SourceRunnerID, q.RequestID, q.PreparationID} {
		if _, err := domain.ParseID(id); err != nil {
			return false
		}
	}
	return r.Proposal.InstanceID == scope.InstanceID && q.InstanceID == scope.InstanceID && q.OwnershipID == p.OwnershipID && q.OwnershipGeneration == p.OwnershipGeneration && q.DispatchSequence == p.DispatchSequence && q.SourceCommandID == p.SourceCommandID && q.SourceAdmissionID == p.SourceAdmissionID
}
func checkCancellationOwnershipTx(ctx context.Context, tx *sql.Tx, scope Scope, p transport.NativeDispatchProof, newPreparation bool) error {
	var raw string
	var last, floor int64
	if err := tx.QueryRowContext(ctx, `SELECT ownership,last_sequence,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&raw, &last, &floor); err != nil {
		return err
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(raw), &o) != nil || o.ID != p.OwnershipID || o.InstanceID != scope.InstanceID || o.OwnershipGeneration != scope.Generation || o.State != "active" {
		return ErrConflict
	}
	if newPreparation && (p.DispatchSequence <= floor || p.DispatchSequence > last+maxCommands) {
		return ErrConflict
	}
	return nil
}
func checkNeverAcceptedDispatchTx(ctx context.Context, tx *sql.Tx, p transport.NativeDispatchProof) error {
	var accepted bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_intent WHERE command_id=?) OR EXISTS(SELECT 1 FROM worker_turn_sources WHERE source_command=?)`, p.SourceCommandID, p.SourceCommandID).Scan(&accepted); err != nil {
		return err
	}
	if accepted {
		return ErrConflict
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_dispatches')`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_dispatches WHERE command_id=? OR dispatch_sequence=?)`, p.SourceCommandID, p.DispatchSequence).Scan(&accepted); err != nil {
			return err
		}
		if accepted {
			return ErrConflict
		}
	}
	return nil
}

// CheckDispatchCancellationTx must run in the same transaction as owned
// dispatch binding and intent insertion. Any prepared or finalized original
// ordinal is fenced. Caller retains its usual full proof/ownership validation.
func CheckDispatchCancellationTx(ctx context.Context, tx *sql.Tx, p transport.NativeDispatchProof) error {
	var fenced bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_dispatch_cancellations WHERE dispatch_sequence=? OR command_id=?)`, p.DispatchSequence, p.SourceCommandID).Scan(&fenced); err != nil {
		return err
	}
	if fenced {
		return ErrConflict
	}
	return nil
}
func (j *Journal) PrepareDispatchCancellation(ctx context.Context, lease int64, proposal transport.NativeDispatchCancellationProposal) (DispatchCancellationPreparation, error) {
	record := DispatchCancellationPreparation{Proposal: proposal, State: "prepared"}
	p := proposal.Proof
	record.Request = transport.NativeDispatchCancelPayload{RequestID: domain.NewID().String(), PreparationID: domain.NewID().String(), InstanceID: proposal.InstanceID, OwnershipID: p.OwnershipID, OwnershipGeneration: p.OwnershipGeneration, DispatchSequence: p.DispatchSequence, SourceCommandID: p.SourceCommandID, SourceAdmissionID: p.SourceAdmissionID}
	if !validCancellationPreparation(j.scope, record) {
		return record, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return record, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return record, err
	}
	if err = checkCancellationOwnershipTx(ctx, tx, j.scope, p, true); err != nil {
		return record, err
	}
	if err = checkNeverAcceptedDispatchTx(ctx, tx, p); err != nil {
		return record, err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_dispatch_cancellations WHERE dispatch_sequence=? OR command_id=?`, p.DispatchSequence, p.SourceCommandID).Scan(&raw)
	if err == nil {
		var old DispatchCancellationPreparation
		if json.Unmarshal(raw, &old) != nil || !transport.SameNativeDispatchCancellationProposal(old.Proposal, proposal) {
			return record, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return record, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_dispatch_cancellations`).Scan(&count); err != nil {
		return record, err
	}
	if count >= maxCommands {
		return record, ErrFull
	}
	raw, err = json.Marshal(record)
	if err != nil || len(raw) > 16384 {
		return record, ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_dispatch_cancellations VALUES(?,?,?,?,?)`, p.DispatchSequence, p.SourceCommandID, record.Request.PreparationID, raw, record.State); err != nil {
		return record, err
	}
	return record, tx.Commit()
}

// Finalize runs only after the authenticated backend's actual COMMIT response.
// It creates no native turn, intent, outcome or observation acknowledgement.
func (j *Journal) FinalizeDispatchCancellation(ctx context.Context, lease int64, response transport.NativeDispatchCancelledPayload) error {
	if response.Disposition != "cancelled" || response.Proof == nil || response.PublicError != "" || response.Retryable {
		return ErrConflict
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
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_dispatch_cancellations WHERE preparation_id=?`, response.PreparationID).Scan(&raw); err != nil {
		return err
	}
	var record DispatchCancellationPreparation
	if json.Unmarshal(raw, &record) != nil || !validCancellationPreparation(j.scope, record) || record.Request.RequestID != response.RequestID || record.Request.InstanceID != response.InstanceID || !transport.SameNativeDispatchProof(record.Proposal.Proof, *response.Proof) {
		return ErrConflict
	}
	if err = checkCancellationOwnershipTx(ctx, tx, j.scope, *response.Proof, false); err != nil {
		return err
	}
	if err = checkNeverAcceptedDispatchTx(ctx, tx, *response.Proof); err != nil {
		return err
	}
	record.State = "finalized"
	raw, err = json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_dispatch_cancellations SET payload=?,state='finalized' WHERE preparation_id=?`, raw, response.PreparationID); err != nil {
		return err
	}
	if err = advanceFinalizedDispatchesTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RetireDispatchCancellationsTx reclaims only finalized metadata after the
// caller has durably advanced this exact ownership's authenticated retired
// floor in the same transaction. Prepared uncertainty can never be skipped.
func RetireDispatchCancellationsTx(ctx context.Context, tx *sql.Tx, ownershipID string, floor int64) error {
	var raw string
	var retained int64
	if err := tx.QueryRowContext(ctx, `SELECT ownership,retired FROM worker_dispatch_meta WHERE singleton=1`).Scan(&raw, &retained); err != nil {
		return err
	}
	var o transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(raw), &o) != nil || o.ID != ownershipID || floor < 0 || retained != floor {
		return ErrConflict
	}
	var unsafe bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_dispatch_cancellations WHERE dispatch_sequence<=? AND state!='finalized')`, floor).Scan(&unsafe); err != nil {
		return err
	}
	if unsafe {
		return ErrConflict
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM worker_dispatch_cancellations WHERE dispatch_sequence<=? AND state='finalized'`, floor)
	return err
}
