package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// requestLocalCancellation commits only cancellation intent, not native EOF or
// completion. The caller holds current registry authorization through this ACK.
func (j *Journal) requestLocalCancellation(ctx context.Context, lease int64, binder nativeauthority.OperationBinder, i nativeauthority.VerifiedIntent) error {
	if !j.isLocal() || nativeauthority.ValidateCancellationIntent(j.authority, binder, i) != nil || i.CurrentController.Epoch() > math.MaxInt64 {
		return ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, _, e = checkLease(ctx, tx, lease)
	if e != nil {
		return e
	}
	var highest int64
	if e = tx.QueryRowContext(ctx, `SELECT highest_epoch FROM worker_local_control WHERE singleton=1`).Scan(&highest); e != nil {
		return e
	}
	if i.CurrentController.Epoch() < uint64(highest) {
		return ErrFenced
	}
	source, e := j.localIntentSource(ctx, tx, i.Commitment.Sequence)
	if e == sql.ErrNoRows {
		return ErrRetired
	}
	if e != nil {
		return e
	}
	a, _ := json.Marshal(source.Admission)
	b, _ := json.Marshal(i.OriginalAdmission)
	originalBinding := i.CurrentBinding
	if i.OriginalBinding != nil {
		originalBinding = *i.OriginalBinding
	}
	if !sameLocalJSON(source.Binding, originalBinding) || source.Commitment != i.Commitment || string(a) != string(b) || !sameLocalJSON(source.Reservation, i.Reservation) {
		return ErrConflict
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO worker_local_cancellations(sequence,command_id,admission_id,controller_epoch) VALUES(?,?,?,?) ON CONFLICT(sequence) DO NOTHING`, i.Commitment.Sequence, i.Commitment.CommandID, i.OriginalAdmission.ID, i.CurrentController.Epoch())
	if e != nil {
		return e
	}
	e = j.storeLocalControlTx(ctx, tx, nativeauthority.LocalControl{CurrentBinding: i.CurrentBinding, CurrentController: i.CurrentController})
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (j *Journal) localCancellationRequested(sequence int64) (bool, error) {
	if !j.isLocal() {
		return false, nil
	}
	var yes bool
	e := j.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM worker_local_cancellations WHERE sequence=?)`, sequence).Scan(&yes)
	return yes, e
}

// CancelLocalInvocation seals cancellation before signaling the owned operation.
// It cannot report the native effect completed; original source/EOF settles that.
func (o *SessionOwner) CancelLocalInvocation(ctx context.Context, lease int64, binder nativeauthority.OperationBinder, i nativeauthority.VerifiedIntent) error {
	if e := o.journal.requestLocalCancellation(ctx, lease, binder, i); e != nil {
		return e
	}
	o.mu.Lock()
	pending := o.operations[i.Commitment.Sequence]
	var barrier chan struct{}
	var previous <-chan struct{}
	active := pending != nil && pending.nativeOwned && o.candidateTurnSource.Sequence == i.Commitment.Sequence
	if pending != nil && !active {
		pending.cancel()
	}
	if active {
		if pending.activationCancel != nil {
			pending.activationCancel()
		}
		previous = o.lastStopDone
		barrier = make(chan struct{})
		o.lastStopDone = barrier
	}
	if active && !o.closing {
		o.wg.Go(func() {
			defer close(barrier)
			if previous != nil {
				select {
				case <-previous:
				case <-o.ctx.Done():
					return
				}
			}
			// New work waits on this barrier. The original prompt is not context-
			// canceled away: actual owned endpoint stop/EOF settles its effect evidence.
			_ = o.manager.Stop(o.journal.instanceID())
			_ = o.supervisor.StopEndpoint(o.journal.instanceID())
			select {
			case <-pending.done:
			case <-o.ctx.Done():
			}
		})
	}
	o.mu.Unlock()
	return nil
}
