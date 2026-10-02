//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/pagnet-code/pagnet/transport"
)

type nativeWorkerGC struct {
	CommandID       string
	DeleteRequestID string
	Ownership       transport.NativeWorkerOwnership
	Phase           string
}

// The bounded registry retains only outstanding deletions; a remote COMMIT
// confirmation reclaims each marker. Every phase is FULL-fsynced before the
// next irreversible step, including the private worker's own retirement.
func (r *NativeWorkerRegistry) beginGC(record NativeWorkerRecord, p transport.ForgetInstancePayload) (nativeWorkerGC, error) {
	if p.CommandID == "" || p.DeleteRequestID == "" || p.InstanceID != record.Scope.InstanceID || p.NativeOwnership == nil || record.Ownership == nil {
		return nativeWorkerGC{}, ErrNativeObservationConflict
	}
	a, b := *p.NativeOwnership, *record.Ownership
	a.LastDispatchSequence, a.RetiredFloor = 0, 0
	b.LastDispatchSequence, b.RetiredFloor = 0, 0
	if !reflect.DeepEqual(a, b) {
		return nativeWorkerGC{}, ErrNativeObservationConflict
	}
	proposed := nativeWorkerGC{CommandID: p.CommandID, DeleteRequestID: p.DeleteRequestID, Ownership: *p.NativeOwnership, Phase: "waiting"}
	raw, err := json.Marshal(proposed)
	if err != nil {
		return proposed, err
	}
	if _, err = r.db.Exec(`INSERT INTO native_worker_gc VALUES(?,?) ON CONFLICT(instance_id) DO NOTHING`, p.InstanceID, raw); err != nil {
		return proposed, err
	}
	existing, err := r.lookupGC(p.InstanceID)
	if err != nil {
		return proposed, err
	}
	if existing.CommandID != p.CommandID || existing.DeleteRequestID != p.DeleteRequestID || existing.Ownership.ID != p.NativeOwnership.ID || existing.Ownership.OwnershipGeneration != record.Scope.Generation {
		return proposed, ErrNativeObservationConflict
	}
	return existing, nil
}
func (r *NativeWorkerRegistry) lookupGC(id string) (nativeWorkerGC, error) {
	var raw []byte
	var gc nativeWorkerGC
	err := r.db.QueryRow(`SELECT payload FROM native_worker_gc WHERE instance_id=?`, id).Scan(&raw)
	if err != nil {
		return gc, err
	}
	if len(raw) > 32<<10 || json.Unmarshal(raw, &gc) != nil || gc.Ownership.InstanceID != id {
		return gc, ErrNativeObservationConflict
	}
	return gc, nil
}
func (r *NativeWorkerRegistry) advanceGC(id string, gc nativeWorkerGC, phase string, proof *transport.NativeWorkerOwnership) (nativeWorkerGC, error) {
	allowed := (gc.Phase == "waiting" && phase == "backend_retired") || (gc.Phase == "backend_retired" && (phase == "worker_retired" || phase == "collecting")) || (gc.Phase == "worker_retired" && phase == "collecting") || (gc.Phase == "collecting" && phase == "collected")
	if !allowed {
		return gc, ErrNativeObservationConflict
	}
	if phase == "backend_retired" {
		if proof == nil || proof.State != "retired" || proof.LastDispatchSequence != proof.RetiredFloor {
			return gc, ErrNativeObservationConflict
		}
		expected, actual := gc.Ownership, *proof
		expected.State = "retired"
		expected.LastDispatchSequence = 0
		expected.RetiredFloor = 0
		actual.LastDispatchSequence = 0
		actual.RetiredFloor = 0
		if !reflect.DeepEqual(expected, actual) {
			return gc, ErrNativeObservationConflict
		}
	} else if proof != nil {
		return gc, ErrNativeObservationConflict
	}
	previous, _ := json.Marshal(gc)
	next := gc
	next.Phase = phase
	if proof != nil {
		next.Ownership = *proof
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return gc, err
	}
	result, err := r.db.Exec(`UPDATE native_worker_gc SET payload=? WHERE instance_id=? AND payload=?`, raw, id, previous)
	if err != nil {
		return gc, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return gc, ErrNativeObservationConflict
	}
	return next, nil
}
func (r *NativeWorkerRegistry) confirmGC(ctx context.Context, p transport.NativeInstanceForgottenPayload) error {
	gc, err := r.lookupGC(p.InstanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if gc.Phase != "collected" || p.Disposition != "forgotten" || p.CommandID != gc.CommandID || p.DeleteRequestID != gc.DeleteRequestID || p.OwnershipID != gc.Ownership.ID || p.OwnershipGeneration != gc.Ownership.OwnershipGeneration {
		return ErrNativeObservationConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM native_worker_gc WHERE instance_id=?`, p.InstanceID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM native_workers WHERE instance_id=?`, p.InstanceID); err != nil {
		return err
	}
	return tx.Commit()
}
