package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeOwnershipVerifyRequest reads an existing immutable ownership.
// It cannot bind ownership or admit any native effect.
type NativeOwnershipVerifyRequest struct {
	Ownership transport.NativeWorkerOwnership `json:"ownership"`
}

type NativeOwnershipVerifyResult struct {
	Snapshot NativeSnapshot `json:"snapshot"`
}

// checkSnapshotOwnership uses a separate transaction on each side of physical
// collection so a controller replacement or retirement cannot hide behind an
// old SQLite read snapshot. The physical read holds no journal lock.
func (j *Journal) checkSnapshotOwnership(ctx context.Context, lease int64, expected transport.NativeWorkerOwnership) error {
	if j.isLocal() || expected.State != "active" || expected.DeletionProof != nil {
		return ErrConflict
	}
	expected.LastDispatchSequence, expected.RetiredFloor = 0, 0
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
	var raw string
	var retired bool
	err = tx.QueryRowContext(ctx, `SELECT ownership,EXISTS(SELECT 1 FROM worker_ownership_retirement) FROM worker_dispatch_meta WHERE singleton=1`).Scan(&raw, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	var bound transport.NativeWorkerOwnership
	if retired || json.Unmarshal([]byte(raw), &bound) != nil || !transport.SameNativeWorkerOwnership(bound, expected) {
		return ErrConflict
	}
	return tx.Commit()
}

func (j *Journal) verifyOwnershipSnapshot(ctx context.Context, lease int64, req NativeOwnershipVerifyRequest, collect func() NativeSnapshot) (*NativeOwnershipVerifyResult, error) {
	if err := j.checkSnapshotOwnership(ctx, lease, req.Ownership); err != nil {
		return nil, err
	}
	snapshot := collect()
	actualStart, identityErr := proc.StartIdentity(snapshot.PID)
	if err := j.checkSnapshotOwnership(ctx, lease, req.Ownership); err != nil {
		return nil, err
	}
	var origin transport.NativeObservationOrigin
	if identityErr != nil || actualStart != snapshot.NativeStartIdentity || snapshot.IdentityPending || snapshot.PID <= 0 || snapshot.NativeStartIdentity == "" || snapshot.NativeGeneration == "" || snapshot.NativeSessionID == "" {
		return nil, ErrNativeBusy
	}
	if snapshot.Scope != j.scope || string(snapshot.ActualRuntime) != req.Ownership.Runtime || snapshot.ProfileFingerprint != req.Ownership.ProfileFingerprint {
		return nil, ErrNativeBusy
	}
	if json.Unmarshal(snapshot.Origin, &origin) != nil || origin.ID == "" || origin.TenantID != j.scope.TenantID || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.NativeGeneration != snapshot.NativeGeneration || origin.Runtime != string(snapshot.ActualRuntime) || (origin.NativeSessionID != "" && origin.NativeSessionID != snapshot.NativeSessionID) {
		return nil, ErrNativeBusy
	}
	return &NativeOwnershipVerifyResult{Snapshot: snapshot}, nil
}
