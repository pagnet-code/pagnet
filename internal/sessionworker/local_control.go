package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"

	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

func (j *Journal) storeLocalControlTx(ctx context.Context, tx *sql.Tx, c nativeauthority.LocalControl) error {
	if nativeauthority.ValidateLocalControl(j.authority, c) != nil || c.CurrentController.Epoch() > math.MaxInt64 {
		return ErrFenced
	}
	var highest int64
	if e := tx.QueryRowContext(ctx, `SELECT highest_epoch FROM worker_local_control WHERE singleton=1`).Scan(&highest); e != nil {
		return e
	}
	if c.CurrentController.Epoch() < uint64(highest) {
		return ErrFenced
	}
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > 64<<10 {
		return ErrFull
	}
	if _, e = tx.ExecContext(ctx, `UPDATE worker_local_control SET highest_epoch=? WHERE singleton=1`, c.CurrentController.Epoch()); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO worker_local_current_control(singleton,proof) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET proof=excluded.proof`, raw)
	return e
}

// CommitLocalControl durably fences current ownership without admitting paid
// work or consuming a registry reservation ordinal. Call under actual fence.
func (j *Journal) CommitLocalControl(ctx context.Context, lease int64, c nativeauthority.LocalControl) error {
	if !j.isLocal() || nativeauthority.ValidateLocalControl(j.authority, c) != nil {
		return ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, _, e = checkLease(ctx, tx, lease); e != nil {
		return e
	}
	if e = j.storeLocalControlTx(ctx, tx, c); e != nil {
		return e
	}
	return tx.Commit()
}
