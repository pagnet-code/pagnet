package sessionworker

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/transport"
)

// A completed native attach only means the PTY exists. Its original operation
// remains replayable until the controller finishes sending bootstrap/snapshot
// or records a final view failure. No native effect occurs on this metadata RPC.
func (j *Journal) CommitTerminalView(ctx context.Context, lease int64, proof *transport.NativeDispatchProof) error {
	if proof == nil {
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
	var sequence int64
	if err = tx.QueryRowContext(ctx, `SELECT proof,operation_sequence FROM worker_dispatches WHERE dispatch_sequence=?`, proof.DispatchSequence).Scan(&raw, &sequence); err != nil {
		return err
	}
	var original transport.NativeDispatchProof
	if json.Unmarshal(raw, &original) != nil || !transport.SameNativeDispatchProof(original, *proof) {
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE worker_terminal_view_commits SET committed=1 WHERE operation_sequence=?`, sequence)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}
