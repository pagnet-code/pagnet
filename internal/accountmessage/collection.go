package accountmessage

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

const CollectionBatch = 64
const Retention = 24 * time.Hour

// Collect reconciles encrypted candidates first, then inspects at most one
// bounded page. An unresolved candidate is never evicted, even after expiry.
// The cursor wraps only after completing a pass, so active early IDs cannot
// prevent later eligible records from being collected.
func (j *Journal) Collect(ctx context.Context, now time.Time) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	reconciled := make([]string, 0, CollectionBatch)
	ids := make([]string, 0, len(j.pending))
	for id := range j.pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	start := sort.SearchStrings(ids, j.pendingCollectionCursor)
	if start < len(ids) && ids[start] == j.pendingCollectionCursor {
		start++
	}
	if start >= len(ids) {
		start = 0
	}
	end := min(start+CollectionBatch, len(ids))
	pendingCursor := ""
	for _, id := range ids[start:end] {
		candidate := j.pending[id]
		pendingCursor = id
		var raw []byte
		err = tx.QueryRowContext(ctx, `SELECT payload FROM account_message_seals WHERE message_id=?`, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		var stored Sealed
		if decode(raw, &stored) != nil || stored.Validate() != nil || stored != candidate {
			return 0, ErrConflict
		}
		reconciled = append(reconciled, id)
	}
	rows, err := tx.QueryContext(ctx, `SELECT message_id,payload FROM account_message_seals WHERE message_id>? ORDER BY message_id LIMIT ?`, j.collectionCursor, CollectionBatch)
	if err != nil {
		return 0, err
	}
	var eligible []string
	cursor := ""
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			break
		}
		cursor = id
		var stored Sealed
		if len(raw) > MaxRecordBytes || decode(raw, &stored) != nil || stored.Validate() != nil || stored.MessageID != id {
			err = ErrConflict
			break
		}
		if _, uncertain := j.pending[id]; uncertain {
			continue
		}
		expires, _ := time.Parse(time.RFC3339Nano, stored.Descriptor.ExpiresAt)
		if !now.Before(expires.Add(Retention)) {
			eligible = append(eligible, id)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range eligible {
		if _, err = tx.ExecContext(ctx, `DELETE FROM account_message_seals WHERE message_id=?`, id); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, ErrUncertain
	}
	for _, id := range reconciled {
		delete(j.pending, id)
	}
	j.collectionCursor = cursor
	j.pendingCollectionCursor = pendingCursor
	return len(eligible), nil
}
