package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/transport"
)

// Terminal backend receipts consume a source sequence, but do not authorize
// deletion of evidence that the backend did not attach. Side metadata retains
// its immutable original source for authenticated recovery.
type NativeSourceDisposition struct {
	Cursor      int64                                     `json:"cursor"`
	Observation NativeObservation                         `json:"observation"`
	Receipt     transport.NativeObservationReceiptPayload `json:"receipt"`
}
type NativeSourceDispositionPage struct {
	After      int64                     `json:"after"`
	NextCursor int64                     `json:"nextCursor"`
	More       bool                      `json:"more"`
	Sources    []NativeSourceDisposition `json:"sources,omitempty"`
}

func (j *Journal) createSourceDispositions() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_source_dispositions(observation_id TEXT PRIMARY KEY NOT NULL,source_digest TEXT NOT NULL,receipt BLOB NOT NULL,size INTEGER NOT NULL)`)
	return err
}
func matchingTerminalReceipt(o NativeObservation, r transport.NativeObservationReceiptPayload) bool {
	p, err := NativeBackendObservation(o)
	return err == nil && (r.Disposition == "expired" || r.Disposition == "stale_origin") && r.ObservationID == p.ObservationID && r.OriginID == p.OriginID && r.Digest == p.Digest
}
func (j *Journal) validateSourceDispositions() error {
	rows, err := j.db.Query(`SELECT d.observation_id,d.source_digest,d.receipt,d.size,o.payload,COALESCE(s.source_sequence,0) FROM worker_source_dispositions d LEFT JOIN worker_observations o ON o.id=d.observation_id LEFT JOIN worker_observation_sequence s ON s.observation_id=d.observation_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, digest string
		var raw, payload []byte
		var size int
		var seq int64
		if err = rows.Scan(&id, &digest, &raw, &size, &payload, &seq); err != nil {
			return err
		}
		var o NativeObservation
		var r transport.NativeObservationReceiptPayload
		if json.Unmarshal(payload, &o) != nil || json.Unmarshal(raw, &r) != nil || len(raw) != size || o.ID != id || o.SourceDigest != digest {
			return ErrConflict
		}
		o.SourceSequence = seq
		if !matchingTerminalReceipt(o, r) {
			return ErrConflict
		}
	}
	return rows.Err()
}
func (j *Journal) RecordNativeSourceDisposition(ctx context.Context, lease int64, id, digest string, r transport.NativeObservationReceiptPayload) error {
	if lease <= 0 {
		return ErrFenced
	}
	if id == "" || len(id) > 256 || len(digest) != 64 {
		return ErrConflict
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 2048 {
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
	var payload []byte
	var seq int64
	err = tx.QueryRowContext(ctx, `SELECT o.payload,COALESCE(s.source_sequence,0) FROM worker_observations o LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.id=? AND o.digest=?`, id, digest).Scan(&payload, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	var o NativeObservation
	if json.Unmarshal(payload, &o) != nil {
		return ErrConflict
	}
	o.SourceSequence = seq
	if !matchingTerminalReceipt(o, r) {
		return ErrConflict
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT receipt FROM worker_source_dispositions WHERE observation_id=?`, id).Scan(&previous)
	if err == nil {
		var old transport.NativeObservationReceiptPayload
		if json.Unmarshal(previous, &old) != nil || old != r {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var total int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT COALESCE(SUM(size),0) FROM worker_observations)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures)+(SELECT COALESCE(SUM(size),0) FROM worker_source_dispositions)`).Scan(&total); err != nil {
		return err
	}
	if total+len(raw)+j.sourceStopReservationsLocked()*sourceStopReserveBytes > maxPendingObservationBytes {
		return ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_source_dispositions VALUES(?,?,?,?)`, id, digest, raw, len(raw)); err != nil {
		return err
	}
	return tx.Commit()
}
func (j *Journal) SourceDispositionPageForLease(ctx context.Context, lease, after int64, limit int) (NativeSourceDispositionPage, error) {
	page := NativeSourceDispositionPage{After: after, NextCursor: after}
	if lease <= 0 {
		return page, ErrFenced
	}
	if after < 0 || limit < 1 || limit > 32 {
		return page, ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return page, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.sequence,o.payload,d.receipt,COALESCE(s.source_sequence,0) FROM worker_source_dispositions d JOIN worker_observations o ON o.id=d.observation_id LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.sequence>? ORDER BY o.sequence LIMIT ?`, after, limit)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var record NativeSourceDisposition
		var raw, receipt []byte
		var seq int64
		if err = rows.Scan(&record.Cursor, &raw, &receipt, &seq); err != nil {
			return page, err
		}
		if total+len(raw)+len(receipt) > maxFrame/2 {
			break
		}
		total += len(raw) + len(receipt)
		if json.Unmarshal(raw, &record.Observation) != nil || json.Unmarshal(receipt, &record.Receipt) != nil {
			return page, ErrConflict
		}
		record.Observation.SourceSequence = seq
		page.Sources = append(page.Sources, record)
		page.NextCursor = record.Cursor
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if err = rows.Close(); err != nil {
		return page, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_source_dispositions d JOIN worker_observations o ON o.id=d.observation_id WHERE o.sequence>?)`, page.NextCursor).Scan(&page.More); err != nil {
		return page, err
	}
	return page, tx.Commit()
}
