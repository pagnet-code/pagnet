package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"

	"github.com/pagnet-code/pagnet/internal/session"
)

// LifecycleSourceType is the bounded lifecycle subset that has an independent
// contiguous original-origin stream. Accepted turn events share that stream;
// unsupported/unbound turns, plans and approvals never consume a sequence.
func LifecycleSourceType(eventType string) string {
	switch eventType {
	case session.EventSessionStarted, session.EventSessionResumed:
		return "host.runtime_session"
	case session.EventBusy, session.EventIdle:
		return "host.agent_status"
	default:
		return ""
	}
}

func (j *Journal) initializeSourceSequences() error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS worker_source_sequence_protocol(singleton INTEGER PRIMARY KEY CHECK(singleton=1))`,
		`CREATE TABLE IF NOT EXISTS worker_source_stream(origin_id TEXT PRIMARY KEY,last_sequence INTEGER NOT NULL CHECK(last_sequence>0))`,
		`CREATE TABLE IF NOT EXISTS worker_observation_sequence(observation_id TEXT PRIMARY KEY,origin_id TEXT NOT NULL,source_sequence INTEGER NOT NULL CHECK(source_sequence>0),UNIQUE(origin_id,source_sequence))`,
	} {
		if _, err := j.db.Exec(query); err != nil {
			return err
		}
	}
	// The protocol is still inactive. Existing unpublished original rows may be
	// assigned in capture order exactly once, without touching ciphertext/digest.
	tx, err := j.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var initialized int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM worker_source_sequence_protocol`).Scan(&initialized); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT payload FROM worker_observations WHERE id NOT IN (SELECT observation_id FROM worker_observation_sequence) ORDER BY sequence`)
	if err != nil {
		return err
	}
	var pending []NativeObservation
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var o NativeObservation
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, o := range pending {
		if initialized > 0 && NativeSourceType(o) != "" {
			return errors.New("original lifecycle sequence mapping is missing")
		}
		if err = allocateSourceSequence(context.Background(), tx, o); err != nil {
			return err
		}
	}
	// Every surviving mapping must still bind its exact original source and the
	// monotonic stream watermark. ACK removes mappings, never that watermark.
	check, err := tx.Query(`SELECT o.payload,s.origin_id,s.source_sequence,t.last_sequence FROM worker_observation_sequence s LEFT JOIN worker_observations o ON o.id=s.observation_id LEFT JOIN worker_source_stream t ON t.origin_id=s.origin_id`)
	if err != nil {
		return err
	}
	for check.Next() {
		var raw []byte
		var id string
		var sequence, last int64
		if err = check.Scan(&raw, &id, &sequence, &last); err != nil {
			check.Close()
			return err
		}
		var o NativeObservation
		var origin struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &o) != nil || json.Unmarshal(o.Origin, &origin) != nil || origin.ID != id || sequence <= 0 || last < sequence || NativeSourceType(o) == "" {
			check.Close()
			return errors.New("original lifecycle sequence binding is corrupt")
		}
	}
	err = check.Err()
	check.Close()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO worker_source_sequence_protocol VALUES(1)`); err != nil {
		return err
	}
	return tx.Commit()
}

func allocateSourceSequence(ctx context.Context, tx *sql.Tx, o NativeObservation) error {
	if NativeSourceType(o) == "" {
		return nil
	}
	var origin struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(o.Origin, &origin) != nil || origin.ID == "" {
		return errors.New("lifecycle source has no original origin")
	}
	var last int64
	err := tx.QueryRowContext(ctx, `SELECT last_sequence FROM worker_source_stream WHERE origin_id=?`, origin.ID).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM worker_source_stream`).Scan(&count); err != nil {
			return err
		}
		if count >= maxPendingObservations {
			return ErrFull
		}
		last = 0
	} else if err != nil {
		return err
	}
	if last == math.MaxInt64 {
		return ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_source_stream(origin_id,last_sequence) VALUES(?,?) ON CONFLICT(origin_id) DO UPDATE SET last_sequence=excluded.last_sequence`, origin.ID, last+1); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_observation_sequence VALUES(?,?,?)`, o.ID, origin.ID, last+1)
	return err
}
