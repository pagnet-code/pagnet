package daemon

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	NativeObservationMaxPayload     = 128 << 10
	NativeObservationOutboxMaxRows  = 4096
	NativeObservationOutboxMaxBytes = 32 << 20
	NativeObservationRetryHorizon   = 7 * 24 * time.Hour
)

var ErrNativeObservationCapacity = errors.New("native observation journal capacity reached")
var ErrNativeObservationConflict = errors.New("native observation identity conflicts with its recorded content")

type NativeObservationRecord struct {
	ID, OriginID, MessageType, Digest, SourceDigest string
	Payload                                         []byte
	CreatedAt, ExpiresAt, RetryAt                   time.Time
	Attempts                                        int
}

func observationDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (s *State) initNativeObservationOutbox() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS native_observation_outbox (
 observation_id TEXT PRIMARY KEY,origin_id TEXT NOT NULL,message_type TEXT NOT NULL,
 digest TEXT NOT NULL,source_digest TEXT NOT NULL,payload BLOB NOT NULL,created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0
 );CREATE INDEX IF NOT EXISTS native_observation_outbox_due ON native_observation_outbox(retry_at,created_at,observation_id);
 CREATE TABLE IF NOT EXISTS native_observation_usage (
 slot INTEGER PRIMARY KEY CHECK(slot=1),row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 4096),
 payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 0 AND 33554432)
 );
 INSERT OR IGNORE INTO native_observation_usage(slot,row_count,payload_bytes) SELECT 1,count(*),COALESCE(sum(length(payload)),0) FROM native_observation_outbox;
 CREATE TRIGGER IF NOT EXISTS native_observation_usage_insert AFTER INSERT ON native_observation_outbox BEGIN
 UPDATE native_observation_usage SET row_count=row_count+1,payload_bytes=payload_bytes+length(NEW.payload) WHERE slot=1;END;
 CREATE TRIGGER IF NOT EXISTS native_observation_usage_delete AFTER DELETE ON native_observation_outbox BEGIN
 UPDATE native_observation_usage SET row_count=row_count-1,payload_bytes=payload_bytes-length(OLD.payload) WHERE slot=1;END;
 CREATE TRIGGER IF NOT EXISTS native_observation_payload_immutable BEFORE UPDATE OF observation_id,origin_id,message_type,digest,source_digest,payload,created_at,expires_at ON native_observation_outbox BEGIN
 SELECT RAISE(ABORT,'native observation content is immutable');END;
 CREATE TABLE IF NOT EXISTS native_observation_completed (
 observation_id TEXT PRIMARY KEY,origin_id TEXT NOT NULL,message_type TEXT NOT NULL,source_digest TEXT NOT NULL,retained_until INTEGER NOT NULL
 );
 CREATE INDEX IF NOT EXISTS native_observation_completed_retention ON native_observation_completed(retained_until);
 CREATE TABLE IF NOT EXISTS native_observation_failures (
 observation_id TEXT PRIMARY KEY,origin_id TEXT NOT NULL,digest TEXT NOT NULL,
 reason TEXT NOT NULL,failed_at INTEGER NOT NULL
 );`)
	return err
}

// JournalNativeObservation reserves bounded durable space before any send.
// BEGIN IMMEDIATE serializes the capacity check across SQLite connections and
// processes: concurrent writers cannot both consume the last reservation.
func (s *State) JournalNativeObservation(ctx context.Context, row NativeObservationRecord) error {
	if row.ID == "" || row.OriginID == "" || (row.MessageType != "interaction.started" && row.MessageType != "interaction.resolved") || len(row.Payload) == 0 || len(row.Payload) > NativeObservationMaxPayload {
		return errors.New("invalid native observation journal record")
	}
	if _, err := domain.ParseID(row.ID); err != nil {
		return errors.New("invalid native observation identity")
	}
	if _, err := domain.ParseID(row.OriginID); err != nil {
		return errors.New("invalid native observation origin")
	}
	digest := observationDigest(row.Payload)
	if row.Digest != "" && row.Digest != digest {
		return ErrNativeObservationConflict
	}
	if row.SourceDigest == "" {
		row.SourceDigest = digest
	}
	if len(row.SourceDigest) != 64 {
		return ErrNativeObservationConflict
	}
	if _, err := hex.DecodeString(row.SourceDigest); err != nil {
		return ErrNativeObservationConflict
	}
	now := time.Now().UTC()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	if row.ExpiresAt.IsZero() {
		row.ExpiresAt = row.CreatedAt.Add(NativeObservationRetryHorizon)
	}
	if row.ExpiresAt.After(row.CreatedAt.Add(NativeObservationRetryHorizon)) || !row.ExpiresAt.After(row.CreatedAt) {
		return errors.New("invalid native observation retry horizon")
	}
	return s.nativeObservationWrite(ctx, func(conn *sql.Conn) error {
		var origin, kind, savedDigest, sourceDigest string
		err := conn.QueryRowContext(ctx, `SELECT origin_id,message_type,digest,source_digest FROM native_observation_outbox WHERE observation_id=?`, row.ID).Scan(&origin, &kind, &savedDigest, &sourceDigest)
		if err == nil {
			if origin == row.OriginID && kind == row.MessageType && savedDigest == digest && sourceDigest == row.SourceDigest {
				return nil
			}
			return ErrNativeObservationConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var completed int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM native_observation_completed WHERE observation_id=?`, row.ID).Scan(&completed); err != nil {
			return err
		}
		if completed != 0 {
			return ErrNativeObservationConflict
		}
		var failed int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM native_observation_failures WHERE observation_id=?`, row.ID).Scan(&failed); err != nil {
			return err
		}
		if failed != 0 {
			return ErrNativeObservationConflict
		}
		var count, bytes int
		if err := conn.QueryRowContext(ctx, `SELECT row_count,payload_bytes FROM native_observation_usage WHERE slot=1`).Scan(&count, &bytes); err != nil {
			return err
		}
		if count >= NativeObservationOutboxMaxRows || bytes+len(row.Payload) > NativeObservationOutboxMaxBytes {
			return ErrNativeObservationCapacity
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO native_observation_outbox(observation_id,origin_id,message_type,digest,source_digest,payload,created_at,expires_at,retry_at) VALUES(?,?,?,?,?,?,?,?,?)`, row.ID, row.OriginID, row.MessageType, digest, row.SourceDigest, row.Payload, row.CreatedAt.UnixMilli(), row.ExpiresAt.UnixMilli(), now.UnixMilli())
		return err
	})
}

// DueNativeObservations returns a bounded snapshot. Expired content remains
// journaled until an explicit failure disposition records its loss truthfully.
func (s *State) DueNativeObservations(ctx context.Context, now time.Time, limit int) ([]NativeObservationRecord, error) {
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	rows, err := s.db.QueryContext(ctx, `SELECT observation_id,origin_id,message_type,digest,source_digest,payload,created_at,expires_at,retry_at,attempts FROM native_observation_outbox WHERE retry_at<=? ORDER BY rowid LIMIT ?`, now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NativeObservationRecord
	for rows.Next() {
		var row NativeObservationRecord
		var created, expires, retry int64
		if err := rows.Scan(&row.ID, &row.OriginID, &row.MessageType, &row.Digest, &row.SourceDigest, &row.Payload, &created, &expires, &retry, &row.Attempts); err != nil {
			return nil, err
		}
		row.CreatedAt = time.UnixMilli(created).UTC()
		row.ExpiresAt = time.UnixMilli(expires).UTC()
		row.RetryAt = time.UnixMilli(retry).UTC()
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *State) RetryNativeObservation(ctx context.Context, id, digest string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE native_observation_outbox SET retry_at=?,attempts=attempts+1 WHERE observation_id=? AND digest=?`, next.UnixMilli(), id, digest)
	return err
}

// FinishNativeObservation requires the exact immutable content identity. A
// permanent failure writes a bounded metadata-only diagnostic before removing
// private ciphertext; successful durable receipts simply retire the payload.
func (s *State) FinishNativeObservation(ctx context.Context, id, origin, digest, reason string) (bool, error) {
	if reason != "" && reason != "expired" && reason != "scope_revoked" && reason != "stale_origin" && reason != "invalid_observation" {
		return false, errors.New("invalid observation disposition")
	}
	removed := false
	err := s.nativeObservationWrite(ctx, func(conn *sql.Conn) error {
		var saved, kind, sourceDigest string
		err := conn.QueryRowContext(ctx, `SELECT digest,message_type,source_digest FROM native_observation_outbox WHERE observation_id=? AND origin_id=?`, id, origin).Scan(&saved, &kind, &sourceDigest)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if saved != digest {
			return ErrNativeObservationConflict
		}

		if _, err := conn.ExecContext(ctx, `DELETE FROM native_observation_completed WHERE retained_until<=?`, time.Now().UnixMilli()); err != nil {
			return err
		}
		var completed int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM native_observation_completed`).Scan(&completed); err != nil {
			return err
		}
		if completed >= 65536 {
			return ErrNativeObservationCapacity
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO native_observation_completed(observation_id,origin_id,message_type,source_digest,retained_until) VALUES(?,?,?,?,?)`, id, origin, kind, sourceDigest, time.Now().Add(14*24*time.Hour).UnixMilli()); err != nil {
			return err
		}
		if reason != "" {
			if _, err := conn.ExecContext(ctx, `INSERT INTO native_observation_failures(observation_id,origin_id,digest,reason,failed_at) VALUES(?,?,?,?,?) ON CONFLICT(observation_id) DO NOTHING`, id, origin, digest, reason, time.Now().UnixMilli()); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, `DELETE FROM native_observation_failures WHERE observation_id IN(SELECT observation_id FROM native_observation_failures ORDER BY failed_at DESC,observation_id DESC LIMIT -1 OFFSET 256)`); err != nil {
				return err
			}
		}
		result, err := conn.ExecContext(ctx, `DELETE FROM native_observation_outbox WHERE observation_id=? AND origin_id=? AND digest=?`, id, origin, digest)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		removed = n == 1
		return err
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

func (s *State) nativeObservationWrite(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanup, `ROLLBACK`)
	}()
	if err = fn(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit native observation journal: %w", err)
	}
	return nil
}

// NativeObservationKnown must precede encryption. A worker retry uses its stable
// source identity to reuse the exact pending ciphertext or a durable completion
// tombstone, including a crash between controller journal COMMIT and worker ACK.
func (s *State) NativeObservationKnown(ctx context.Context, id, origin, kind, sourceDigest string) (bool, error) {
	var savedOrigin, savedKind, savedDigest string
	err := s.db.QueryRowContext(ctx, `SELECT origin_id,message_type,source_digest FROM native_observation_outbox WHERE observation_id=? UNION ALL SELECT origin_id,message_type,source_digest FROM native_observation_completed WHERE observation_id=? LIMIT 1`, id, id).Scan(&savedOrigin, &savedKind, &savedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if savedOrigin != origin || savedKind != kind || savedDigest != sourceDigest {
		return false, ErrNativeObservationConflict
	}
	return true, nil
}
