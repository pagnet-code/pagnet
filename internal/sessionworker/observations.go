package sessionworker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

const maxPendingObservations = 4096
const maxPendingObservationBytes = 32 << 20

// ObservedAt and SourceDigest belong to the original native source. Neither
// reconnect nor replacement of the controller creates a new observation.
type NativeObservation struct {
	InteractionID    string               `json:"interactionId,omitempty"`
	ID               string               `json:"id"`
	NativeGeneration string               `json:"nativeGeneration"`
	NativeSessionID  string               `json:"nativeSessionId,omitempty"`
	Origin           json.RawMessage      `json:"origin"`
	ObservedAt       time.Time            `json:"observedAt"`
	SourceDigest     string               `json:"sourceDigest"`
	Event            session.SessionEvent `json:"event"`
	Inspection       *Inspection          `json:"inspection,omitempty"`
}

func observationDigest(observation NativeObservation) (string, error) {
	observation.SourceDigest = ""
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > maxFrame*3/4 {
		return "", errors.New("native observation exceeds private frame bound")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func (j *Journal) initializeObservations() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_observations(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,payload BLOB NOT NULL,size INTEGER NOT NULL)`)
	if err != nil {
		return err
	}
	var count, bytes int
	if err = j.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0) FROM worker_observations`).Scan(&count, &bytes); err != nil {
		return err
	}
	if count > maxPendingObservations || bytes > maxPendingObservationBytes {
		return errors.New("worker observation history exceeds bounds")
	}
	rows, err := j.db.Query(`SELECT id,digest,payload,size FROM worker_observations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, digest string
		var payload []byte
		var size int
		if err = rows.Scan(&id, &digest, &payload, &size); err != nil {
			return err
		}
		var observation NativeObservation
		if json.Unmarshal(payload, &observation) != nil || len(payload) != size || observation.ID != id || observation.SourceDigest != digest {
			return errors.New("worker observation history binding is invalid")
		}
		actual, err := observationDigest(observation)
		if err != nil || actual != digest {
			return errors.New("worker observation history digest is invalid")
		}
	}
	return rows.Err()
}

// JournalObservation is idempotent across ambiguous COMMIT outcomes. The native
// reader retains this exact record on failure and applies backpressure.
func (j *Journal) JournalObservation(ctx context.Context, observation NativeObservation) error {
	digest, err := observationDigest(observation)
	if err != nil || observation.ID == "" || len(observation.ID) > 256 || observation.NativeGeneration == "" || len(observation.NativeGeneration) > 256 || observation.ObservedAt.IsZero() || len(observation.Origin) > 8192 || !json.Valid(observation.Origin) || digest != observation.SourceDigest {
		return errors.New("invalid native source observation")
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRow(`SELECT digest FROM worker_observations WHERE id=?`, observation.ID).Scan(&previous)
	if err == nil {
		if previous != digest {
			return ErrConflict
		}
		return nil
	}
	// QueryRow's missing-row case is the sole authority to create a new entry.
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count, total int
	if err = tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0) FROM worker_observations`).Scan(&count, &total); err != nil {
		return err
	}
	if count >= maxPendingObservations || total+len(raw) > maxPendingObservationBytes {
		return ErrFull
	}
	if _, err = tx.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, observation.ID, digest, raw, len(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

func (j *Journal) PendingObservations(ctx context.Context, limit int) ([]NativeObservation, error) {
	if limit < 1 || limit > 32 {
		return nil, errors.New("invalid native observation page bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	rows, err := j.db.QueryContext(ctx, `SELECT payload FROM worker_observations ORDER BY sequence LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []NativeObservation
	total := 0
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if total+len(raw) > maxFrame*3/4 {
			break
		}
		total += len(raw)
		var observation NativeObservation
		if err = json.Unmarshal(raw, &observation); err != nil {
			return nil, err
		}
		result = append(result, observation)
	}
	return result, rows.Err()
}

// A controller acknowledges only after its ciphertext outbox COMMIT. Removing
// this row never asserts a control-plane or browser receipt.
func (j *Journal) AcknowledgeObservation(ctx context.Context, id, digest string) error {
	if id == "" || len(id) > 256 || len(digest) != 64 {
		return errors.New("invalid native observation acknowledgement")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var previous string
	err := j.db.QueryRowContext(ctx, `SELECT digest FROM worker_observations WHERE id=?`, id).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if previous != digest {
		return ErrConflict
	}
	_, err = j.db.ExecContext(ctx, `DELETE FROM worker_observations WHERE id=? AND digest=?`, id, digest)
	return err
}
