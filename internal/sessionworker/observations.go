package sessionworker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

const maxPendingObservations = 4096
const maxPendingObservationBytes = 48 << 20

// ObservedAt and SourceDigest belong to the original native source. Neither
// reconnect nor replacement of the controller creates a new observation.
type NativeResolution struct {
	DetailContent  *transport.NativeContentReference `json:"detailContent,omitempty"`
	DetailEnvelope e2ee.EncryptedPayloadV1           `json:"detailEnvelope"`
	DetailAAD      e2ee.AAD                          `json:"detailAAD"`
}
type NativeObservation struct {
	// SourceSequence is durable delivery metadata, independent of private capture identity.
	SourceSequence               int64                             `json:"sourceSequence,omitempty"`
	OriginalNativePayloadContent *transport.NativeContentReference `json:"originalNativePayloadContent,omitempty"`
	TurnSource                   *NativeTurnSource                 `json:"turnSource,omitempty"`
	SourceUnavailable            bool                              `json:"sourceUnavailable,omitempty"`
	InteractionID                string                            `json:"interactionId,omitempty"`
	ID                           string                            `json:"id"`
	NativeGeneration             string                            `json:"nativeGeneration"`
	NativeSessionID              string                            `json:"nativeSessionId,omitempty"`
	Origin                       json.RawMessage                   `json:"origin"`
	ObservedAt                   time.Time                         `json:"observedAt"`
	SourceDigest                 string                            `json:"sourceDigest"`
	Event                        session.SessionEvent              `json:"event"`
	Resolution                   *NativeResolution                 `json:"resolution,omitempty"`
	Capture                      *NativeCaptureRef                 `json:"capture,omitempty"`
	Inspection                   *Inspection                       `json:"inspection,omitempty"`
}

func observationDigest(observation NativeObservation) (string, error) {
	observation.SourceDigest = ""
	observation.SourceSequence = 0
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

// Direct imports support unpublished fixtures before the producer protocol.
// Registered production sources require their exact original append capability,
// including retries after an uncertain COMMIT.
func (j *Journal) JournalObservation(ctx context.Context, observation NativeObservation) error {
	return j.JournalCapturedObservation(ctx, observation, nil)
}

func (j *Journal) JournalCapturedObservation(ctx context.Context, observation NativeObservation, encrypted []byte, transfers ...nativecontent.Transfer) error {
	return j.journalCapturedObservation(ctx, nil, observation, encrypted, transfers...)
}
func (j *Journal) journalCapturedObservation(ctx context.Context, producer *nativeSourceProducer, observation NativeObservation, encrypted []byte, transfers ...nativecontent.Transfer) error {
	if err := verifyCapture(observation.Capture, encrypted); err != nil {
		return err
	}
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
	if j.strictSourceProducer && (producer == nil || producer.closed || !j.sourceProducers[producer] || producer.generation != observation.NativeGeneration || !producer.owns(observation.Origin)) {
		return ErrFenced
	}
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
		if producer != nil && observation.Event.Type == session.EventSessionStopped {
			producer.stoppedCommitted = true
		}
		return nil
	}
	// QueryRow's missing-row case is the sole authority to create a new entry.
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Only an actually pinned original native producer can retry an ambiguous
	// COMMIT after ACK. Pins have worker lifetime, and no IPC append API exists.
	if retry := j.sourceRetries[observation.ID]; retry != nil {
		if retry.digest != digest {
			return ErrConflict
		}
		if retry.retired {
			return nil
		}
	}
	var count, total int
	if err = tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures) FROM worker_observations`).Scan(&count, &total); err != nil {
		return err
	}
	reserved := j.sourceStopReservationsLocked()
	terminal := producer != nil && !producer.stoppedCommitted && observation.Event.Type == session.EventSessionStopped
	if terminal {
		reserved--
		if len(raw)+len(encrypted) > sourceStopReserveBytes {
			return ErrFull
		}
	}
	if count+reserved >= maxPendingObservations || total+len(raw)+len(encrypted)+reserved*sourceStopReserveBytes > maxPendingObservationBytes {
		return ErrFull
	}
	if _, err = tx.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, observation.ID, digest, raw, len(raw)); err != nil {
		return err
	}
	if err = allocateSourceSequence(ctx, tx, observation); err != nil {
		return err
	}
	if err = retainNativeEventSource(ctx, tx, observation); err != nil {
		return err
	}
	if len(encrypted) > 0 {
		if _, err = tx.Exec(`INSERT INTO worker_source_captures(id,ciphertext,size) VALUES(?,?,?)`, observation.ID, encrypted, len(encrypted)); err != nil {
			return err
		}
	}
	for _, transfer := range transfers {
		if err = insertOriginalTransfer(ctx, tx, observation, transfer); err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err == nil && terminal {
		producer.stoppedCommitted = true
	}
	return err
}

func (j *Journal) PendingObservations(ctx context.Context, limit int) ([]NativeObservation, error) {
	page, err := j.pendingObservationPage(ctx, 0, 0, limit)
	return page.Observations, err
}
func (j *Journal) PendingObservationsForLease(ctx context.Context, lease int64, limit int) ([]NativeObservation, error) {
	if lease <= 0 {
		return nil, ErrFenced
	}
	page, err := j.pendingObservationPage(ctx, lease, 0, limit)
	return page.Observations, err
}

// NativeObservationPage cursors identify SQLite rows, not native source identity.
// A cursor is transport metadata authenticated by the exact controller IPC lease.
type NativeObservationPage struct {
	After        int64               `json:"after"`
	NextCursor   int64               `json:"nextCursor"`
	More         bool                `json:"more"`
	Observations []NativeObservation `json:"-"`
}

func (j *Journal) ObservationPageForLease(ctx context.Context, lease, after int64, limit int) (NativeObservationPage, error) {
	if lease <= 0 {
		return NativeObservationPage{}, ErrFenced
	}
	return j.pendingObservationPage(ctx, lease, after, limit)
}
func (j *Journal) pendingObservationPage(ctx context.Context, lease, after int64, limit int) (NativeObservationPage, error) {
	page := NativeObservationPage{After: after, NextCursor: after}
	if after < 0 || limit < 1 || limit > 32 {
		return page, errors.New("invalid native observation page bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if lease > 0 {
		if _, _, err = checkLease(ctx, tx, lease); err != nil {
			return page, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.sequence,o.payload,COALESCE(s.source_sequence,0) FROM worker_observations o LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.sequence>? ORDER BY o.sequence LIMIT ?`, after, limit)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var raw []byte
		var rowSequence, sourceSequence int64
		if err = rows.Scan(&rowSequence, &raw, &sourceSequence); err != nil {
			return page, err
		}
		if total+len(raw) > maxFrame*3/4 {
			break
		}
		total += len(raw)
		var observation NativeObservation
		if err = json.Unmarshal(raw, &observation); err != nil {
			return page, err
		}
		observation.SourceSequence = sourceSequence
		page.Observations = append(page.Observations, observation)
		page.NextCursor = rowSequence
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if err = rows.Close(); err != nil {
		return page, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_observations WHERE sequence>?)`, page.NextCursor).Scan(&page.More); err != nil {
		return page, err
	}
	if err = tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}

// A controller acknowledges only after a matching durable backend commit receipt.
// Staging receipts, writes and local projections never retire original evidence.
func (j *Journal) AcknowledgeObservation(ctx context.Context, lease int64, id, digest string) error {
	if id == "" || len(id) > 256 || len(digest) != 64 {
		return errors.New("invalid native observation acknowledgement")
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
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT digest FROM worker_observations WHERE id=?`, id).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if previous != digest {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_observation_sequence WHERE observation_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_content_fragments WHERE observation_id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_source_captures WHERE id=?`, id); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM worker_observations WHERE id=? AND digest=?`, id, digest)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if retry := j.sourceRetries[id]; retry != nil {
		retry.retired = true
	}
	close(j.observationCapacity)
	j.observationCapacity = make(chan struct{})
	return j.reclaimSourceStreamsLocked(ctx)
}

// Capture before attempting a journal write so a concurrent capacity release
// cannot be missed between the failed write and the native reader's wait.
func (j *Journal) ObservationCapacity() <-chan struct{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.observationCapacity
}
