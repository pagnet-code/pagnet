package sessionworker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func (j *Journal) initializeAccountReplySettlements() error {
	if _, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_account_reply_settlements(observation_id TEXT PRIMARY KEY,operation_sequence INTEGER NOT NULL CHECK(operation_sequence>0),source_digest TEXT NOT NULL,wire_digest TEXT NOT NULL,reference BLOB NOT NULL,receipt BLOB NOT NULL)`); err != nil {
		return err
	}
	rows, err := j.db.Query(`SELECT observation_id,operation_sequence,source_digest,wire_digest,reference,receipt,(SELECT next_sequence FROM worker_meta WHERE singleton=1) FROM worker_account_reply_settlements`)
	if err != nil {
		return err
	}
	defer rows.Close()
	count, total := 0, 0
	for rows.Next() {
		var id, sourceDigest, wireDigest string
		var operationSequence, nextSequence int64
		var reference, receipt []byte
		if err = rows.Scan(&id, &operationSequence, &sourceDigest, &wireDigest, &reference, &receipt, &nextSequence); err != nil {
			return err
		}
		count++
		total += len(reference) + len(receipt)
		decodedDigest, digestErr := hex.DecodeString(sourceDigest)
		if count > maxCommands || total > maxPendingObservationBytes || digestErr != nil || len(decodedDigest) != 32 {
			return ErrConflict
		}
		ref, decodeErr := transport.DecodeNativeAccountReplyBegin(reference)
		if decodeErr != nil || operationSequence <= 0 || operationSequence >= nextSequence || ref.ObservationID != id || ref.InstanceID != j.scope.InstanceID || ref.ManifestAAD.NativeContent == nil || ref.ManifestAAD.NativeContent.LogicalTurnID != logicalWorkerTurn(operationSequence) || len(sourceDigest) != 64 {
			return ErrConflict
		}
		if _, err = transport.DecodeNativeAccountReplyReceipt(receipt, ref, wireDigest); err != nil {
			return ErrConflict
		}
	}
	return rows.Err()
}

// AcknowledgeAccountReplyObservation accepts only a correlated durable account
// commit receipt, and persists its replay identity in the same deletion commit.
// Exact replay remains available until the original backend dispatch retires.
func (j *Journal) AcknowledgeAccountReplyObservation(ctx context.Context, lease int64, id, digest string, receipt *transport.NativeAccountReplyReceiptPayload) error {
	if id == "" || len(id) > 256 || len(digest) != 64 || receipt == nil {
		return ErrConflict
	}
	decodedDigest, digestErr := hex.DecodeString(digest)
	if digestErr != nil || len(decodedDigest) != 32 {
		return ErrConflict
	}
	rawReceipt, err := MarshalNativeJSON(receipt)
	if err != nil {
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
	var previous string
	var raw []byte
	var sequence int64
	err = tx.QueryRowContext(ctx, `SELECT o.digest,o.payload,COALESCE(s.source_sequence,0) FROM worker_observations o LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.id=?`, id).Scan(&previous, &raw, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		var storedDigest string
		var storedReceipt []byte
		if err = tx.QueryRowContext(ctx, `SELECT source_digest,receipt FROM worker_account_reply_settlements WHERE observation_id=?`, id).Scan(&storedDigest, &storedReceipt); err != nil {
			return ErrConflict
		}
		if storedDigest != digest || !bytes.Equal(storedReceipt, rawReceipt) {
			return ErrConflict
		}
		return nil
	}
	if err != nil {
		return err
	}
	if previous != digest {
		return ErrConflict
	}
	var o NativeObservation
	if json.Unmarshal(raw, &o) != nil || o.ID != id || o.SourceDigest != digest || o.TurnSource == nil || o.OutputContent == nil {
		return ErrConflict
	}
	originalDigest, err := observationDigest(o)
	if err != nil || originalDigest != digest {
		return ErrConflict
	}
	o.SourceSequence = sequence
	wire, err := NativeAccountReplyObservation(o)
	if err != nil {
		return err
	}
	proof, err := accountReplyProof(ctx, tx, *o.TurnSource)
	if err != nil || validateAccountReply(o, *o.OutputContent, proof) != nil {
		return ErrConflict
	}
	if _, err = transport.DecodeNativeAccountReplyReceipt(rawReceipt, *o.OutputContent, wire.Digest); err != nil {
		return ErrConflict
	}
	var quarantined bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_source_dispositions WHERE observation_id=?)`, id).Scan(&quarantined); err != nil {
		return err
	}
	if quarantined {
		return ErrConflict
	}
	var count, total int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(length(reference)+length(receipt)),0) FROM worker_account_reply_settlements`).Scan(&count, &total); err != nil {
		return err
	}
	reference, err := MarshalNativeJSON(o.OutputContent)
	if err != nil {
		return err
	}
	if count >= maxCommands || total+len(reference)+len(rawReceipt) > maxPendingObservationBytes {
		return ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_account_reply_settlements VALUES(?,?,?,?,?,?)`, id, o.TurnSource.Sequence, digest, wire.Digest, reference, rawReceipt); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM worker_observation_sequence WHERE observation_id=?`,
		`DELETE FROM worker_content_fragments WHERE observation_id=?`,
		`DELETE FROM worker_source_captures WHERE id=?`,
		`DELETE FROM worker_output_spools WHERE sequence IN(SELECT sequence FROM worker_terminal_reservations WHERE observation_id=?)`,
		`DELETE FROM worker_terminal_reservations WHERE observation_id=?`,
		`DELETE FROM worker_observations WHERE id=?`,
	} {
		if _, err = tx.ExecContext(ctx, query, id); err != nil {
			return err
		}
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

// DeliveryObservationsForLease always starts with the oldest retained supported
// source in each origin stream. Private unsupported rows cannot consume a page.
func (j *Journal) DeliveryObservationsForLease(ctx context.Context, lease int64, limit int) (NativeObservationPage, error) {
	var page NativeObservationPage
	if lease <= 0 {
		return page, ErrFenced
	}
	if limit < 1 || limit > 32 {
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
	rows, err := tx.QueryContext(ctx, `SELECT o.payload,COALESCE(s.source_sequence,0) FROM worker_observations o LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id) ORDER BY CASE WHEN s.observation_id IS NULL THEN 1 ELSE 0 END,s.origin_id,s.source_sequence,o.sequence`)
	if err != nil {
		return page, err
	}
	total := 0
	for rows.Next() {
		var raw []byte
		var sequence int64
		if err = rows.Scan(&raw, &sequence); err != nil {
			rows.Close()
			return page, err
		}
		var o NativeObservation
		if json.Unmarshal(raw, &o) != nil {
			rows.Close()
			return page, ErrConflict
		}
		o.SourceSequence = sequence
		if accountObservation(o) {
			if _, err = NativeAccountReplyObservation(o); err != nil {
				continue
			}
			if !validAccountReplySequence(ctx, tx, o) {
				continue
			}
		} else {
			if NativeSourceType(o) == "" && o.Event.Type != session.EventInteractionStarted && o.Event.Type != session.EventInteractionResolved {
				continue
			}
			if _, err = NativeBackendObservation(o); err != nil {
				if errors.Is(err, ErrNativeSourceUnsupported) {
					continue
				}
				rows.Close()
				return page, err
			}
		}
		if len(page.Observations) == limit || total+len(raw) > maxFrame*3/4 {
			page.More = true
			break
		}
		page.Observations = append(page.Observations, o)
		total += len(raw)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	return page, tx.Commit()
}
