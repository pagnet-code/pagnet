package sessionworker

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// Explicit deletion permits reclaiming only evidence with an authenticated
// terminal rejection. It never fabricates a source ACK or settles an uncertain
// native effect. The original worker scope and actual reader EOF stay mandatory.
func (j *Journal) CollectDeletionQuarantines(ctx context.Context, lease int64, proof *transport.NativeOwnershipDeletionProof) error {
	if proof == nil || proof.DeleteRequestID == "" || proof.OriginID == "" || proof.NativeGeneration == "" || proof.NativeSessionID == "" || proof.StoppedObservationID == "" || proof.StoppedSourceSequence <= 0 || proof.StoppedObservedAt.IsZero() || !proof.StoppedExpiresAt.After(proof.StoppedObservedAt) {
		return ErrConflict
	}
	switch proof.StoppedDisposition {
	case "committed", "expired", "stale_origin", transport.NativeObservationDeleteQuarantined:
	default:
		return ErrConflict
	}
	digest, err := hex.DecodeString(proof.StoppedDigest)
	if err != nil || len(digest) != 32 {
		return ErrConflict
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.sourceRetries) != 0 {
		return ErrConflict
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return err
	}
	var raw string
	var last int64
	if err = tx.QueryRowContext(ctx, `SELECT ownership,last_sequence FROM worker_dispatch_meta WHERE singleton=1`).Scan(&raw, &last); err != nil {
		return err
	}
	var owned transport.NativeWorkerOwnership
	if json.Unmarshal([]byte(raw), &owned) != nil || proof.StopProof.OwnershipID != owned.ID || proof.StopProof.OwnershipGeneration != j.scope.Generation || proof.StopProof.DispatchSequence <= 0 || proof.StopProof.DispatchSequence > last || proof.StopProof.SourceCommandID == "" || proof.StopProof.SourceAdmissionID == "" || proof.StopProof.SourceRunnerID == "" || proof.StopProof.SourceBootID == "" || proof.StopProof.SourceRunnerEpoch.IsZero() {
		return ErrConflict
	}
	var unsafe bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_source_registration WHERE quiesced=0) OR EXISTS(SELECT 1 FROM worker_intent WHERE state NOT IN ('completed','failed')) OR EXISTS(SELECT 1 FROM worker_dispatches WHERE state NOT IN ('completed','failed')) OR EXISTS(SELECT 1 FROM worker_dispatch_cancellations WHERE state!='finalized')`).Scan(&unsafe); err != nil {
		return err
	}
	if unsafe {
		return ErrConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.digest,o.payload,d.receipt,COALESCE(s.source_sequence,0) FROM worker_source_dispositions d JOIN worker_observations o ON o.id=d.observation_id JOIN worker_source_registration r ON r.origin_id=json_extract(o.payload,'$.origin.id') AND r.native_generation=json_extract(o.payload,'$.nativeGeneration') LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE r.quiesced=1 LIMIT ?`, maxPendingObservations)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, privateDigest string
		var payload, receipt []byte
		var sequence int64
		if err = rows.Scan(&id, &privateDigest, &payload, &receipt, &sequence); err != nil {
			rows.Close()
			return err
		}
		var observation NativeObservation
		var terminal transport.NativeObservationReceiptPayload
		var origin transport.NativeObservationOrigin
		if json.Unmarshal(payload, &observation) != nil || json.Unmarshal(receipt, &terminal) != nil || json.Unmarshal(observation.Origin, &origin) != nil || observation.ID != id || observation.SourceDigest != privateDigest || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.Runtime != owned.Runtime || origin.NativeGeneration != observation.NativeGeneration {
			rows.Close()
			return ErrConflict
		}
		observation.SourceSequence = sequence
		actual, digestErr := observationDigest(observation)
		if digestErr != nil || actual != privateDigest || !matchingTerminalReceipt(observation, terminal) {
			rows.Close()
			return ErrConflict
		}
		if id == proof.StoppedObservationID {
			wire, wireErr := NativeBackendObservation(observation)
			if wireErr != nil || observation.Event.Type != session.EventSessionStopped || origin.ID != proof.OriginID || observation.NativeGeneration != proof.NativeGeneration || observation.NativeSessionID != proof.NativeSessionID || wire.Digest != proof.StoppedDigest || sequence != proof.StoppedSourceSequence || !wire.ObservedAt.Equal(proof.StoppedObservedAt) || !wire.ExpiresAt.Equal(proof.StoppedExpiresAt) || terminal.Disposition != proof.StoppedDisposition {
				rows.Close()
				return ErrConflict
			}
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		for _, query := range []string{`DELETE FROM worker_source_dispositions WHERE observation_id=?`, `DELETE FROM worker_observation_sequence WHERE observation_id=?`, `DELETE FROM worker_content_fragments WHERE observation_id=?`, `DELETE FROM worker_source_captures WHERE id=?`, `DELETE FROM worker_observations WHERE id=?`} {
			if _, err = tx.ExecContext(ctx, query, id); err != nil {
				return err
			}
		}
	}
	// These are source references, not native outcomes. Only already settled
	// original local operations can lose their references after explicit deletion.
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_turn_sources AS t WHERE EXISTS(SELECT 1 FROM worker_source_registration r WHERE r.quiesced=1 AND r.native_generation=t.native_generation) AND NOT EXISTS(SELECT 1 FROM worker_observations o WHERE json_extract(o.payload,'$.nativeGeneration')=t.native_generation AND json_extract(o.payload,'$.turnSource.logicalTurnId')=t.logical_turn) AND NOT EXISTS(SELECT 1 FROM worker_interaction_sources i WHERE i.native_generation=t.native_generation AND i.logical_turn=t.logical_turn) AND (t.sequence<=(SELECT retired FROM worker_meta WHERE singleton=1) OR EXISTS(SELECT 1 FROM worker_intent w WHERE w.sequence=t.sequence AND w.state IN ('completed','failed')))`); err != nil {
		return err
	}
	if err = j.collectClosedPrivateObservationsTx(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	// Reclaim source registration only after the same transaction commits.
	if err = j.reclaimSourceStreamsLocked(ctx); errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}
