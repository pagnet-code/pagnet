package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// OwnerStopped records explicit owner-requested abandonment of the original
// interrupted process. Unknown prior effects remain non-replayable.
const OwnerStopped = "owner_stopped"

type stoppedReceipt struct {
	Observation NativeObservation                         `json:"observation"`
	Receipt     transport.NativeObservationReceiptPayload `json:"receipt"`
}
type ownerStopSettlement struct {
	Stopped  stoppedReceipt                         `json:"stopped"`
	Deletion transport.NativeOwnershipDeletionProof `json:"deletion"`
	Turn     NativeTurnSource                       `json:"turn"`
	Proof    transport.NativeDispatchProof          `json:"proof"`
}

func validateStoppedReceipt(scope Scope, e stoppedReceipt) error {
	o, r := e.Observation, e.Receipt
	var origin transport.NativeObservationOrigin
	if o.Event.Type != session.EventSessionStopped || o.NativeSessionID == "" || o.Event.SessionID != o.NativeSessionID || json.Unmarshal(o.Origin, &origin) != nil || origin.TenantID != scope.TenantID || origin.HostID != scope.HostID || origin.InstanceID != scope.InstanceID || origin.NativeGeneration != o.NativeGeneration {
		return ErrConflict
	}
	digest, err := observationDigest(o)
	if err != nil || digest != o.SourceDigest {
		return ErrConflict
	}
	wire, err := NativeBackendObservation(o)
	if err != nil || r.ObservationID != o.ID || r.OriginID != wire.OriginID || r.Digest != wire.Digest {
		return ErrConflict
	}
	switch r.Disposition {
	case "committed", "expired", "stale_origin", transport.NativeObservationDeleteQuarantined:
	default:
		return ErrConflict
	}
	return nil
}
func validateOwnerStopSettlement(scope Scope, e ownerStopSettlement) error {
	if validateStoppedReceipt(scope, e.Stopped) != nil {
		return ErrConflict
	}
	o, d, s, p := e.Stopped.Observation, e.Deletion, e.Turn, e.Proof
	wire, err := NativeBackendObservation(o)
	if err != nil || d.DeleteRequestID == "" || d.StoppedObservationID != o.ID || d.OriginID != wire.OriginID || d.NativeGeneration != o.NativeGeneration || d.NativeSessionID != o.NativeSessionID || d.StoppedDigest != wire.Digest || d.StoppedSourceSequence != o.SourceSequence || d.StoppedDisposition != e.Stopped.Receipt.Disposition || !d.StoppedObservedAt.Equal(wire.ObservedAt) || !d.StoppedExpiresAt.Equal(wire.ExpiresAt) {
		return ErrConflict
	}
	if s.Sequence <= 0 || s.LogicalTurnID != logicalWorkerTurn(s.Sequence) || s.NativeGeneration != o.NativeGeneration || s.NativeSessionID != o.NativeSessionID || !ValidNativeInputKind(s.InputKind) || p.SourceCommandID != s.SourceCommandID || p.SourceAdmissionID != s.SourceAdmissionID || !reflect.DeepEqual(p.TaskSource, s.SourceTask) || p.OwnershipGeneration != scope.Generation || p.OwnershipID == "" || d.StopProof.OwnershipID != p.OwnershipID || d.StopProof.OwnershipGeneration != p.OwnershipGeneration || d.StopProof.DispatchSequence <= p.DispatchSequence {
		return ErrConflict
	}
	return nil
}
func (j *Journal) initializeOwnerStopSettlements() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_stopped_receipts(observation_id TEXT PRIMARY KEY,source_digest TEXT NOT NULL,native_generation TEXT NOT NULL,payload BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_owner_stop_settlements(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL)`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	rows, err := j.db.Query(`SELECT observation_id,source_digest,native_generation,payload FROM worker_stopped_receipts`)
	if err != nil {
		return err
	}
	count, total := 0, 0
	for rows.Next() {
		var raw []byte
		var e stoppedReceipt
		var id, digest, generation string
		if err = rows.Scan(&id, &digest, &generation, &raw); err != nil {
			rows.Close()
			return err
		}
		count++
		total += len(raw)
		if count > maxPendingObservations || total > maxPendingObservationBytes || json.Unmarshal(raw, &e) != nil || e.Observation.ID != id || e.Observation.SourceDigest != digest || e.Observation.NativeGeneration != generation || validateStoppedReceipt(j.scope, e) != nil {
			rows.Close()
			return ErrConflict
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = j.db.Query(`SELECT sequence,payload FROM worker_owner_stop_settlements`)
	if err != nil {
		return err
	}
	defer rows.Close()
	count = 0
	for rows.Next() {
		var seq int64
		var raw []byte
		var e ownerStopSettlement
		if err = rows.Scan(&seq, &raw); err != nil {
			return err
		}
		count++
		total += len(raw)
		if count > maxCommands || total > maxPendingObservationBytes || json.Unmarshal(raw, &e) != nil || e.Turn.Sequence != seq || validateOwnerStopSettlement(j.scope, e) != nil {
			return ErrConflict
		}
	}
	return rows.Err()
}
func (j *Journal) retainStoppedReceiptTx(ctx context.Context, tx *sql.Tx, o NativeObservation, r *transport.NativeObservationReceiptPayload) error {
	if o.Event.Type != session.EventSessionStopped || o.ResourceInterruption != nil || r == nil {
		return nil
	}
	e := stoppedReceipt{Observation: o, Receipt: *r}
	if validateStoppedReceipt(j.scope, e) != nil {
		return ErrConflict
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_stopped_receipts(observation_id,source_digest,native_generation,payload) VALUES(?,?,?,?)`, o.ID, o.SourceDigest, o.NativeGeneration, raw)
	return err
}
func stoppedReceiptReplayTx(ctx context.Context, tx *sql.Tx, id, digest string, r *transport.NativeObservationReceiptPayload) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT payload FROM worker_stopped_receipts WHERE observation_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var e stoppedReceipt
	if json.Unmarshal(raw, &e) != nil || e.Observation.SourceDigest != digest || r == nil || e.Receipt != *r {
		return ErrConflict
	}
	return nil
}

// Runs before generic quarantine cleanup. Only an actual captured accepted turn
// in this original process can be abandoned by its later completed owned Stop.
func (j *Journal) settleOwnerStoppedTx(ctx context.Context, tx *sql.Tx, d *transport.NativeOwnershipDeletionProof) (err error) {
	stage := "original_candidates"
	defer func() {
		if err != nil {
			err = fmt.Errorf("owner_stop/%s: %w", stage, err)
		}
	}()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM worker_intent w JOIN worker_turn_sources t ON t.sequence=w.sequence WHERE w.state='uncertain' AND w.kind='prompt' AND t.native_generation=? AND t.native_session=?`, d.NativeGeneration, d.NativeSessionID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	stage = "original_stop_dispatch"
	var stopRaw []byte
	var stopKind, stopState string
	if err := tx.QueryRowContext(ctx, `SELECT d.proof,w.kind,w.state FROM worker_dispatches d JOIN worker_intent w ON w.sequence=d.operation_sequence WHERE d.dispatch_sequence=?`, d.StopProof.DispatchSequence).Scan(&stopRaw, &stopKind, &stopState); err != nil {
		return err
	}
	var stop transport.NativeDispatchProof
	if json.Unmarshal(stopRaw, &stop) != nil || !transport.SameNativeDispatchProof(stop, d.StopProof) || stopKind != "stop" || stopState != "completed" {
		return ErrConflict
	}
	stage = "original_stopped_receipt"
	var captured []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_stopped_receipts WHERE observation_id=?`, d.StoppedObservationID).Scan(&captured)
	var stopped stoppedReceipt
	if errors.Is(err, sql.ErrNoRows) {
		var raw, receipt []byte
		var sourceSeq int64
		err = tx.QueryRowContext(ctx, `SELECT o.payload,r.receipt,s.source_sequence FROM worker_observations o JOIN worker_source_dispositions r ON r.observation_id=o.id JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE o.id=?`, d.StoppedObservationID).Scan(&raw, &receipt, &sourceSeq)
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &stopped.Observation) != nil || json.Unmarshal(receipt, &stopped.Receipt) != nil {
			return ErrConflict
		}
		stopped.Observation.SourceSequence = sourceSeq
	} else if err != nil {
		return err
	} else if json.Unmarshal(captured, &stopped) != nil {
		return ErrConflict
	}
	stage = "original_reader_quiescence"
	var quiesced bool
	if err = tx.QueryRowContext(ctx, `SELECT quiesced FROM worker_source_registration WHERE origin_id=? AND native_generation=?`, d.OriginID, d.NativeGeneration).Scan(&quiesced); err != nil {
		return err
	}
	if !quiesced {
		return ErrConflict
	}
	stage = "accepted_turn_binding"
	rows, err := tx.QueryContext(ctx, `SELECT t.sequence,t.logical_turn,t.native_generation,t.native_session,t.source_command,t.source_admission,t.input_kind,d.proof,a.admission,t.started,t.source_task FROM worker_turn_sources t JOIN worker_intent w ON w.sequence=t.sequence JOIN worker_dispatches d ON d.operation_sequence=t.sequence JOIN worker_intent_admission a ON a.sequence=t.sequence WHERE w.state='uncertain' AND w.kind='prompt' AND t.native_generation=? AND t.native_session=?`, d.NativeGeneration, d.NativeSessionID)
	if err != nil {
		return err
	}
	var candidates []ownerStopSettlement
	for rows.Next() {
		var e ownerStopSettlement
		var proofRaw, admissionRaw []byte
		var task string
		var started bool
		e.Stopped = stopped
		e.Deletion = *d
		s := &e.Turn
		if err = rows.Scan(&s.Sequence, &s.LogicalTurnID, &s.NativeGeneration, &s.NativeSessionID, &s.SourceCommandID, &s.SourceAdmissionID, &s.InputKind, &proofRaw, &admissionRaw, &started, &task); err != nil {
			rows.Close()
			return err
		}
		if task != "" && json.Unmarshal([]byte(task), &s.SourceTask) != nil {
			rows.Close()
			return ErrConflict
		}
		var admission Admission
		if !started || json.Unmarshal(proofRaw, &e.Proof) != nil || json.Unmarshal(admissionRaw, &admission) != nil || admission.Scope != j.scope || admission.NativeAdmissionID != s.SourceAdmissionID || admission.RunnerID != e.Proof.SourceRunnerID || !admission.RunnerEpoch.Equal(e.Proof.SourceRunnerEpoch) || admission.BootID != e.Proof.SourceBootID || validateOwnerStopSettlement(j.scope, e) != nil {
			rows.Close()
			return ErrConflict
		}
		candidates = append(candidates, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(candidates) != count {
		return ErrConflict
	}
	stage = "settlement_write"
	for _, e := range candidates {
		raw, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO worker_owner_stop_settlements(sequence,payload) VALUES(?,?)`, e.Turn.Sequence, raw); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE worker_intent SET state=?,result=? WHERE sequence=? AND state='uncertain'`, OwnerStopped, []byte(`{"interruption":"explicit_owner_delete","priorEffects":"unknown_not_replayable"}`), e.Turn.Sequence); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE worker_turn_sources SET completed=1 WHERE sequence=?`, e.Turn.Sequence); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND logical_turn=?`, e.Turn.NativeGeneration, e.Turn.NativeSessionID, e.Turn.LogicalTurnID); err != nil {
			return err
		}
	}
	return nil
}

// Only an unpublished private permission inspection can be discarded under the
// exact owner-stopped proof. Task output, plans, protected references, encrypted
// fragments and any source lacking the original accepted binding stay fenced.
func (j *Journal) collectOwnerStoppedPrivateInspectionsTx(ctx context.Context, tx *sql.Tx, d *transport.NativeOwnershipDeletionProof) error {
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.digest,o.payload,c.ciphertext,COALESCE(s.source_sequence,0) FROM worker_observations o JOIN worker_source_captures c ON c.id=o.id LEFT JOIN worker_observation_sequence s ON s.observation_id=o.id WHERE json_extract(o.payload,'$.nativeGeneration')=? AND NOT EXISTS(SELECT 1 FROM worker_source_dispositions r WHERE r.observation_id=o.id) AND NOT EXISTS(SELECT 1 FROM worker_content_fragments f WHERE f.observation_id=o.id)`, d.NativeGeneration)
	if err != nil {
		return err
	}
	type candidate struct {
		o      NativeObservation
		digest string
	}
	var candidates []candidate
	for rows.Next() {
		var id, digest string
		var raw, cipher []byte
		var sourceSeq int64
		var o NativeObservation
		if err = rows.Scan(&id, &digest, &raw, &cipher, &sourceSeq); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal(raw, &o) != nil || o.ID != id || o.SourceDigest != digest || o.NativeSessionID != d.NativeSessionID || o.TurnSource == nil || o.Event.Type != session.EventInteractionStarted || o.Event.Interaction == nil || o.Event.Interaction.Resolved || o.Inspection != nil || o.Resolution != nil || o.OutputContent != nil || o.PlanContent != nil || o.OriginalNativePayloadContent != nil || o.OutputStream != nil || sourceSeq != 0 || verifyCapture(o.Capture, cipher) != nil {
			continue
		}
		actual, digestErr := observationDigest(o)
		if digestErr != nil || actual != digest {
			continue
		}
		if _, wireErr := NativeBackendObservation(o); !errors.Is(wireErr, ErrNativeSourceUnsupported) {
			continue
		}
		candidates = append(candidates, candidate{o, digest})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range candidates {
		var raw []byte
		var e ownerStopSettlement
		if err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_owner_stop_settlements WHERE sequence=?`, c.o.TurnSource.Sequence).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			return err
		}
		if json.Unmarshal(raw, &e) != nil || validateOwnerStopSettlement(j.scope, e) != nil || !transport.SameNativeOwnershipDeletionProof(e.Deletion, *d) || !reflect.DeepEqual(e.Turn, *c.o.TurnSource) || !reflect.DeepEqual(e.Stopped.Observation.Origin, c.o.Origin) {
			continue
		}
		for _, q := range []string{`DELETE FROM worker_observation_sequence WHERE observation_id=?`, `DELETE FROM worker_source_captures WHERE id=?`, `DELETE FROM worker_observations WHERE id=?`} {
			if _, err = tx.ExecContext(ctx, q, c.o.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
