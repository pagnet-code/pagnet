package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// ResourceInterrupted is a local, receipt-proven process interruption. It is
// neither a vendor turn result nor permission to replay any prior native effect.
const ResourceInterrupted = "resource_interrupted"

type resourceSettlement struct {
	Observation NativeObservation                         `json:"observation"`
	Receipt     transport.NativeObservationReceiptPayload `json:"receipt"`
	Proof       transport.NativeDispatchProof             `json:"proof"`
}

func (j *Journal) initializeResourceSettlements() error {
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_resource_settlements(sequence INTEGER PRIMARY KEY,observation_id TEXT NOT NULL UNIQUE,source_digest TEXT NOT NULL,payload BLOB NOT NULL,finished INTEGER NOT NULL DEFAULT 0 CHECK(finished IN(0,1)))`)
	if err != nil {
		return err
	}
	rows, err := j.db.Query(`SELECT sequence,observation_id,source_digest,payload,finished FROM worker_resource_settlements`)
	if err != nil {
		return err
	}
	defer rows.Close()
	count, total := 0, 0
	for rows.Next() {
		var sequence int64
		var finished int
		var id, digest string
		var raw []byte
		var evidence resourceSettlement
		if err = rows.Scan(&sequence, &id, &digest, &raw, &finished); err != nil {
			return err
		}
		count++
		total += len(raw)
		if (finished != 0 && finished != 1) || count > maxCommands || total > maxPendingObservationBytes || json.Unmarshal(raw, &evidence) != nil || validateResourceSettlement(j.scope, evidence) != nil || evidence.Observation.ID != id || evidence.Observation.SourceDigest != digest || evidence.Observation.ResourceInterruption.Source.NativeTurnSequence != sequence {
			return ErrConflict
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Exclusive lifetime-lock reopen means no prior owner finish callback survives.
	_, err = j.db.Exec(`UPDATE worker_resource_settlements SET finished=1`)
	return err
}

func validateResourceSettlement(scope Scope, evidence resourceSettlement) error {
	o := evidence.Observation
	if o.ResourceInterruption == nil || o.Event.Type != session.EventSessionStopped {
		return ErrConflict
	}
	m := *o.ResourceInterruption
	if m.Cause != transport.NativeResourceOutputLimit && m.Cause != transport.NativeResourceCaptureLimit && m.Cause != transport.NativeResourceEventLimit {
		return ErrConflict
	}
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(o.Origin, &origin) != nil || origin.ID != m.Source.OriginID || origin.TenantID != scope.TenantID || origin.HostID != scope.HostID || origin.InstanceID != scope.InstanceID || origin.NativeGeneration != o.NativeGeneration || m.Source.NativeGeneration != o.NativeGeneration || m.Source.SessionID != o.NativeSessionID || o.Event.SessionID != o.NativeSessionID || m.Source.NativeTurnSequence <= 0 || m.Source.LogicalTurnID != logicalWorkerTurn(m.Source.NativeTurnSequence) || !ValidNativeInputKind(m.Source.InputKind) {
		return ErrConflict
	}
	p := evidence.Proof
	if p.OwnershipID == "" || p.OwnershipGeneration != scope.Generation || p.DispatchSequence <= 0 || p.SourceCommandID != m.Source.SourceCommandID || p.SourceAdmissionID != m.Source.SourceAdmissionID || p.SourceRunnerID == "" || p.SourceRunnerEpoch.IsZero() || p.SourceBootID == "" {
		return ErrConflict
	}
	digest, err := observationDigest(o)
	if err != nil || digest != o.SourceDigest {
		return ErrConflict
	}
	wire, err := NativeBackendObservation(o)
	r := evidence.Receipt
	if err != nil || wire.MessageType != transport.MsgAgentStopped || r.Disposition != "committed" || r.ObservationID != o.ID || r.OriginID != wire.OriginID || r.Digest != wire.Digest {
		return ErrConflict
	}
	return nil
}

// Called within the observation ACK transaction, using only the worker's
// private capture key. All native tail evidence stays until its original bytes
// have been captured and every earlier observation has actually committed.
func (j *Journal) settleResourceObservationTx(ctx context.Context, tx *sql.Tx, o NativeObservation, receipt *transport.NativeObservationReceiptPayload, captureKey []byte) error {
	if o.ResourceInterruption == nil {
		return nil
	}
	if receipt == nil {
		return ErrConflict
	}
	s := o.ResourceInterruption.Source
	var marker []byte
	if err := tx.QueryRowContext(ctx, `SELECT payload FROM worker_resource_interruptions WHERE sequence=? AND native_generation=?`, s.NativeTurnSequence, o.NativeGeneration).Scan(&marker); err != nil {
		return err
	}
	var original transport.NativeResourceInterruption
	if json.Unmarshal(marker, &original) != nil || !reflect.DeepEqual(original, *o.ResourceInterruption) {
		return ErrConflict
	}
	turn, err := readNativeTurn(ctx, tx, o.NativeGeneration, s.LogicalTurnID)
	if err != nil {
		return err
	}
	if turn.Sequence != s.NativeTurnSequence || turn.NativeSessionID != s.SessionID || turn.SourceCommandID != s.SourceCommandID || turn.SourceAdmissionID != s.SourceAdmissionID || turn.InputKind != s.InputKind {
		return ErrConflict
	}
	var proofRaw, admissionRaw []byte
	var state, kind, command string
	if err = tx.QueryRowContext(ctx, `SELECT d.proof,w.state,w.kind,w.command_id,a.admission FROM worker_dispatches d JOIN worker_intent w ON w.sequence=d.operation_sequence JOIN worker_intent_admission a ON a.sequence=w.sequence WHERE d.operation_sequence=?`, turn.Sequence).Scan(&proofRaw, &state, &kind, &command, &admissionRaw); err != nil {
		return err
	}
	var proof transport.NativeDispatchProof
	var admission Admission
	if json.Unmarshal(proofRaw, &proof) != nil || json.Unmarshal(admissionRaw, &admission) != nil || admission.Scope != j.scope || admission.NativeAdmissionID != s.SourceAdmissionID || admission.RunnerID != proof.SourceRunnerID || !admission.RunnerEpoch.Equal(proof.SourceRunnerEpoch) || admission.BootID != proof.SourceBootID || command != s.SourceCommandID || kind != "prompt" || (state != "admitted" && state != "uncertain") {
		return ErrConflict
	}
	evidence := resourceSettlement{Observation: o, Receipt: *receipt, Proof: proof}
	if validateResourceSettlement(j.scope, evidence) != nil {
		return ErrConflict
	}
	var quiesced bool
	if err = tx.QueryRowContext(ctx, `SELECT quiesced FROM worker_source_registration WHERE origin_id=? AND native_generation=?`, s.OriginID, o.NativeGeneration).Scan(&quiesced); err != nil {
		return err
	}
	if !quiesced {
		return ErrConflict
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	if len(raw) > maxFrame*3/4 {
		return ErrFull
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_resource_settlements(sequence,observation_id,source_digest,payload,finished) VALUES(?,?,?,?,?)`, turn.Sequence, o.ID, o.SourceDigest, raw, state == "uncertain"); err != nil {
		return err
	}
	result := json.RawMessage(`{"interruption":"native_resource_limit","priorEffects":"not_replayable"}`)
	if _, err = tx.ExecContext(ctx, `UPDATE worker_intent SET state=?,result=? WHERE sequence=? AND state IN ('admitted','uncertain')`, ResourceInterrupted, []byte(result), turn.Sequence); err != nil {
		return err
	}
	// Actual EOF closes this source binding, without inventing a native choice
	// resolution or settling a separate approval operation.
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_interaction_sources WHERE native_generation=? AND native_session=? AND logical_turn=?`, o.NativeGeneration, s.SessionID, s.LogicalTurnID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_turn_sources SET completed=1 WHERE native_generation=? AND logical_turn=?`, o.NativeGeneration, s.LogicalTurnID); err != nil {
		return err
	}
	return j.collectStoppedNativeReservationsTx(ctx, tx, captureKey, o.NativeGeneration, s.SessionID, s.OriginID, turn.Sequence)
}

func resourceSettlementReplayTx(ctx context.Context, tx *sql.Tx, id, digest string, receipt *transport.NativeObservationReceiptPayload) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT payload FROM worker_resource_settlements WHERE observation_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var evidence resourceSettlement
	if json.Unmarshal(raw, &evidence) != nil || evidence.Observation.SourceDigest != digest || receipt == nil || evidence.Receipt != *receipt {
		return ErrConflict
	}
	return nil
}
