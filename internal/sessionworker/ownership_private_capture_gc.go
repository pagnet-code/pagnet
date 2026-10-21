package sessionworker

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

// Private observations with no accepted turn/source adapter are local captures,
// not unpublished task effects. Only original reader quiescence plus the exact
// backend retirement transaction permits their removal. Supported observations,
// accepted-turn evidence and authenticated quarantine dispositions stay fenced.
func (j *Journal) collectClosedPrivateObservationsTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.digest,o.payload FROM worker_observations o JOIN worker_source_registration r ON r.origin_id=json_extract(o.payload,'$.origin.id') AND r.native_generation=json_extract(o.payload,'$.nativeGeneration') WHERE r.quiesced=1 AND NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id) LIMIT ?`, maxPendingObservations)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, digest string
		var raw []byte
		if err = rows.Scan(&id, &digest, &raw); err != nil {
			rows.Close()
			return err
		}
		var o NativeObservation
		var origin transport.NativeObservationOrigin
		if len(raw) > maxFrame*3/4 || json.Unmarshal(raw, &o) != nil || o.ID != id || o.SourceDigest != digest || o.TurnSource != nil {
			continue
		}
		if json.Unmarshal(o.Origin, &origin) != nil || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.NativeGeneration != o.NativeGeneration {
			continue
		}
		actual, digestErr := observationDigest(o)
		if digestErr != nil || actual != digest {
			continue
		}
		if _, wireErr := NativeBackendObservation(o); !errors.Is(wireErr, ErrNativeSourceUnsupported) {
			continue
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		for _, q := range []string{`DELETE FROM worker_observation_sequence WHERE observation_id=?`, `DELETE FROM worker_content_fragments WHERE observation_id=?`, `DELETE FROM worker_source_captures WHERE id=?`, `DELETE FROM worker_observations WHERE id=?`} {
			if _, err = tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// Explicit deletion can discard a private ask output only after its original
// accepted prompt was completed and acknowledged. It cannot settle task effects
// or turn an unsupported capture into a published source acknowledgement.
func (j *Journal) collectDeletedPrivateTurnOutputsTx(ctx context.Context, tx *sql.Tx, key []byte, deletion *transport.NativeOwnershipDeletionProof, owned transport.NativeWorkerOwnership) error {
	if len(key) != 32 {
		return nil
	}
	var stopRaw []byte
	var final bool
	err := tx.QueryRowContext(ctx, `SELECT proof,dispatch_sequence=(SELECT last_sequence FROM worker_dispatch_meta WHERE singleton=1) AND operation_kind='stop' AND state='completed' FROM worker_dispatches WHERE dispatch_sequence=?`, deletion.StopProof.DispatchSequence).Scan(&stopRaw, &final)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var stop transport.NativeDispatchProof
	if !final || json.Unmarshal(stopRaw, &stop) != nil || !transport.SameNativeDispatchProof(stop, deletion.StopProof) {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.digest,o.payload,c.ciphertext,c.size FROM worker_observations o JOIN worker_source_captures c ON c.id=o.id JOIN worker_source_registration r ON r.origin_id=json_extract(o.payload,'$.origin.id') AND r.native_generation=json_extract(o.payload,'$.nativeGeneration') WHERE r.quiesced=1 AND NOT EXISTS(SELECT 1 FROM worker_source_dispositions d WHERE d.observation_id=o.id) AND NOT EXISTS(SELECT 1 FROM worker_content_fragments f WHERE f.observation_id=o.id) AND NOT EXISTS(SELECT 1 FROM worker_observation_sequence s WHERE s.observation_id=o.id) LIMIT ?`, maxPendingObservations)
	if err != nil {
		return err
	}
	type candidate struct {
		observation NativeObservation
		cipher      []byte
	}
	var candidates []candidate
	for rows.Next() {
		var id, digest string
		var raw, encrypted []byte
		var size int
		if err = rows.Scan(&id, &digest, &raw, &encrypted, &size); err != nil {
			rows.Close()
			return err
		}
		var o NativeObservation
		var origin transport.NativeObservationOrigin
		if len(raw) > maxFrame*3/4 || json.Unmarshal(raw, &o) != nil || o.ID != id || o.SourceDigest != digest || o.SourceSequence != 0 || o.SourceUnavailable || o.SourceContentUnavailable || o.OutputContent != nil || o.PlanContent != nil || o.OriginalNativePayloadContent != nil || o.Inspection != nil || o.Resolution != nil || o.ResourceInterruption != nil || o.InteractionID != "" || o.Event.Type != session.EventTurnOutput || !o.Event.NativeOutput || o.OutputStream == nil || o.Capture == nil || o.Capture.Version != 3 || size != len(encrypted) {
			continue
		}
		source := o.TurnSource
		if source == nil || source.InputKind != "ask" || source.SourceTask != nil || source.SourceInvocation != nil || source.Sequence <= 0 || source.LogicalTurnID != logicalWorkerTurn(source.Sequence) || source.LogicalTurnID != o.Event.TurnID || source.NativeGeneration != o.NativeGeneration || source.NativeSessionID != o.NativeSessionID || o.Event.SessionID != o.NativeSessionID || o.NativeSessionID == "" || source.SourceCommandID == "" || source.SourceAdmissionID == "" {
			continue
		}
		if json.Unmarshal(o.Origin, &origin) != nil || origin.ID == "" || origin.TenantID != j.scope.TenantID || origin.HostID != j.scope.HostID || origin.InstanceID != j.scope.InstanceID || origin.Runtime != owned.Runtime || origin.NativeGeneration != o.NativeGeneration {
			continue
		}
		actual, digestErr := observationDigest(o)
		if digestErr != nil || actual != digest || NativeSourceType(o) != "" {
			continue
		}
		stream := o.OutputStream
		rolling, decodeErr := hex.DecodeString(stream.RollingDigest)
		if stream.Format != NativeOutputStreamCaptureFormat || stream.StreamID == "" || stream.BatchID != o.ID || stream.DeltaCount <= 0 || decodeErr != nil || len(rolling) != 32 || stream.ByteOffset < 0 || stream.ByteLength <= 0 || stream.FirstObservedAt.IsZero() || stream.LastObservedAt.Before(stream.FirstObservedAt) || !o.ObservedAt.Equal(stream.FirstObservedAt) {
			continue
		}
		candidates = append(candidates, candidate{o, encrypted})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range candidates {
		o := c.observation
		source, readErr := readNativeTurn(ctx, tx, o.NativeGeneration, o.TurnSource.LogicalTurnID)
		if errors.Is(readErr, sql.ErrNoRows) {
			continue
		}
		if readErr != nil {
			return readErr
		}
		if !reflect.DeepEqual(source, *o.TurnSource) {
			continue
		}
		var raw []byte
		var completed bool
		err = tx.QueryRowContext(ctx, `SELECT d.proof,d.operation_kind='prompt' AND d.state='completed' AND d.command_id=? AND d.dispatch_sequence<? AND (d.operation_sequence<=(SELECT retired FROM worker_meta WHERE singleton=1) OR EXISTS(SELECT 1 FROM worker_intent w WHERE w.sequence=d.operation_sequence AND w.kind='prompt' AND w.state='completed' AND w.acknowledged=1)) FROM worker_dispatches d WHERE d.operation_sequence=?`, source.SourceCommandID, deletion.StopProof.DispatchSequence, source.Sequence).Scan(&raw, &completed)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		var p transport.NativeDispatchProof
		if !completed || json.Unmarshal(raw, &p) != nil || p.OwnershipID != owned.ID || p.OwnershipGeneration != j.scope.Generation || p.SourceCommandID != source.SourceCommandID || p.SourceAdmissionID != source.SourceAdmissionID || p.TaskSource != nil || p.InvocationSource != nil {
			continue
		}
		captured, openErr := OpenNativeSourceCapture(key, j.scope, j.dir, o, c.cipher)
		if openErr != nil {
			continue
		}
		event := captured.Event
		length := len(event.Output)
		event.Output = ""
		if length != o.OutputStream.ByteLength || !reflect.DeepEqual(event, o.Event) || !reflect.DeepEqual(captured.OutputStream, o.OutputStream) {
			continue
		}
		for _, q := range []string{`DELETE FROM worker_source_captures WHERE id=?`, `DELETE FROM worker_observations WHERE id=?`} {
			if _, err = tx.ExecContext(ctx, q, o.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
