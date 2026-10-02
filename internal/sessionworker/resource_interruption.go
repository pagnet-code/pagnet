package sessionworker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func (j *Journal) recordNativeResourceInterruption(ctx context.Context, producer *nativeSourceProducer, source NativeTurnSource, cause string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if producer == nil || producer.closed || !j.sourceProducers[producer] || producer.generation != source.NativeGeneration {
		return ErrFenced
	}
	var origin transport.NativeObservationOrigin
	if json.Unmarshal(producer.origin, &origin) != nil || origin.ID == "" {
		return ErrConflict
	}
	proof := transport.NativeResourceInterruption{Cause: cause, Source: transport.NativeAgentSource{OriginID: origin.ID, NativeGeneration: source.NativeGeneration, SessionID: source.NativeSessionID, LogicalTurnID: source.LogicalTurnID, NativeTurnSequence: source.Sequence, InputKind: source.InputKind, SourceCommandID: source.SourceCommandID, SourceAdmissionID: source.SourceAdmissionID}}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var prior []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM worker_resource_interruptions WHERE sequence=?`, source.Sequence).Scan(&prior)
	if err == nil {
		if string(prior) != string(raw) {
			return ErrConflict
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	changed, err := tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET capture_left=capture_left-? WHERE sequence=? AND observation_id='' AND capture_left>=?`, len(raw), source.Sequence, len(raw))
	if err != nil {
		return err
	}
	count, _ := changed.RowsAffected()
	if count != 1 {
		return ErrFull
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_resource_interruptions(sequence,native_generation,payload) VALUES(?,?,?)`, source.Sequence, source.NativeGeneration, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (j *Journal) nativeResourceInterruption(ctx context.Context, generation string) (*transport.NativeResourceInterruption, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var raw []byte
	err := j.db.QueryRowContext(ctx, `SELECT payload FROM worker_resource_interruptions WHERE native_generation=? ORDER BY sequence DESC LIMIT 1`, generation).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result transport.NativeResourceInterruption
	if json.Unmarshal(raw, &result) != nil || result.Source.NativeGeneration != generation {
		return nil, ErrConflict
	}
	return &result, nil
}
func (o *SessionOwner) nativeOutputResourceLimit(p *nativeSourceProducer, source *NativeTurnSource, err error) error {
	if source == nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 3e9)
	defer cancel()
	if persistErr := o.journal.recordNativeResourceInterruption(ctx, p, *source, func() string {
		if errors.Is(err, ErrNativeCaptureLimit) {
			return transport.NativeResourceCaptureLimit
		}
		if errors.Is(err, ErrNativeEventLimit) {
			return transport.NativeResourceEventLimit
		}
		return transport.NativeResourceOutputLimit
	}()); persistErr != nil {
		return persistErr
	}
	return session.ErrNativeResourceLimit
}

func nativeSourceResourceLimit(err error) bool {
	return errors.Is(err, ErrNativeOutputLimit) || errors.Is(err, ErrNativeCaptureLimit) || errors.Is(err, ErrNativeEventLimit)
}
