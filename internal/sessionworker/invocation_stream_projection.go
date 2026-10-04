package sessionworker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/session"
)

func (o *SessionOwner) projectInvocationStreams(ctx context.Context) error {
	j := o.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var lease int64
	if err = tx.QueryRowContext(ctx, `SELECT lease FROM worker_meta WHERE singleton=1`).Scan(&lease); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.sequence,s.native_generation,COALESCE(c.lease,0),COALESCE(c.expires_at,0) FROM worker_invocation_streams s LEFT JOIN worker_invocation_stream_subscriptions c ON c.sequence=s.sequence WHERE s.closed=0 ORDER BY s.sequence`)
	if err != nil {
		return err
	}
	type eligible struct {
		sequence      int64
		generation    string
		lease, expiry int64
	}
	var sources []eligible
	for rows.Next() {
		var e eligible
		if err = rows.Scan(&e.sequence, &e.generation, &e.lease, &e.expiry); err != nil {
			break
		}
		sources = append(sources, e)
		if len(sources) > maxCommands {
			err = ErrFull
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return nil
	}
	for _, e := range sources {
		source, err := readNativeTurn(ctx, tx, e.generation, logicalWorkerTurn(e.sequence))
		if err != nil {
			return err
		}
		h, err := j.readInvocationCheckpoint(ctx, tx, o.captureKey, invocationIdentity(source))
		if err != nil {
			return err
		}
		if (e.expiry != 0 && e.expiry <= time.Now().UnixNano()) || (e.expiry == 0 && !h.ClaimDeadline.After(time.Now())) {
			h.Closed = true
			if h.UnavailableReason == "" {
				h.UnavailableReason = "consumer_expired"
				if e.expiry == 0 {
					h.UnavailableReason = "consumer_unclaimed"
				}
			}
			h.Pending = nil
			if _, err = tx.ExecContext(ctx, `DELETE FROM worker_invocation_stream_deltas WHERE sequence=?`, e.sequence); err != nil {
				clear(h.Key)
				return err
			}
			err = j.writeInvocationCheckpoint(ctx, tx, o.captureKey, h)
			clear(h.Key)
			if err != nil {
				return err
			}
			continue
		}
		if e.lease != lease || e.expiry == 0 || h.Pending != nil {
			clear(h.Key)
			continue
		}
		if err = j.projectInvocationRangeTx(ctx, tx, o.captureKey, &h); err != nil {
			clear(h.Key)
			return err
		}
		clear(h.Key)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(ctx)
}

func (j *Journal) projectInvocationRangeTx(ctx context.Context, tx *sql.Tx, key []byte, h *invocationStreamCheckpoint) error {
	if h.Pending != nil || h.Closed {
		return nil
	}
	cursor := h.Cursor
	payload := InvocationStreamRange{Source: h.Source, Origin: h.Origin, Ordinal: h.ProjectionOrdinal + 1, ByteOffset: cursor.Bytes, Proof: NativeOutputStreamProof{Format: NativeOutputStreamCaptureFormat, StreamID: h.StreamID, DeltaCount: h.Captured, RollingDigest: h.CapturedDigest, ByteOffset: cursor.Bytes, FirstObservedAt: h.FirstCapturedAt, LastObservedAt: h.LastCapturedAt}}
	aead, err := captureAEAD(key, j.scope, j.dir)
	if err != nil {
		return err
	}
	if h.UnavailableReason != "" {
		payload.DeliveryError = h.UnavailableReason
	}
	if h.UnavailableReason == "" {
		rows, err := tx.QueryContext(ctx, `SELECT ordinal,ciphertext FROM worker_invocation_stream_deltas WHERE sequence=? AND ordinal>=? ORDER BY ordinal`, h.Source.Sequence, cursor.Ordinal)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ordinal int64
			var cipher []byte
			if err = rows.Scan(&ordinal, &cipher); err != nil {
				break
			}
			if ordinal != cursor.Ordinal || ordinal > h.Captured || len(cipher) < aead.NonceSize()+aead.Overhead() {
				err = ErrConflict
				break
			}
			raw, openErr := aead.Open(nil, cipher[:aead.NonceSize()], cipher[aead.NonceSize():], outputDeltaAAD(j.scope, j.dir, h.Source.NativeGeneration, h.Source.Sequence, ordinal))
			if openErr != nil {
				err = ErrConflict
				break
			}
			var event session.SessionEvent
			if json.Unmarshal(raw, &event) != nil || event.Type != session.EventTurnOutput || !event.NativeOutput || event.TurnID != h.Source.LogicalTurnID || event.SessionID != h.Source.NativeSessionID || cursor.InFrame > len(event.Output) {
				clear(raw)
				err = ErrConflict
				break
			}
			previous, decodeErr := hex.DecodeString(cursor.Digest)
			if decodeErr != nil {
				clear(raw)
				err = ErrConflict
				break
			}
			hash := sha256.New()
			hash.Write(previous)
			hash.Write(raw)
			digest := hex.EncodeToString(hash.Sum(nil))
			clear(raw)
			count := min(len(event.Output)-cursor.InFrame, invocationStreamChunkBytes-len(payload.Data))
			if utf8.ValidString(event.Output) && cursor.InFrame+count < len(event.Output) {
				for count > 0 && !utf8.RuneStart(event.Output[cursor.InFrame+count]) {
					count--
				}
			}
			if count == 0 && cursor.InFrame < len(event.Output) {
				break
			}
			payload.Data = append(payload.Data, event.Output[cursor.InFrame:cursor.InFrame+count]...)
			cursor.InFrame += count
			cursor.Bytes += int64(count)
			if cursor.InFrame == len(event.Output) {
				cursor.Ordinal++
				cursor.InFrame = 0
				cursor.Digest = digest
			}
			if cursor.InFrame != 0 || len(payload.Data) == invocationStreamChunkBytes {
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if cursor.Ordinal == h.Captured+1 && (cursor.InFrame != 0 || cursor.Bytes != h.NativeBytes || cursor.Digest != h.CapturedDigest) {
			return ErrConflict
		}
	}
	if len(payload.Data) == 0 && payload.DeliveryError == "" {
		if cursor.Ordinal != h.Captured+1 {
			return ErrConflict
		}
		if h.Terminal == nil {
			return nil
		}
		// Genuine terminal source, copied in its original observation transaction.
		payload.Terminal = h.Terminal
	}
	payload.Proof.ByteLength = len(payload.Data)
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	defer clear(plain)
	aad := h.Source.SourceInvocation.InputAAD
	aad.ObjectType = e2ee.ObjectTypeInvocationOutput
	aad.Sender = j.scope.InstanceID
	// This timestamp belongs to original capture, never timer scheduling.
	if payload.DeliveryError != "" {
		aad.CreatedAt = h.UnavailableAt.UTC().Format(time.RFC3339Nano)
	} else if payload.Terminal != nil {
		aad.CreatedAt = payload.Terminal.ObservedAt.UTC().Format(time.RFC3339Nano)
	} else {
		aad.CreatedAt = h.LastCapturedAt.UTC().Format(time.RFC3339Nano)
	}
	var original [32]byte
	copy(original[:], h.Key)
	encrypted, err := e2ee.Encrypt(plain, original, aad)
	clear(original[:])
	if err != nil {
		return err
	}
	projection := InvocationStreamProjection{Ordinal: payload.Ordinal, AAD: aad, Ciphertext: encrypted}
	projection.Digest = invocationProjectionDigest(projection)
	h.Pending = &projection
	h.PendingCursor = cursor
	h.PendingTerminal = payload.Terminal != nil || payload.DeliveryError != ""
	h.ProjectionOrdinal = payload.Ordinal
	return j.writeInvocationCheckpoint(ctx, tx, key, *h)
}

// A real completion or stopped observation enters the stream ledger in the
// SAME FULL transaction. Ordinary source ACK can never erase its provenance.
func (j *Journal) recordInvocationTerminalTx(ctx context.Context, tx *sql.Tx, key []byte, observation NativeObservation) error {
	switch observation.Event.Type {
	case session.EventTurnCompleted, session.EventTurnFailed, session.EventSessionStopped:
	default:
		return nil
	}
	var identities []InvocationStreamIdentity
	if observation.TurnSource != nil && observation.TurnSource.SourceInvocation != nil {
		identities = append(identities, invocationIdentity(*observation.TurnSource))
	} else if observation.Event.Type == session.EventSessionStopped {
		rows, err := tx.QueryContext(ctx, `SELECT sequence FROM worker_invocation_streams WHERE native_generation=?`, observation.NativeGeneration)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sequence int64
			if err = rows.Scan(&sequence); err != nil {
				rows.Close()
				return err
			}
			source, sourceErr := readNativeTurn(ctx, tx, observation.NativeGeneration, logicalWorkerTurn(sequence))
			if sourceErr != nil {
				rows.Close()
				return sourceErr
			}
			if source.NativeSessionID == observation.NativeSessionID {
				identities = append(identities, invocationIdentity(source))
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	for _, id := range identities {
		h, err := j.readInvocationCheckpoint(ctx, tx, key, id)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if h.Terminal != nil {
			clear(h.Key)
			continue
		}
		if observation.NativeGeneration != h.Source.NativeGeneration || observation.NativeSessionID != h.Source.NativeSessionID || !reflect.DeepEqual(observation.Origin, h.Origin) {
			clear(h.Key)
			return ErrConflict
		}
		copy := observation
		h.Terminal = &copy
		if err = j.writeInvocationCheckpoint(ctx, tx, key, h); err != nil {
			clear(h.Key)
			return err
		}
		clear(h.Key)
	}
	return nil
}

// Before any new native work, authenticate every retained sealed cursor, even
// a closed one. Plain SQL bookkeeping cannot authorize source proof deletion.
func (o *SessionOwner) recoverInvocationStreams(ctx context.Context) error {
	j := o.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sequence,native_generation FROM worker_invocation_streams ORDER BY sequence`)
	if err != nil {
		return err
	}
	type entry struct {
		sequence   int64
		generation string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err = rows.Scan(&e.sequence, &e.generation); err != nil {
			break
		}
		entries = append(entries, e)
		if len(entries) > maxCommands {
			err = ErrFull
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		source, readErr := readNativeTurn(ctx, tx, e.generation, logicalWorkerTurn(e.sequence))
		if readErr != nil {
			return readErr
		}
		h, readErr := j.readInvocationCheckpoint(ctx, tx, o.captureKey, invocationIdentity(source))
		if readErr != nil {
			return readErr
		}
		clear(h.Key)
	}
	var orphan bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_invocation_stream_deltas d LEFT JOIN worker_invocation_streams s ON s.sequence=d.sequence WHERE s.sequence IS NULL) OR EXISTS(SELECT 1 FROM worker_invocation_stream_subscriptions c LEFT JOIN worker_invocation_streams s ON s.sequence=c.sequence WHERE s.sequence IS NULL)`).Scan(&orphan); err != nil {
		return err
	}
	if orphan {
		return ErrConflict
	}
	return nil
}
