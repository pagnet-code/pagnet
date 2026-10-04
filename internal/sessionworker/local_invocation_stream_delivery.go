package sessionworker

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/session"
)

// BeginLocalInvocationStream clones genuine accepted source and separately
// retained activation evidence before the driver receives the paid prompt.
func (j *Journal) BeginLocalInvocationStream(ctx context.Context, key []byte, turn NativeTurnSource) error {
	if ctx == nil || !j.isLocal() || turn.InputKind != "local-native" {
		return ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	original, e := j.localIntentSource(ctx, tx, turn.Sequence)
	if e != nil {
		return e
	}
	activation, e := j.localActivationEvidenceTx(ctx, tx, key, turn.NativeGeneration)
	if e != nil {
		return e
	}
	source := LocalStreamSource{Authority: j.authority, Turn: turn, Original: *original, ActivationOrigin: activation.Origin, ActivationAdmission: activation.Admission}
	if validateLocalStreamSource(source) != nil {
		return ErrConflict
	}
	stored, e := readNativeTurn(ctx, tx, turn.NativeGeneration, turn.LogicalTurnID)
	if e != nil || !sameLocalJSON(stored, turn) {
		return ErrConflict
	}
	previous, e := j.readLocalStreamHead(ctx, tx, key, turn.Sequence)
	if e == nil {
		if !sameLocalJSON(previous.Source, source) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if turn.Sequence <= m.LastBegunSequence {
		return ErrRetired
	}
	if m.Sources >= m.Config.MaxSources {
		var retired int64
		e = tx.QueryRowContext(ctx, `SELECT sequence FROM worker_local_stream_heads WHERE closed=1 ORDER BY sequence LIMIT 1`).Scan(&retired)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrFull
		}
		if e != nil {
			return e
		}
		old, e := j.readLocalStreamHead(ctx, tx, key, retired)
		if e != nil || !old.Terminal || old.Frames != 0 || old.Bytes != 0 {
			return ErrConflict
		}
		var headBytes int64
		if e = tx.QueryRowContext(ctx, `SELECT length(payload) FROM worker_local_stream_heads WHERE sequence=?`, retired).Scan(&headBytes); e != nil {
			return e
		}
		m.Bytes -= headBytes
		if _, e = tx.ExecContext(ctx, `DELETE FROM worker_local_stream_heads WHERE sequence=?`, retired); e != nil {
			return e
		}
		m.Sources--
	}
	h := localStreamHead{Source: source, Floor: -1}
	raw, e := sealLocalStream(key, j.authority, j.dir, "head", turn.Sequence, 0, "", h)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO worker_local_stream_heads VALUES(?,?,0)`, turn.Sequence, raw); e != nil {
		return e
	}
	if m.Frames+2*(m.PendingTerminals+1) > m.Config.MaxFrames || m.Bytes+int64(len(raw))+int64(m.PendingTerminals+1)*2048 > m.Config.MaxBytes {
		return ErrFull
	}
	m.Bytes += int64(len(raw))
	m.Sources++
	m.PendingTerminals++
	m.LastBegunSequence = turn.Sequence
	if e = j.writeLocalStreamMeta(ctx, tx, key, m); e != nil {
		return e
	}
	if e := tx.Commit(); e != nil {
		return e
	}
	j.pulseLocalReady()
	return nil
}

// Caller holds original native producer and journal transaction. Repeated
// producer callbacks are deduplicated by the enclosing delta/observation fence.
func (j *Journal) appendLocalStreamFrameTx(ctx context.Context, tx *sql.Tx, key []byte, h *localStreamHead, m *localStreamMeta, frame fabric.InvocationFrame) error {
	if h.Terminal || h.Next == math.MaxInt64 {
		return ErrConflict
	}
	frame.InvocationID = h.Source.Original.Admission.InvocationID
	frame.Sequence = uint64(h.Next)
	digest, e := localStreamDigest(h.Source)
	if e != nil {
		return e
	}
	raw, e := sealLocalStream(key, j.authority, j.dir, "frame", h.Source.Turn.Sequence, h.Next, digest, localStreamPlainFrame{h.HeadDigest, frame})
	if e != nil {
		return e
	}
	terminal := frame.Kind == fabric.FrameComplete || frame.Kind == fabric.FrameError
	if m.Frames >= m.Config.MaxFrames || int64(len(raw)) > m.Config.MaxBytes-m.Bytes {
		return ErrFull
	}
	if terminal {
		if len(raw) > 1024 || m.PendingTerminals <= 0 {
			return ErrConflict
		}
	} else if m.Frames >= m.Config.MaxFrames-m.PendingTerminals || int64(len(raw)) > m.Config.MaxBytes-m.Bytes-int64(m.PendingTerminals)*2048 {
		return ErrFull
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO worker_local_stream_frames VALUES(?,?,?)`, h.Source.Turn.Sequence, h.Next, raw); e != nil {
		return e
	}
	h.Next++
	h.Frames++
	h.Bytes += int64(len(raw))
	h.HeadDigest = localCipherDigest(raw)
	m.Frames++
	m.Bytes += int64(len(raw))
	h.Terminal = terminal
	if terminal {
		m.PendingTerminals--
	}
	return nil
}
func (j *Journal) appendLocalStreamEventTx(ctx context.Context, tx *sql.Tx, key []byte, h *localStreamHead, m *localStreamMeta, event session.SessionEvent) error {
	if event.TurnID != h.Source.Turn.LogicalTurnID || event.SessionID != h.Source.Turn.NativeSessionID {
		return ErrConflict
	}
	if h.Next == 0 {
		if e := j.appendLocalStreamFrameTx(ctx, tx, key, h, m, fabric.InvocationFrame{Kind: fabric.FrameStart}); e != nil {
			return e
		}
	}
	switch event.Type {
	case session.EventTurnStarted:
		return nil
	case session.EventTurnOutput:
		if !event.NativeOutput || !utf8.ValidString(event.Output) {
			return ErrFenced
		}
		data := []byte(event.Output)
		for len(data) > 0 {
			n := min(32<<10, len(data))
			if n < len(data) {
				for n > 0 && !utf8.RuneStart(data[n]) {
					n--
				}
			}
			if e := j.appendLocalStreamFrameTx(ctx, tx, key, h, m, fabric.InvocationFrame{Kind: fabric.FrameChunk, ContentType: "text/plain; charset=utf-8", Data: data[:n]}); e != nil {
				return e
			}
			data = data[n:]
		}
	case session.EventTurnCompleted:
		return j.appendLocalStreamFrameTx(ctx, tx, key, h, m, fabric.InvocationFrame{Kind: fabric.FrameComplete})
	case session.EventTurnFailed:
		code := fabric.ErrorCode("native.failed")
		switch event.FailureKind {
		case "auth_required":
			code = "native.auth_required"
		case "rate_limited":
			code = "native.rate_limited"
		case "interrupted":
			code = "native.interrupted"
		}
		failure := fabric.NewError(code, "Native runtime reported failure")
		failure.Effect = fabric.EffectUnknown
		return j.appendLocalStreamFrameTx(ctx, tx, key, h, m, fabric.InvocationFrame{Kind: fabric.FrameError, Error: failure})
	default:
		return ErrConflict
	}
	return nil
}
func (j *Journal) captureLocalInvocationDeltasTx(ctx context.Context, tx *sql.Tx, key []byte, source NativeTurnSource, firstDelta int64, events []session.SessionEvent) error {
	if !j.isLocal() || source.InputKind != "local-native" {
		return nil
	}
	h, e := j.readLocalStreamHead(ctx, tx, key, source.Sequence)
	if e != nil {
		return e
	}
	if !sameLocalJSON(h.Source.Turn, source) || firstDelta != h.LastDelta+1 {
		return ErrConflict
	}
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	// Project bytes from this exact admitted batch, not provider-dependent
	// event fragmentation. Original encrypted delta rows, ordinals and rolling
	// commitments remain in the same FULL transaction. This buffer never spans
	// callbacks/commits and does not fabricate a combined native event.
	buffer := make([]byte, 0, 32<<10)
	defer func() { clear(buffer[:cap(buffer)]) }()
	flush := func() error {
		if len(buffer) == 0 {
			return nil
		}
		if e := j.appendLocalStreamFrameTx(ctx, tx, key, &h, &m, fabric.InvocationFrame{Kind: fabric.FrameChunk, ContentType: "text/plain; charset=utf-8", Data: buffer}); e != nil {
			return e
		}
		clear(buffer)
		buffer = buffer[:0]
		return nil
	}
	for _, event := range events {
		if event.Type != session.EventTurnOutput || !event.NativeOutput || event.TurnID != source.LogicalTurnID || event.SessionID != source.NativeSessionID || !utf8.ValidString(event.Output) {
			return ErrFenced
		}
		if h.Next == 0 {
			if e = j.appendLocalStreamFrameTx(ctx, tx, key, &h, &m, fabric.InvocationFrame{Kind: fabric.FrameStart}); e != nil {
				return e
			}
		}
		remaining := event.Output
		for len(remaining) > 0 {
			n := min(cap(buffer)-len(buffer), len(remaining))
			if n < len(remaining) {
				for n > 0 && !utf8.RuneStart(remaining[n]) {
					n--
				}
			}
			if n == 0 {
				if e = flush(); e != nil {
					return e
				}
				continue
			}
			buffer = append(buffer, remaining[:n]...)
			remaining = remaining[n:]
			if len(buffer) == cap(buffer) {
				if e = flush(); e != nil {
					return e
				}
			}
		}
		h.LastDelta++
	}
	if e = flush(); e != nil {
		return e
	}
	if e = j.writeLocalStreamHead(ctx, tx, key, h, &m); e != nil {
		return e
	}
	return j.writeLocalStreamMeta(ctx, tx, key, m)
}
func (j *Journal) recordLocalInvocationEventTx(ctx context.Context, tx *sql.Tx, key []byte, source NativeTurnSource, event session.SessionEvent) error {
	if !j.isLocal() || source.InputKind != "local-native" {
		return nil
	}
	switch event.Type {
	case session.EventTurnStarted, session.EventTurnCompleted, session.EventTurnFailed:
	default:
		return nil
	}
	h, e := j.readLocalStreamHead(ctx, tx, key, source.Sequence)
	if e != nil {
		return e
	}
	if !sameLocalJSON(h.Source.Turn, source) {
		return ErrConflict
	}
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	if e = j.appendLocalStreamEventTx(ctx, tx, key, &h, &m, event); e != nil {
		return e
	}
	if e = j.writeLocalStreamHead(ctx, tx, key, h, &m); e != nil {
		return e
	}
	return j.writeLocalStreamMeta(ctx, tx, key, m)
}

// ErrLocalInvocationNotReady means exact FULL-admitted work has not yet bound
// a native stream. It grants neither native identity nor acceptance evidence.
var ErrLocalInvocationNotReady = errors.New("local invocation native stream is not ready")

func (j *Journal) localStreamAbsentHead(ctx context.Context, tx *sql.Tx, sequence int64) error {
	source, e := j.localIntentSource(ctx, tx, sequence)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrRetired
	}
	if e != nil {
		return e
	}
	if validateLocalReservation(j.authority, *source) != nil || source.Kind != "prompt" || source.Commitment.Sequence != sequence {
		return ErrConflict
	}
	var command, state string
	if e = tx.QueryRowContext(ctx, `SELECT command_id,state FROM worker_intent WHERE sequence=?`, sequence).Scan(&command, &state); errors.Is(e, sql.ErrNoRows) {
		return ErrRetired
	}
	if e != nil {
		return e
	}
	if command != source.Commitment.CommandID {
		return ErrConflict
	}
	var cancelled bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_local_cancellations WHERE sequence=? AND command_id=? AND admission_id=?)`, sequence, command, source.Admission.ID).Scan(&cancelled); e != nil {
		return e
	}
	if cancelled {
		return fabric.NewError(fabric.CodeCancelled, "Local invocation was cancelled before stream materialization")
	}
	if state == "admitted" {
		return ErrLocalInvocationNotReady
	}
	return fabric.NewError(fabric.CodeTargetUnavailable, "Local invocation has no native stream completion evidence")
}

// LocalStreamPage never grants authority: the private control composition must
// additionally fresh-authorize the original caller and current root per pull.
func (j *Journal) LocalStreamPage(ctx context.Context, key []byte, lease, sequence, afterCursor int64, limit int) (out LocalInvocationPage, err error) {
	if ctx == nil || !j.isLocal() || sequence <= 0 || afterCursor < -1 || limit < 1 || limit > 4 {
		return out, ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	token := j.localReadiness.snapshot()
	defer func() {
		if err == nil || errors.Is(err, ErrLocalInvocationNotReady) {
			out.Readiness = token
		}
	}()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if _, _, e = checkLease(ctx, tx, lease); e != nil {
		return out, e
	}
	if _, e = j.readLocalStreamMeta(ctx, tx, key); e != nil {
		return out, e
	}
	h, e := j.readLocalStreamHead(ctx, tx, key, sequence)
	if errors.Is(e, sql.ErrNoRows) {
		return out, j.localStreamAbsentHead(ctx, tx, sequence)
	}
	if e != nil {
		return out, e
	}
	if afterCursor < h.Floor {
		return out, ErrRetired
	}
	if afterCursor >= h.Next && afterCursor != -1 {
		return out, ErrConflict
	}
	out.Source = h.Source
	out.Floor = h.Floor
	out.Terminal = h.Terminal
	previous := ""
	if afterCursor == h.Floor {
		previous = h.FloorDigest
	} else {
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT CASE WHEN length(ciphertext)<=? THEN ciphertext END FROM worker_local_stream_frames WHERE sequence=? AND cursor=?`, localStreamCipherLimit, sequence, afterCursor).Scan(&raw); e != nil {
			return out, e
		}
		previous = localCipherDigest(raw)
	}
	cursor := afterCursor
	for len(out.Frames) < limit && cursor < h.Next-1 {
		var raw []byte
		var next int64
		e = tx.QueryRowContext(ctx, `SELECT cursor,CASE WHEN length(ciphertext)<=? THEN ciphertext END FROM worker_local_stream_frames WHERE sequence=? AND cursor>? ORDER BY cursor LIMIT 1`, localStreamCipherLimit, sequence, cursor).Scan(&next, &raw)
		if e != nil || next != cursor+1 {
			return LocalInvocationPage{}, ErrConflict
		}
		cipher := LocalInvocationCipherFrame{next, raw, localCipherDigest(raw)}
		plain, e := openLocalInvocationFrame(key, j.authority, j.dir, h.Source, cipher)
		if e != nil || plain.Previous != previous {
			return LocalInvocationPage{}, ErrConflict
		}
		previous = cipher.Digest
		cursor = next
		if cursor == h.Next-1 && (previous != h.HeadDigest || h.Terminal != (plain.Frame.Kind == fabric.FrameComplete || plain.Frame.Kind == fabric.FrameError)) {
			return LocalInvocationPage{}, ErrConflict
		}
		out.Frames = append(out.Frames, cipher)
	}
	return out, nil
}

// AckLocalStream deletes only the exact retained contiguous delivery prefix;
// the sealed floor and global begin watermark prohibit recreation or effects.
func (j *Journal) AckLocalStream(ctx context.Context, key []byte, lease, sequence, cursor int64, digest string) error {
	if ctx == nil || !j.isLocal() || cursor < 0 || len(digest) != 64 {
		return ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, _, e = checkLease(ctx, tx, lease); e != nil {
		return e
	}
	h, e := j.readLocalStreamHead(ctx, tx, key, sequence)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrRetired
	}
	if e != nil {
		return e
	}
	if cursor == h.Floor {
		if digest != h.FloorDigest {
			return ErrConflict
		}
		return nil
	}
	if cursor < h.Floor {
		return ErrRetired
	}
	if cursor-h.Floor > 4 {
		return ErrConflict
	}
	if cursor >= h.Next {
		return ErrConflict
	}
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	previous := h.FloorDigest
	var count int
	var bytes int64
	for ordinal := h.Floor + 1; ordinal <= cursor; ordinal++ {
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT CASE WHEN length(ciphertext)<=? THEN ciphertext END FROM worker_local_stream_frames WHERE sequence=? AND cursor=?`, localStreamCipherLimit, sequence, ordinal).Scan(&raw); e != nil {
			return ErrConflict
		}
		p, e := openLocalInvocationFrame(key, j.authority, j.dir, h.Source, LocalInvocationCipherFrame{ordinal, raw, localCipherDigest(raw)})
		if e != nil || p.Previous != previous {
			return ErrConflict
		}
		previous = localCipherDigest(raw)
		count++
		bytes += int64(len(raw))
	}
	if previous != digest || count > h.Frames || bytes > h.Bytes {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM worker_local_stream_frames WHERE sequence=? AND cursor<=?`, sequence, cursor); e != nil {
		return e
	}
	h.Floor = cursor
	h.FloorDigest = digest
	h.Frames -= count
	h.Bytes -= bytes
	m.Frames -= count
	m.Bytes -= bytes
	if e = j.writeLocalStreamHead(ctx, tx, key, h, &m); e != nil {
		return e
	}
	// Keep the authenticated terminal floor as a bounded tombstone until source
	// cleanup. The global monotonic begin watermark outlives its eventual removal.
	if e = j.writeLocalStreamMeta(ctx, tx, key, m); e != nil {
		return e
	}
	return tx.Commit()
}

// A genuine original endpoint EOF settles unfinished delivery with unknown
// effect, never success. The finite active-source set belongs to this worker.
func (j *Journal) recordLocalInvocationStoppedTx(ctx context.Context, tx *sql.Tx, key []byte, o NativeObservation) error {
	if !j.isLocal() || o.localInvocationEvent == nil || o.localInvocationEvent.Type != session.EventSessionStopped {
		return ErrFenced
	}
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	var sequence int64
	for count := 0; count < m.Config.MaxSources; count++ {
		var next int64
		e = tx.QueryRowContext(ctx, `SELECT sequence FROM worker_local_stream_heads WHERE sequence>? AND closed=0 ORDER BY sequence LIMIT 1`, sequence).Scan(&next)
		if errors.Is(e, sql.ErrNoRows) {
			break
		}
		if e != nil {
			return e
		}
		sequence = next
		h, e := j.readLocalStreamHead(ctx, tx, key, sequence)
		if e != nil {
			return e
		}
		if h.Terminal || h.Source.Turn.NativeGeneration != o.NativeGeneration {
			continue
		}
		if h.Source.Turn.NativeSessionID != o.localInvocationEvent.SessionID || !sameLocalJSON(h.Source.ActivationOrigin, o.Origin) {
			return ErrConflict
		}
		if h.Next == 0 {
			if e = j.appendLocalStreamFrameTx(ctx, tx, key, &h, &m, fabric.InvocationFrame{Kind: fabric.FrameStart}); e != nil {
				return e
			}
		}
		code := fabric.ErrorCode("native.stopped")
		var cancellation bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_local_cancellations WHERE sequence=? AND command_id=? AND admission_id=?)`, h.Source.Turn.Sequence, h.Source.Turn.SourceCommandID, h.Source.Turn.SourceAdmissionID).Scan(&cancellation); e != nil {
			return e
		}
		if cancellation {
			code = fabric.CodeCancelled
		}
		failure := fabric.NewError(code, "Native endpoint stopped before genuine turn completion")
		failure.Effect = fabric.EffectUnknown
		if e = j.appendLocalStreamFrameTx(ctx, tx, key, &h, &m, fabric.InvocationFrame{Kind: fabric.FrameError, Error: failure}); e != nil {
			return e
		}
		if e = j.writeLocalStreamHead(ctx, tx, key, h, &m); e != nil {
			return e
		}
	}
	return j.writeLocalStreamMeta(ctx, tx, key, m)
}
