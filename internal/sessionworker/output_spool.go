package sessionworker

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

var ErrNativeOutputLimit = errors.New("accepted native output exceeds reserved stream bound")

// The tail is original private captured input to a source projection, not a
// mutable backend observation. Sealing copies complete immutable evidence and
// advances/deletes this tail in the SAME FULL transaction as that projection.
type nativeOutputReady struct {
	Observation NativeObservation        `json:"observation"`
	Capture     []byte                   `json:"capture"`
	Transfers   []nativecontent.Transfer `json:"transfers"`
	Remaining   []byte                   `json:"remaining"`
}

type nativeOutputSpool struct {
	Ready             *nativeOutputReady `json:"ready,omitempty"`
	Source            NativeTurnSource
	Origin            json.RawMessage
	StreamID          string
	BatchID           string
	Text              string
	NativeBytes       int
	DeltaCount        int64
	RollingDigest     string
	ByteOffset        int64
	FirstObservedAt   time.Time
	LastObservedAt    time.Time
	Key               []byte
	KeyAvailable      bool
	LastDeltaID       string
	LastDeltaDigest   string
	LastCaptureCount  int
	PendingDeltas     int64
	PendingBytes      int
	PendingBaseDigest string
}

func (j *Journal) initializeOutputSpools() error {
	if _, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_resource_interruptions(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,payload BLOB NOT NULL)`); err != nil {
		return err
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_output_spools(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,ciphertext BLOB NOT NULL,size INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_output_deltas(sequence INTEGER NOT NULL,ordinal INTEGER NOT NULL,ciphertext BLOB NOT NULL,PRIMARY KEY(sequence,ordinal)) WITHOUT ROWID`,
		`CREATE TRIGGER IF NOT EXISTS worker_output_delta_cleanup AFTER DELETE ON worker_output_spools BEGIN DELETE FROM worker_output_deltas WHERE sequence=OLD.sequence; END`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
func outputSpoolAAD(scope Scope, directory, generation string, sequence int64) []byte {
	return outputSpoolAADBound(scope, directory, generation, sequence)
}
func outputSpoolAADBound(scope any, directory, generation string, sequence int64) []byte {
	domain := NativeOutputStreamCaptureFormat
	if local, ok := scope.(AuthorityScope); ok && local.Kind() == nativeauthority.Local {
		domain = "pagnet-worker-private-local-output-head-v1"
	}
	raw, _ := canonicalNativeJSON(struct {
		Domain                string
		Scope                 any
		Directory, Generation string
		Sequence              int64
	}{domain, scope, directory, generation, sequence})
	return raw
}

// Compression scratch belongs to one private journal, never to a global pool.
// Reset starts an independent gzip stream for every authenticated capture.
// Reusing its bounded workspace avoids rebuilding megabytes of match-finding
// state for each small native delta while preserving FULL per-delta commits.
type nativeOutputEncoder struct {
	mu     sync.Mutex
	writer *gzip.Writer
	buffer bytes.Buffer
	closed bool
}

func (c *nativeOutputEncoder) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	clear(c.buffer.Bytes())
	c.buffer = bytes.Buffer{}
	c.writer = nil
}

func sealOutputSpool(key []byte, scope Scope, directory string, s nativeOutputSpool) ([]byte, error) {
	return sealOutputSpoolBound(key, scope, directory, s)
}
func sealOutputSpoolBound(key []byte, scope any, directory string, s nativeOutputSpool) ([]byte, error) {
	var encoder nativeOutputEncoder
	defer encoder.close()
	return encoder.sealBound(key, scope, directory, s)
}

func (c *nativeOutputEncoder) seal(key []byte, scope Scope, directory string, s nativeOutputSpool) ([]byte, error) {
	return c.sealBound(key, scope, directory, s)
}
func (c *nativeOutputEncoder) sealBound(key []byte, scope any, directory string, s nativeOutputSpool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrFenced
	}
	raw, err := canonicalNativeJSON(s)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	c.buffer.Reset()
	defer func() {
		clear(c.buffer.Bytes())
		// A prepared projection can be larger than the normal stream tail.
		// Do not retain that peak allocation for an otherwise idle journal.
		if c.buffer.Cap() > 4*nativeOutputBatchBytes {
			c.buffer = bytes.Buffer{}
		}
	}()
	if c.writer == nil {
		c.writer, err = gzip.NewWriterLevel(&c.buffer, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
	} else {
		c.writer.Reset(&c.buffer)
	}
	if _, err = c.writer.Write(raw); err != nil {
		return nil, err
	}
	if err = c.writer.Close(); err != nil {
		return nil, err
	}
	aead, err := captureAEADBound(key, scope, directory)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, c.buffer.Bytes(), outputSpoolAADBound(scope, directory, s.Source.NativeGeneration, s.Source.Sequence)), nil
}
func openOutputSpool(key []byte, scope Scope, directory, generation string, sequence int64, ciphertext []byte) (nativeOutputSpool, error) {
	return openOutputSpoolBound(key, scope, directory, generation, sequence, ciphertext)
}
func openOutputSpoolBound(key []byte, scope any, directory, generation string, sequence int64, ciphertext []byte) (nativeOutputSpool, error) {
	var result nativeOutputSpool
	aead, err := captureAEADBound(key, scope, directory)
	if err != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return result, ErrConflict
	}
	raw, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], outputSpoolAADBound(scope, directory, generation, sequence))
	if err != nil {
		return result, ErrConflict
	}
	defer clear(raw)
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return result, ErrConflict
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, 7*transport.NativeContentMaxPlaintextBytes+1))
	_ = reader.Close()
	defer clear(decoded)
	if err != nil || len(decoded) > 7*transport.NativeContentMaxPlaintextBytes || json.Unmarshal(decoded, &result) != nil || result.Source.Sequence != sequence || result.Source.NativeGeneration != generation || result.NativeBytes < 0 || result.NativeBytes > transport.NativeContentMaxPlaintextBytes || len(result.Text) > result.NativeBytes || result.DeltaCount < 1 || result.LastCaptureCount < 0 || result.LastCaptureCount > session.NativeOutputBatchMaxEvents || len(result.RollingDigest) != 64 || (result.KeyAvailable && len(result.Key) != 32) {
		clear(result.Key)
		return nativeOutputSpool{}, ErrConflict
	}
	if result.ByteOffset < 0 || result.PendingDeltas < 0 || result.PendingDeltas > result.DeltaCount || result.PendingBytes < 0 || result.ByteOffset+int64(len(result.Text))+int64(result.PendingBytes) != int64(result.NativeBytes) || (result.PendingDeltas == 0 && (result.PendingBytes != 0 || result.PendingBaseDigest != "")) {
		clear(result.Key)
		return nativeOutputSpool{}, ErrConflict
	}
	return result, nil
}

// Serialized with projection flush by owner.outputMu. A callback's stable ID
// pins ambiguous COMMIT recovery; no subsequent callback can displace it first.
func (j *Journal) appendOutputDelta(ctx context.Context, p *nativeSourceProducer, key []byte, source NativeTurnSource, event session.SessionEvent, deltaID string, originalKey [32]byte, available bool) (nativeOutputSpool, error) {
	result, _, err := j.appendOutputDeltas(ctx, p, key, source, []session.SessionEvent{event}, deltaID, originalKey, available)
	return result, err
}

// Distinct original frame ordinals/ciphertexts/hashes share one FULL commit.
func (j *Journal) appendOutputDeltas(ctx context.Context, p *nativeSourceProducer, key []byte, source NativeTurnSource, events []session.SessionEvent, deltaID string, originalKey [32]byte, available bool) (nativeOutputSpool, int, error) {
	var result nativeOutputSpool
	if len(events) == 0 || len(events) > session.NativeOutputBatchMaxEvents {
		return result, 0, ErrConflict
	}
	raws := make([][]byte, len(events))
	defer func() {
		for _, raw := range raws {
			clear(raw)
		}
	}()
	commitDigest := sha256.New()
	batchBytes := 0
	for i, event := range events {
		if event.Type != session.EventTurnOutput || !event.NativeOutput || event.SessionID != source.NativeSessionID || event.TurnID != source.LogicalTurnID {
			return result, 0, ErrConflict
		}
		var err error
		raws[i], err = canonicalNativeJSON(event)
		if err != nil {
			return result, 0, err
		}
		batchBytes += len(raws[i])
		if len(events) > 1 && batchBytes > session.NativeOutputBatchMaxBytes {
			return result, 0, ErrConflict
		}
		commitDigest.Write(raws[i])
	}
	deltaDigest := hex.EncodeToString(commitDigest.Sum(nil))
	j.mu.Lock()
	defer j.mu.Unlock()
	if p == nil || p.closed || !j.sourceProducers[p] || p.generation != source.NativeGeneration {
		return result, 0, ErrFenced
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return result, 0, err
	}
	defer tx.Rollback()
	var previous []byte
	var previousSize int
	lookup := tx.StmtContext(ctx, j.outputSpoolLookup)
	defer lookup.Close()
	err = lookup.QueryRowContext(ctx, source.Sequence, source.NativeGeneration).Scan(&previous, &previousSize)
	if err == sql.ErrNoRows {
		result = nativeOutputSpool{Source: source, Origin: append(json.RawMessage(nil), p.origin...), StreamID: uuid.NewString(), BatchID: uuid.NewString(), FirstObservedAt: nativeSourceTime(time.Now()), KeyAvailable: available}
		if available {
			result.Key = append([]byte(nil), originalKey[:]...)
		}
	} else if err != nil {
		return result, 0, err
	} else {
		result, err = openOutputSpoolBound(key, j.privateCaptureAuthority(), j.dir, source.NativeGeneration, source.Sequence, previous)
		if err != nil {
			return result, 0, err
		}
		original, _ := json.Marshal(result.Source)
		current, _ := json.Marshal(source)
		if !bytes.Equal(original, current) || !bytes.Equal(result.Origin, p.origin) {
			clear(result.Key)
			return nativeOutputSpool{}, 0, ErrConflict
		}
		if result.Ready != nil && result.LastDeltaID != deltaID {
			return nativeOutputSpool{}, 0, ErrConflict
		}
		if result.LastDeltaID == deltaID {
			if result.LastDeltaDigest != deltaDigest || result.LastCaptureCount < 1 || result.LastCaptureCount > len(events) {
				clear(result.Key)
				return nativeOutputSpool{}, 0, ErrConflict
			}
			if err = j.assembleOutputDeltas(ctx, tx, key, &result, previousSize, len(previous)); err != nil {
				clear(result.Key)
				return nativeOutputSpool{}, 0, err
			}
			j.pulseLocalReady()
			return result, result.LastCaptureCount, nil
		}
	}
	appendDelta := tx.StmtContext(ctx, j.outputDeltaAppend)
	defer appendDelta.Close()
	consumed, deltaBytes := 0, 0
	firstInvocationDelta := result.DeltaCount + 1
	var invocationDeltas [][]byte
	for i, event := range events {
		if len(event.Output) > transport.NativeContentMaxPlaintextBytes-result.NativeBytes {
			if consumed == 0 {
				clear(result.Key)
				return nativeOutputSpool{}, 0, ErrNativeOutputLimit
			}
			break
		}
		raw := raws[i]
		oldDigest, _ := hex.DecodeString(result.RollingDigest)
		if result.PendingDeltas == 0 {
			result.PendingBaseDigest = result.RollingDigest
		}
		chain := sha256.New()
		chain.Write(oldDigest)
		chain.Write(raw)
		result.RollingDigest = hex.EncodeToString(chain.Sum(nil))
		result.DeltaCount++
		result.NativeBytes += len(event.Output)
		if result.Text == "" && result.PendingBytes == 0 {
			result.FirstObservedAt = nativeSourceTime(time.Now())
		}
		result.LastObservedAt = nativeSourceTime(time.Now())
		result.PendingDeltas++
		result.PendingBytes += len(event.Output)
		delta, err := sealOutputDeltaBound(key, j.privateCaptureAuthority(), j.dir, source, result.DeltaCount, raw)
		if err != nil {
			clear(result.Key)
			return nativeOutputSpool{}, 0, err
		}
		if _, err = appendDelta.ExecContext(ctx, source.Sequence, result.DeltaCount, delta); err != nil {
			clear(result.Key)
			return nativeOutputSpool{}, 0, err
		}
		if source.SourceInvocation != nil {
			invocationDeltas = append(invocationDeltas, delta)
		}
		deltaBytes += len(delta)
		consumed++
		// Preserve existing projection and resource-prefix boundaries.
		if int64(result.NativeBytes)-result.ByteOffset >= nativeOutputBatchBytes {
			break
		}
	}
	if err := j.captureLocalInvocationDeltasTx(ctx, tx, key, source, int64(firstInvocationDelta), events[:consumed]); err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	if err := j.captureInvocationDeltasTx(ctx, tx, key, result, firstInvocationDelta, invocationDeltas); err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	result.LastDeltaID, result.LastDeltaDigest, result.LastCaptureCount = deltaID, deltaDigest, consumed
	sealed, err := j.outputEncoder.sealBound(key, j.privateCaptureAuthority(), j.dir, result)
	if err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	growth := len(sealed) - len(previous) + deltaBytes
	reserve := tx.StmtContext(ctx, j.outputSpoolReserve)
	defer reserve.Close()
	changed, err := reserve.ExecContext(ctx, growth, source.Sequence, growth, terminalCaptureReserveBytes/2)
	if err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	n, _ := changed.RowsAffected()
	if n != 1 {
		clear(result.Key)
		return nativeOutputSpool{}, 0, ErrNativeOutputLimit
	}
	appendStatement := tx.StmtContext(ctx, j.outputSpoolAppend)
	defer appendStatement.Close()
	if _, err = appendStatement.ExecContext(ctx, source.Sequence, source.NativeGeneration, sealed, previousSize+growth); err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	err = tx.Commit()
	if err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, 0, err
	}
	j.pulseLocalReady()
	return result, consumed, nil
}

// Private projection capability: validated against an existing original FULL
// captured tail, never available through a controller request or native reader.
type outputSpoolProjection struct {
	Ready          *nativeOutputReady
	Sequence       int64
	Generation     string
	PreviousDigest string
	Remaining      []byte
	Close          bool
}

func (j *Journal) projectOutputSpoolTx(ctx context.Context, tx *sql.Tx, p *outputSpoolProjection) error {
	var previous []byte
	var previousSize int
	if err := tx.QueryRowContext(ctx, `SELECT ciphertext,size FROM worker_output_spools WHERE sequence=? AND native_generation=?`, p.Sequence, p.Generation).Scan(&previous, &previousSize); err != nil {
		return err
	}
	sum := sha256.Sum256(previous)
	if hex.EncodeToString(sum[:]) != p.PreviousDigest {
		return ErrConflict
	}
	if p.Close {
		if _, err := tx.ExecContext(ctx, `DELETE FROM worker_output_spools WHERE sequence=?`, p.Sequence); err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE worker_output_spools SET ciphertext=?,size=? WHERE sequence=?`, p.Remaining, len(p.Remaining), p.Sequence); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM worker_output_deltas WHERE sequence=?`, p.Sequence); err != nil {
		return err
	}
	// Replace the private tail with its complete immutable observation/capture
	// and exact native ciphertext, in this transaction. No backend ACK invented.
	_, err := tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET capture_left=capture_left+? WHERE sequence=?`, previousSize-len(p.Remaining), p.Sequence)
	return err
}
func (j *Journal) readOutputSpool(ctx context.Context, key []byte, generation string, sequence int64) (nativeOutputSpool, []byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var encrypted []byte
	var size int
	if err := j.db.QueryRowContext(ctx, `SELECT ciphertext,size FROM worker_output_spools WHERE sequence=? AND native_generation=?`, sequence, generation).Scan(&encrypted, &size); err != nil {
		return nativeOutputSpool{}, nil, err
	}
	data, err := openOutputSpoolBound(key, j.privateCaptureAuthority(), j.dir, generation, sequence, encrypted)
	if err == nil {
		err = j.assembleOutputDeltas(ctx, j.db, key, &data, size, len(encrypted))
	}
	if err != nil {
		clear(data.Key)
	}
	return data, encrypted, err
}
func (j *Journal) outputSpoolSequences(ctx context.Context, generation string) ([]int64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rows, err := j.db.QueryContext(ctx, `SELECT sequence FROM worker_output_spools WHERE native_generation=? ORDER BY sequence`, generation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []int64
	for rows.Next() {
		var sequence int64
		if err := rows.Scan(&sequence); err != nil {
			return nil, err
		}
		result = append(result, sequence)
	}
	return result, rows.Err()
}

type nativeOutputProjectionObserver func(session.SessionEvent, *NativeOutputStreamProof, *outputSpoolProjection) error

func (o *SessionOwner) observeOutputDelta(p *nativeSourceProducer, source NativeTurnSource, event session.SessionEvent, observe nativeOutputProjectionObserver) error {
	if event.Output == "" {
		return nil
	}
	return o.observeOutputDeltas(p, source, []session.SessionEvent{event}, observe)
}

func (o *SessionOwner) observeOutputDeltas(p *nativeSourceProducer, source NativeTurnSource, events []session.SessionEvent, observe nativeOutputProjectionObserver) error {
	originalKey, available := o.originalTaskContentPin(&source)
	defer clear(originalKey[:])
	for len(events) > 0 {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 3*time.Second)
		deltaID := uuid.NewString()
		var data nativeOutputSpool
		var consumed int
		var err error
		for {
			data, consumed, err = o.journal.appendOutputDeltas(ctx, p, o.captureKey, source, events, deltaID, originalKey, available)
			if err == nil || errors.Is(err, ErrNativeOutputLimit) || errors.Is(err, ErrFenced) || errors.Is(err, ErrConflict) {
				break
			}
			select {
			case <-ctx.Done():
				cancel()
				return err
			case <-time.After(50 * time.Millisecond):
			}
		}
		cancel()
		if errors.Is(err, ErrNativeOutputLimit) && len(events) > 1 {
			// The rejected transaction accepted no frame. Recover the exact
			// admissible prefix individually before reporting exhausted capacity.
			for _, event := range events {
				if err := o.observeOutputDelta(p, source, event, observe); err != nil {
					return err
				}
			}
			return nil
		}
		if err != nil {
			clear(data.Key)
			return err
		}
		needsProjection := data.Ready != nil || int64(data.NativeBytes)-data.ByteOffset >= nativeOutputBatchBytes
		clear(data.Key)
		if consumed < 1 || consumed > len(events) {
			return ErrConflict
		}
		if needsProjection {
			if err := o.flushNativeOutput(source.NativeGeneration, source.Sequence, false, observe); err != nil {
				return err
			}
		}
		events = events[consumed:]
	}
	return nil
}
func (o *SessionOwner) flushNativeOutputGeneration(generation string, observe nativeOutputProjectionObserver) error {
	sequences, err := o.journal.outputSpoolSequences(context.WithoutCancel(o.ctx), generation)
	if err != nil {
		return err
	}
	for _, sequence := range sequences {
		if err := o.flushNativeOutput(generation, sequence, true, observe); err != nil {
			return err
		}
	}
	return nil
}
func (o *SessionOwner) flushNativeOutput(generation string, sequence int64, force bool, observe nativeOutputProjectionObserver) error {
	for {
		data, encrypted, err := o.journal.readOutputSpool(context.WithoutCancel(o.ctx), o.captureKey, generation, sequence)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if data.Ready != nil {
			sum := sha256.Sum256(encrypted)
			projection := &outputSpoolProjection{Sequence: sequence, Generation: generation, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: data.Ready.Remaining, Ready: data.Ready}
			clear(data.Key)
			if err = observe(data.Ready.Observation.Event, data.Ready.Observation.OutputStream, projection); err != nil {
				return err
			}
			continue
		}
		if len(data.Text) == 0 || (!force && len(data.Text) < nativeOutputBatchBytes) {
			clear(data.Key)
			return nil
		}
		count := min(len(data.Text), nativeOutputBatchBytes)
		// JSON-native text is UTF-8; never split a rune between immutable batches.
		for count < len(data.Text) && count > 0 && data.Text[count]&0xc0 == 0x80 {
			count--
		}
		if count == 0 {
			clear(data.Key)
			return ErrConflict
		}
		proof := &NativeOutputStreamProof{Format: NativeOutputStreamCaptureFormat, StreamID: data.StreamID, BatchID: data.BatchID, DeltaCount: data.DeltaCount, RollingDigest: data.RollingDigest, ByteOffset: data.ByteOffset, ByteLength: count, FirstObservedAt: data.FirstObservedAt, LastObservedAt: data.LastObservedAt}
		event := session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: data.Source.LogicalTurnID, SessionID: data.Source.NativeSessionID, Output: data.Text[:count]}
		data.Text = data.Text[count:]
		data.PendingDeltas, data.PendingBytes, data.PendingBaseDigest = 0, 0, ""
		data.ByteOffset += int64(count)
		data.BatchID = uuid.NewString()
		remaining, err := o.journal.outputEncoder.sealBound(o.captureKey, o.journal.privateCaptureAuthority(), o.journal.dir, data)
		if err != nil {
			clear(data.Key)
			return err
		}
		sum := sha256.Sum256(encrypted)
		projection := &outputSpoolProjection{Sequence: sequence, Generation: generation, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: remaining}
		// The original wrapped accepted key restores only output capture capability,
		// never an input admission or a current-epoch read capability.
		if sourceContentDescriptor(&data.Source) != "" && data.KeyAvailable {
			var key [32]byte
			copy(key[:], data.Key)
			o.mu.Lock()
			if o.taskContentPins == nil {
				o.taskContentPins = map[string]nativeTaskContentPin{}
			}
			id := taskPinID(data.Source)
			pin, found := o.taskContentPins[id]
			if found && (!pin.available || pin.descriptor != sourceContentDescriptor(&data.Source) || !bytes.Equal(pin.key[:], key[:])) {
				o.mu.Unlock()
				clear(key[:])
				clear(data.Key)
				return ErrConflict
			}
			if !found {
				o.taskContentPins[id] = nativeTaskContentPin{descriptor: sourceContentDescriptor(&data.Source), key: key, available: true}
			}
			o.mu.Unlock()
			clear(key[:])
		}
		clear(data.Key)
		if err = observe(event, proof, projection); err != nil {
			return err
		}
	}
}

func (o *SessionOwner) recoverCapturedNativeOutput() error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 30*time.Second)
	defer cancel()
	o.journal.mu.Lock()
	rows, err := o.journal.db.QueryContext(ctx, `SELECT sequence,native_generation FROM worker_output_spools ORDER BY sequence LIMIT 4096`)
	if err != nil {
		o.journal.mu.Unlock()
		return err
	}
	type pending struct {
		sequence   int64
		generation string
	}
	var entries []pending
	for rows.Next() {
		var entry pending
		if err = rows.Scan(&entry.sequence, &entry.generation); err != nil {
			break
		}
		entries = append(entries, entry)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	o.journal.mu.Unlock()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		data, _, err := o.journal.readOutputSpool(ctx, o.captureKey, entry.generation, entry.sequence)
		if err != nil {
			return err
		}
		origin := append(json.RawMessage(nil), data.Origin...)
		clear(data.Key)
		_, project, _ := o.nativeCapturedSourceObservers(o.journal.instanceID(), nil, entry.generation, origin)
		if err = o.flushNativeOutput(entry.generation, entry.sequence, true, project); err != nil {
			return err
		}
	}
	return nil
}

// Pin completed original encryption before the observation transaction. A
// failed/unknown projection COMMIT can then retry exact ciphertext after reopen.
func (j *Journal) prepareOutputReady(ctx context.Context, key []byte, p *outputSpoolProjection, ready *nativeOutputReady) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous []byte
	var previousSize int
	if err = tx.QueryRowContext(ctx, `SELECT ciphertext,size FROM worker_output_spools WHERE sequence=? AND native_generation=?`, p.Sequence, p.Generation).Scan(&previous, &previousSize); err != nil {
		return err
	}
	sum := sha256.Sum256(previous)
	if hex.EncodeToString(sum[:]) != p.PreviousDigest {
		return ErrConflict
	}
	data, err := openOutputSpoolBound(key, j.privateCaptureAuthority(), j.dir, p.Generation, p.Sequence, previous)
	if err != nil {
		return err
	}
	defer clear(data.Key)
	if data.Ready != nil {
		return ErrConflict
	}
	data.Ready = ready
	encrypted, err := j.outputEncoder.sealBound(key, j.privateCaptureAuthority(), j.dir, data)
	if err != nil {
		return err
	}
	growth := len(encrypted) - len(previous)
	reserve, err := tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET capture_left=capture_left-? WHERE sequence=? AND observation_id='' AND capture_left>=?`, growth, p.Sequence, growth)
	if err != nil {
		return err
	}
	count, _ := reserve.RowsAffected()
	if count != 1 {
		return ErrNativeCaptureLimit
	}
	if _, err = tx.ExecContext(ctx, `UPDATE worker_output_spools SET ciphertext=?,size=? WHERE sequence=?`, encrypted, previousSize+growth, p.Sequence); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	sum = sha256.Sum256(encrypted)
	p.PreviousDigest = hex.EncodeToString(sum[:])
	p.Ready = ready
	return nil
}
func (o *SessionOwner) commitReadyNativeOutput(ctx context.Context, producer *nativeSourceProducer, p *outputSpoolProjection) error {
	ready := p.Ready
	if ready == nil {
		return ErrConflict
	}
	observation := ready.Observation
	observation.outputProjection = p
	if err := o.journal.pinSourceRetry(observation.ID, observation.SourceDigest); err != nil {
		return err
	}
	defer o.journal.releaseSourceRetry(observation.ID, observation.SourceDigest)
	for {
		err := o.journal.journalCapturedObservation(ctx, producer, observation, ready.Capture, ready.Transfers...)
		if err == nil {
			o.record("session", observation.Event, observation.NativeGeneration, observation.Origin)
			return nil
		}
		if nativeSourceResourceLimit(err) || errors.Is(err, ErrConflict) || errors.Is(err, ErrFenced) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(50 * time.Millisecond):
		}
	}
}
