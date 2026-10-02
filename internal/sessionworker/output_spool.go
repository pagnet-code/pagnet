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
	Ready           *nativeOutputReady `json:"ready,omitempty"`
	Source          NativeTurnSource
	Origin          json.RawMessage
	StreamID        string
	BatchID         string
	Text            string
	NativeBytes     int
	DeltaCount      int64
	RollingDigest   string
	ByteOffset      int64
	FirstObservedAt time.Time
	LastObservedAt  time.Time
	Key             []byte
	KeyAvailable    bool
	LastDeltaID     string
	LastDeltaDigest string
}

func (j *Journal) initializeOutputSpools() error {
	if _, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_resource_interruptions(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,payload BLOB NOT NULL)`); err != nil {
		return err
	}
	_, err := j.db.Exec(`CREATE TABLE IF NOT EXISTS worker_output_spools(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,ciphertext BLOB NOT NULL,size INTEGER NOT NULL)`)
	return err
}
func outputSpoolAAD(scope Scope, directory, generation string, sequence int64) []byte {
	raw, _ := canonicalNativeJSON(struct {
		Domain                string
		Scope                 Scope
		Directory, Generation string
		Sequence              int64
	}{NativeOutputStreamCaptureFormat, scope, directory, generation, sequence})
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
	var encoder nativeOutputEncoder
	defer encoder.close()
	return encoder.seal(key, scope, directory, s)
}

func (c *nativeOutputEncoder) seal(key []byte, scope Scope, directory string, s nativeOutputSpool) ([]byte, error) {
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
	aead, err := captureAEAD(key, scope, directory)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, c.buffer.Bytes(), outputSpoolAAD(scope, directory, s.Source.NativeGeneration, s.Source.Sequence)), nil
}
func openOutputSpool(key []byte, scope Scope, directory, generation string, sequence int64, ciphertext []byte) (nativeOutputSpool, error) {
	var result nativeOutputSpool
	aead, err := captureAEAD(key, scope, directory)
	if err != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return result, ErrConflict
	}
	raw, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], outputSpoolAAD(scope, directory, generation, sequence))
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
	if err != nil || len(decoded) > 7*transport.NativeContentMaxPlaintextBytes || json.Unmarshal(decoded, &result) != nil || result.Source.Sequence != sequence || result.Source.NativeGeneration != generation || result.NativeBytes < 0 || result.NativeBytes > transport.NativeContentMaxPlaintextBytes || len(result.Text) > result.NativeBytes || result.DeltaCount < 1 || len(result.RollingDigest) != 64 || (result.KeyAvailable && len(result.Key) != 32) {
		clear(result.Key)
		return nativeOutputSpool{}, ErrConflict
	}
	return result, nil
}

// Serialized with projection flush by owner.outputMu. A callback's stable ID
// pins ambiguous COMMIT recovery; no subsequent callback can displace it first.
func (j *Journal) appendOutputDelta(ctx context.Context, p *nativeSourceProducer, key []byte, source NativeTurnSource, event session.SessionEvent, deltaID string, originalKey [32]byte, available bool) (nativeOutputSpool, error) {
	var result nativeOutputSpool
	raw, err := canonicalNativeJSON(event)
	if err != nil {
		return result, err
	}
	sum := sha256.Sum256(raw)
	deltaDigest := hex.EncodeToString(sum[:])
	defer clear(raw)
	j.mu.Lock()
	defer j.mu.Unlock()
	if p == nil || p.closed || !j.sourceProducers[p] || p.generation != source.NativeGeneration {
		return result, ErrFenced
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT ciphertext FROM worker_output_spools WHERE sequence=? AND native_generation=?`, source.Sequence, source.NativeGeneration).Scan(&previous)
	if err == sql.ErrNoRows {
		result = nativeOutputSpool{Source: source, Origin: append(json.RawMessage(nil), p.origin...), StreamID: uuid.NewString(), BatchID: uuid.NewString(), FirstObservedAt: nativeSourceTime(time.Now()), KeyAvailable: available}
		if available {
			result.Key = append([]byte(nil), originalKey[:]...)
		}
	} else if err != nil {
		return result, err
	} else {
		result, err = openOutputSpool(key, j.scope, j.dir, source.NativeGeneration, source.Sequence, previous)
		if err != nil {
			return result, err
		}
		original, _ := json.Marshal(result.Source)
		current, _ := json.Marshal(source)
		if !bytes.Equal(original, current) || !bytes.Equal(result.Origin, p.origin) {
			clear(result.Key)
			return nativeOutputSpool{}, ErrConflict
		}
		if result.Ready != nil && result.LastDeltaID != deltaID {
			return nativeOutputSpool{}, ErrConflict
		}
		if result.LastDeltaID == deltaID {
			if result.LastDeltaDigest != deltaDigest {
				clear(result.Key)
				return nativeOutputSpool{}, ErrConflict
			}
			return result, nil
		}
	}
	if len(event.Output) > transport.NativeContentMaxPlaintextBytes-result.NativeBytes {
		clear(result.Key)
		return nativeOutputSpool{}, ErrNativeOutputLimit
	}
	oldDigest, _ := hex.DecodeString(result.RollingDigest)
	chain := sha256.New()
	_, _ = chain.Write(oldDigest)
	_, _ = chain.Write(raw)
	result.RollingDigest = hex.EncodeToString(chain.Sum(nil))
	result.DeltaCount++
	result.NativeBytes += len(event.Output)
	if result.Text == "" {
		result.FirstObservedAt = nativeSourceTime(time.Now())
	}
	result.LastObservedAt = nativeSourceTime(time.Now())
	result.Text += event.Output
	result.LastDeltaID, result.LastDeltaDigest = deltaID, deltaDigest
	sealed, err := j.outputEncoder.seal(key, j.scope, j.dir, result)
	if err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, err
	}
	// Private tail storage consumes only original reserved prefix capacity.
	growth := len(sealed) - len(previous)
	changed, err := tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET capture_left=capture_left-? WHERE sequence=? AND observation_id='' AND capture_left-?>=?`, growth, source.Sequence, growth, terminalCaptureReserveBytes/2)
	if err != nil {
		return nativeOutputSpool{}, err
	}
	n, _ := changed.RowsAffected()
	if n != 1 {
		clear(result.Key)
		return nativeOutputSpool{}, ErrNativeOutputLimit
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO worker_output_spools(sequence,native_generation,ciphertext,size) VALUES(?,?,?,?) ON CONFLICT(sequence) DO UPDATE SET ciphertext=excluded.ciphertext,size=excluded.size`, source.Sequence, source.NativeGeneration, sealed, len(sealed)); err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, err
	}
	err = tx.Commit()
	if err != nil {
		clear(result.Key)
		return nativeOutputSpool{}, err
	}
	return result, nil
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
	if err := tx.QueryRowContext(ctx, `SELECT ciphertext FROM worker_output_spools WHERE sequence=? AND native_generation=?`, p.Sequence, p.Generation).Scan(&previous); err != nil {
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
	// Replace the private tail with its complete immutable observation/capture
	// and exact native ciphertext, in this transaction. No backend ACK invented.
	_, err := tx.ExecContext(ctx, `UPDATE worker_terminal_reservations SET capture_left=capture_left+? WHERE sequence=?`, len(previous)-len(p.Remaining), p.Sequence)
	return err
}
func (j *Journal) readOutputSpool(ctx context.Context, key []byte, generation string, sequence int64) (nativeOutputSpool, []byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var encrypted []byte
	if err := j.db.QueryRowContext(ctx, `SELECT ciphertext FROM worker_output_spools WHERE sequence=? AND native_generation=?`, sequence, generation).Scan(&encrypted); err != nil {
		return nativeOutputSpool{}, nil, err
	}
	data, err := openOutputSpool(key, j.scope, j.dir, generation, sequence, encrypted)
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
	ctx, cancel := context.WithTimeout(context.WithoutCancel(o.ctx), 3*time.Second)
	defer cancel()
	originalKey, available := o.originalTaskContentPin(&source)
	defer clear(originalKey[:])
	deltaID := uuid.NewString()
	var err error
	var needsProjection bool
	for {
		var data nativeOutputSpool
		data, err = o.journal.appendOutputDelta(ctx, p, o.captureKey, source, event, deltaID, originalKey, available)
		needsProjection = data.Ready != nil || len(data.Text) >= nativeOutputBatchBytes
		clear(data.Key)
		if err == nil {
			break
		}
		if errors.Is(err, ErrNativeOutputLimit) || errors.Is(err, ErrFenced) || errors.Is(err, ErrConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(50 * time.Millisecond):
		}
	}
	// The committed append already authenticated this tail. Below the batch
	// threshold there is nothing to project; avoid loading and decrypting the
	// same growing ciphertext a second time for every small native delta.
	if !needsProjection {
		return nil
	}
	return o.flushNativeOutput(source.NativeGeneration, source.Sequence, false, observe)
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
		data.ByteOffset += int64(count)
		data.BatchID = uuid.NewString()
		remaining, err := o.journal.outputEncoder.seal(o.captureKey, o.journal.scope, o.journal.dir, data)
		if err != nil {
			clear(data.Key)
			return err
		}
		sum := sha256.Sum256(encrypted)
		projection := &outputSpoolProjection{Sequence: sequence, Generation: generation, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: remaining}
		// The original wrapped accepted key restores only output capture capability,
		// never an input admission or a current-epoch read capability.
		if data.Source.SourceTask != nil && data.KeyAvailable {
			var key [32]byte
			copy(key[:], data.Key)
			o.mu.Lock()
			if o.taskContentPins == nil {
				o.taskContentPins = map[string]nativeTaskContentPin{}
			}
			id := taskPinID(data.Source)
			pin, found := o.taskContentPins[id]
			if found && (!pin.available || pin.descriptor != taskSourceJSON(data.Source.SourceTask) || !bytes.Equal(pin.key[:], key[:])) {
				o.mu.Unlock()
				clear(key[:])
				clear(data.Key)
				return ErrConflict
			}
			if !found {
				o.taskContentPins[id] = nativeTaskContentPin{descriptor: taskSourceJSON(data.Source.SourceTask), key: key, available: true}
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
		_, project := o.nativeCapturedSourceObservers(o.journal.scope.InstanceID, nil, entry.generation, origin)
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
	if err = tx.QueryRowContext(ctx, `SELECT ciphertext FROM worker_output_spools WHERE sequence=? AND native_generation=?`, p.Sequence, p.Generation).Scan(&previous); err != nil {
		return err
	}
	sum := sha256.Sum256(previous)
	if hex.EncodeToString(sum[:]) != p.PreviousDigest {
		return ErrConflict
	}
	data, err := openOutputSpool(key, j.scope, j.dir, p.Generation, p.Sequence, previous)
	if err != nil {
		return err
	}
	defer clear(data.Key)
	if data.Ready != nil {
		return ErrConflict
	}
	data.Ready = ready
	encrypted, err := j.outputEncoder.seal(key, j.scope, j.dir, data)
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
	if _, err = tx.ExecContext(ctx, `UPDATE worker_output_spools SET ciphertext=?,size=? WHERE sequence=?`, encrypted, len(encrypted), p.Sequence); err != nil {
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
