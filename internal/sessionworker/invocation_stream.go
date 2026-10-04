package sessionworker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

const invocationStreamWindowBytes = 128 << 20
const invocationStreamWindowRows = 262144
const invocationStreamTTL = 5 * time.Second
const invocationStreamTick = 200 * time.Millisecond
const invocationStreamChunkBytes = 64 << 10

var ErrInvocationStreamExpired = errors.New("original invocation consumer expired or closed")

type InvocationStreamIdentity struct {
	Sequence          int64  `json:"sequence"`
	NativeGeneration  string `json:"nativeGeneration"`
	SourceCommandID   string `json:"sourceCommandId"`
	SourceAdmissionID string `json:"sourceAdmissionId"`
	InvocationID      string `json:"invocationId"`
}

func invocationIdentity(s NativeTurnSource) InvocationStreamIdentity {
	id := ""
	if s.SourceInvocation != nil {
		id = s.SourceInvocation.InvocationID
	}
	return InvocationStreamIdentity{s.Sequence, s.NativeGeneration, s.SourceCommandID, s.SourceAdmissionID, id}
}

type InvocationStreamRequest struct {
	Source            InvocationStreamIdentity `json:"source"`
	SubscriptionID    string                   `json:"subscriptionId,omitempty"`
	ProjectionOrdinal int64                    `json:"projectionOrdinal,omitempty"`
	Digest            string                   `json:"digest,omitempty"`
}

type InvocationStreamSubscription struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Projection is delivered only on authenticated private IPC. Its ciphertext's
// inner range binds the source and cursor; AAD is the original accepted epoch.
type InvocationStreamProjection struct {
	Ordinal    int64                   `json:"ordinal"`
	AAD        e2ee.AAD                `json:"aad"`
	Ciphertext e2ee.EncryptedPayloadV1 `json:"ciphertext"`
	Digest     string                  `json:"digest"`
}
type InvocationStreamRange struct {
	Source     NativeTurnSource        `json:"source"`
	Origin     json.RawMessage         `json:"origin"`
	Ordinal    int64                   `json:"ordinal"`
	ByteOffset int64                   `json:"byteOffset"`
	Data       []byte                  `json:"data,omitempty"`
	Proof      NativeOutputStreamProof `json:"proof"`
	// This is an actual committed native observation, never a timer-made event.
	Terminal      *NativeObservation `json:"terminal,omitempty"`
	DeliveryError string             `json:"deliveryError,omitempty"`
}

type invocationCursor struct {
	Ordinal int64
	InFrame int
	Bytes   int64
	Digest  string
}
type invocationStreamCheckpoint struct {
	Source                          NativeTurnSource
	Origin                          json.RawMessage
	Key                             []byte
	StreamID                        string
	Captured                        int64
	NativeBytes                     int64
	CapturedDigest                  string
	FirstCapturedAt, LastCapturedAt time.Time
	Cursor                          invocationCursor
	ProjectionOrdinal               int64
	Pending                         *InvocationStreamProjection
	PendingCursor                   invocationCursor
	PendingTerminal                 bool
	ClaimDeadline                   time.Time
	Terminal                        *NativeObservation
	AckOrdinal                      int64
	AckDigest                       string
	Closed                          bool
	UnavailableReason               string
	UnavailableAt                   time.Time
}

func (j *Journal) initializeInvocationStreams() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_invocation_stream_capacity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),bytes INTEGER NOT NULL,rows INTEGER NOT NULL)`,
		`INSERT OR IGNORE INTO worker_invocation_stream_capacity VALUES(1,0,0)`,
		`CREATE TABLE IF NOT EXISTS worker_invocation_streams(sequence INTEGER PRIMARY KEY,native_generation TEXT NOT NULL,checkpoint BLOB NOT NULL,closed INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS worker_invocation_stream_deltas(sequence INTEGER NOT NULL,ordinal INTEGER NOT NULL,ciphertext BLOB NOT NULL,PRIMARY KEY(sequence,ordinal)) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS worker_invocation_stream_subscriptions(sequence INTEGER PRIMARY KEY,lease INTEGER NOT NULL,id TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS worker_invocation_delta_release AFTER DELETE ON worker_invocation_stream_deltas BEGIN UPDATE worker_invocation_stream_capacity SET bytes=bytes-length(OLD.ciphertext),rows=rows-1 WHERE singleton=1; END`,
		`CREATE TRIGGER IF NOT EXISTS worker_invocation_source_fence BEFORE DELETE ON worker_turn_sources WHEN EXISTS(SELECT 1 FROM worker_invocation_streams WHERE sequence=OLD.sequence AND closed=0) BEGIN SELECT RAISE(ABORT,'original invocation stream remains retained'); END`,
		`CREATE TRIGGER IF NOT EXISTS worker_invocation_source_cleanup AFTER DELETE ON worker_turn_sources BEGIN DELETE FROM worker_invocation_stream_deltas WHERE sequence=OLD.sequence; DELETE FROM worker_invocation_stream_subscriptions WHERE sequence=OLD.sequence; DELETE FROM worker_invocation_streams WHERE sequence=OLD.sequence; END`,
	} {
		if _, err := j.db.Exec(q); err != nil {
			return err
		}
	}
	var size, rows, actualSize, actualRows, heads int64
	if err := j.db.QueryRow(`SELECT bytes,rows,(SELECT COALESCE(SUM(length(ciphertext)),0) FROM worker_invocation_stream_deltas),(SELECT COUNT(*) FROM worker_invocation_stream_deltas),(SELECT COUNT(*) FROM worker_invocation_streams) FROM worker_invocation_stream_capacity WHERE singleton=1`).Scan(&size, &rows, &actualSize, &actualRows, &heads); err != nil {
		return err
	}
	if size != actualSize || rows != actualRows || size < 0 || size > invocationStreamWindowBytes || rows < 0 || rows > invocationStreamWindowRows || heads > maxCommands {
		return ErrConflict
	}
	// No subscription authority survives a worker process restart. Retained
	// original ciphertext/checkpoints do survive and can be rebound by new lease.
	_, err := j.db.Exec(`UPDATE worker_invocation_stream_subscriptions SET lease=0`)
	return err
}
func invocationPrivateAAD(j *Journal, generation string, sequence int64) []byte {
	raw, _ := json.Marshal(struct {
		Domain                string
		Scope                 Scope
		Directory, Generation string
		Sequence              int64
	}{"pagnet-native-invocation-stream-checkpoint-v1", j.scope, j.dir, generation, sequence})
	return raw
}
func (j *Journal) sealInvocationCheckpoint(key []byte, h invocationStreamCheckpoint) ([]byte, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	aead, err := captureAEAD(key, j.scope, j.dir)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, raw, invocationPrivateAAD(j, h.Source.NativeGeneration, h.Source.Sequence)), nil
}
func (j *Journal) readInvocationCheckpoint(ctx context.Context, tx *sql.Tx, key []byte, id InvocationStreamIdentity) (invocationStreamCheckpoint, error) {
	var h invocationStreamCheckpoint
	var cipher []byte
	var generation string
	var closed bool
	if err := tx.QueryRowContext(ctx, `SELECT checkpoint,native_generation,closed FROM worker_invocation_streams WHERE sequence=?`, id.Sequence).Scan(&cipher, &generation, &closed); err != nil {
		return h, err
	}
	if generation != id.NativeGeneration || len(cipher) > maxFrame {
		return h, ErrConflict
	}
	aead, err := captureAEAD(key, j.scope, j.dir)
	if err != nil || len(cipher) < aead.NonceSize()+aead.Overhead() {
		return h, ErrConflict
	}
	raw, err := aead.Open(nil, cipher[:aead.NonceSize()], cipher[aead.NonceSize():], invocationPrivateAAD(j, generation, id.Sequence))
	if err != nil {
		return h, ErrConflict
	}
	defer clear(raw)
	if json.Unmarshal(raw, &h) != nil || invocationIdentity(h.Source) != id || h.Source.SourceInvocation == nil || h.Source.SourceTask != nil || h.Source.SourceInvocation.Validate() != nil || h.Source.InputKind != "invocation" || h.Source.LogicalTurnID != logicalWorkerTurn(id.Sequence) || len(h.Key) != 32 || h.Closed != closed || h.Captured < 0 || h.NativeBytes < 0 || h.NativeBytes > invocationStreamWindowBytes || h.Cursor.Ordinal < 1 || h.Cursor.Ordinal > h.Captured+1 || h.Cursor.InFrame < 0 || h.Cursor.Bytes < 0 || h.Cursor.Bytes > h.NativeBytes || (h.Closed && h.Pending != nil) {
		clear(h.Key)
		return invocationStreamCheckpoint{}, ErrConflict
	}
	stored, err := readNativeTurn(ctx, tx, h.Source.NativeGeneration, h.Source.LogicalTurnID)
	if err != nil || !reflect.DeepEqual(stored, h.Source) {
		clear(h.Key)
		return invocationStreamCheckpoint{}, ErrConflict
	}
	if h.ProjectionOrdinal < 0 || h.AckOrdinal < 0 || h.AckOrdinal > h.ProjectionOrdinal || h.ClaimDeadline.IsZero() || !validInvocationDeliveryReason(h.UnavailableReason) {
		clear(h.Key)
		return invocationStreamCheckpoint{}, ErrConflict
	}
	if h.Pending != nil && (h.Pending.Ordinal != h.ProjectionOrdinal || h.Pending.Digest != invocationProjectionDigest(*h.Pending) || h.PendingCursor.Bytes < h.Cursor.Bytes || h.PendingCursor.Bytes > h.NativeBytes || h.PendingCursor.Ordinal < h.Cursor.Ordinal || h.PendingCursor.Ordinal > h.Captured+1 || h.PendingCursor.InFrame < 0) {
		clear(h.Key)
		return invocationStreamCheckpoint{}, ErrConflict
	}
	return h, nil
}
func (j *Journal) writeInvocationCheckpoint(ctx context.Context, tx *sql.Tx, key []byte, h invocationStreamCheckpoint) error {
	cipher, err := j.sealInvocationCheckpoint(key, h)
	if err != nil {
		return err
	}
	if len(cipher) > maxFrame {
		return ErrFull
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_invocation_streams(sequence,native_generation,checkpoint,closed) VALUES(?,?,?,?) ON CONFLICT(sequence) DO UPDATE SET checkpoint=excluded.checkpoint,closed=excluded.closed`, h.Source.Sequence, h.Source.NativeGeneration, cipher, h.Closed)
	return err
}

// Called after exact BindNativeTurn and before the real native Submit effect.
func (j *Journal) beginInvocationStream(ctx context.Context, key []byte, source NativeTurnSource, origin json.RawMessage, originalKey [32]byte) error {
	if source.SourceInvocation == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stored, err := readNativeTurn(ctx, tx, source.NativeGeneration, source.LogicalTurnID)
	if err != nil || !reflect.DeepEqual(stored, source) {
		return ErrConflict
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, invocationIdentity(source))
	if err == nil {
		defer clear(h.Key)
		if !reflect.DeepEqual(h.Source, source) || !bytes.Equal(h.Key, originalKey[:]) || !bytes.Equal(h.Origin, origin) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	h = invocationStreamCheckpoint{Source: source, Origin: append(json.RawMessage(nil), origin...), Key: append([]byte(nil), originalKey[:]...), Cursor: invocationCursor{Ordinal: 1}, ClaimDeadline: time.Now().Add(30 * time.Second)}
	defer clear(h.Key)
	if err = j.writeInvocationCheckpoint(ctx, tx, key, h); err != nil {
		return err
	}
	return tx.Commit()
}

// Mirrors the ORIGINAL ciphertext ordinal in its existing FULL transaction.
// No observer returns accepted before both journals have committed that frame.
// Original encrypted frame rows are copied in their capture FULL transaction.
// Checkpoint encryption runs once per bounded native batch, not per frame.
func (j *Journal) captureInvocationDeltasTx(ctx context.Context, tx *sql.Tx, key []byte, s nativeOutputSpool, first int64, ciphers [][]byte) error {
	if s.Source.SourceInvocation == nil {
		return nil
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, invocationIdentity(s.Source))
	if err != nil {
		return err
	}
	defer clear(h.Key)
	if h.Closed || h.UnavailableReason != "" {
		return nil
	}
	if h.Captured+1 != first || !reflect.DeepEqual(h.Source, s.Source) || !bytes.Equal(h.Origin, s.Origin) || first+int64(len(ciphers))-1 != s.DeltaCount {
		return ErrConflict
	}
	total := 0
	for _, cipher := range ciphers {
		total += len(cipher)
	}
	changed, err := tx.ExecContext(ctx, `UPDATE worker_invocation_stream_capacity SET bytes=bytes+?,rows=rows+? WHERE singleton=1 AND bytes+?<=? AND rows+?<=?`, total, len(ciphers), total, invocationStreamWindowBytes, len(ciphers), invocationStreamWindowRows)
	if err != nil {
		return err
	}
	n, _ := changed.RowsAffected()
	if n != 1 {
		// Only auxiliary delivery ends. The original capture transaction still
		// commits every frame under its unchanged native limits.
		h.UnavailableReason = "delivery_window_exhausted"
		h.UnavailableAt = s.LastObservedAt
		if _, err = tx.ExecContext(ctx, `DELETE FROM worker_invocation_stream_deltas WHERE sequence=?`, s.Source.Sequence); err != nil {
			return err
		}
		return j.writeInvocationCheckpoint(ctx, tx, key, h)
	}
	for i, cipher := range ciphers {
		if _, err = tx.ExecContext(ctx, `INSERT INTO worker_invocation_stream_deltas VALUES(?,?,?)`, s.Source.Sequence, first+int64(i), cipher); err != nil {
			return err
		}
	}
	if h.StreamID != "" && h.StreamID != s.StreamID {
		return ErrConflict
	}
	h.StreamID = s.StreamID
	h.Captured = s.DeltaCount
	h.NativeBytes = int64(s.NativeBytes)
	h.CapturedDigest = s.RollingDigest
	if h.FirstCapturedAt.IsZero() {
		h.FirstCapturedAt = s.FirstObservedAt
	}
	h.LastCapturedAt = s.LastObservedAt
	return j.writeInvocationCheckpoint(ctx, tx, key, h)
}

func (j *Journal) invocationSourceTx(ctx context.Context, tx *sql.Tx, id InvocationStreamIdentity) (NativeTurnSource, error) {
	s, err := readNativeTurn(ctx, tx, id.NativeGeneration, logicalWorkerTurn(id.Sequence))
	if err != nil {
		return s, err
	}
	if invocationIdentity(s) != id || s.SourceInvocation == nil || s.SourceInvocation.Validate() != nil || s.SourceTask != nil || s.InputKind != "invocation" {
		return NativeTurnSource{}, ErrConflict
	}
	return s, nil
}
func (j *Journal) subscribeInvocationStream(ctx context.Context, key []byte, lease int64, req InvocationStreamRequest) (InvocationStreamSubscription, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return InvocationStreamSubscription{}, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return InvocationStreamSubscription{}, err
	}
	if _, err = j.invocationSourceTx(ctx, tx, req.Source); err != nil {
		return InvocationStreamSubscription{}, err
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, req.Source)
	if err != nil {
		return InvocationStreamSubscription{}, err
	}
	defer clear(h.Key)
	if h.Closed {
		return InvocationStreamSubscription{}, ErrInvocationStreamExpired
	}
	var existing InvocationStreamSubscription
	var previousLease, expiry int64
	err = tx.QueryRowContext(ctx, `SELECT lease,id,expires_at FROM worker_invocation_stream_subscriptions WHERE sequence=?`, req.Source.Sequence).Scan(&previousLease, &existing.ID, &expiry)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return existing, err
	}
	if err == nil && expiry <= time.Now().UnixNano() {
		return existing, ErrInvocationStreamExpired
	}
	if errors.Is(err, sql.ErrNoRows) && !h.ClaimDeadline.After(time.Now()) {
		return existing, ErrInvocationStreamExpired
	}
	if err == nil && previousLease == lease && expiry > time.Now().UnixNano() {
		existing.ExpiresAt = time.Unix(0, expiry)
		return existing, tx.Commit()
	}
	existing = InvocationStreamSubscription{ID: uuid.NewString(), ExpiresAt: time.Now().Add(invocationStreamTTL)}
	_, err = tx.ExecContext(ctx, `INSERT INTO worker_invocation_stream_subscriptions VALUES(?,?,?,?) ON CONFLICT(sequence) DO UPDATE SET lease=excluded.lease,id=excluded.id,expires_at=excluded.expires_at`, req.Source.Sequence, lease, existing.ID, existing.ExpiresAt.UnixNano())
	if err != nil {
		return existing, err
	}
	return existing, tx.Commit()
}
func (j *Journal) checkInvocationSubscriber(ctx context.Context, tx *sql.Tx, lease int64, req InvocationStreamRequest) error {
	if _, _, err := checkLease(ctx, tx, lease); err != nil {
		return err
	}
	if _, err := j.invocationSourceTx(ctx, tx, req.Source); err != nil {
		return err
	}
	var actualLease, expiry int64
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT lease,id,expires_at FROM worker_invocation_stream_subscriptions WHERE sequence=?`, req.Source.Sequence).Scan(&actualLease, &id, &expiry); err != nil {
		return err
	}
	if actualLease != lease || id != req.SubscriptionID || id == "" {
		return ErrFenced
	}
	if expiry <= time.Now().UnixNano() {
		return ErrInvocationStreamExpired
	}
	return nil
}
func (j *Journal) renewInvocationStream(ctx context.Context, lease int64, req InvocationStreamRequest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = j.checkInvocationSubscriber(ctx, tx, lease, req); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE worker_invocation_stream_subscriptions SET expires_at=? WHERE sequence=?`, time.Now().Add(invocationStreamTTL).UnixNano(), req.Source.Sequence)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (j *Journal) readInvocationStream(ctx context.Context, key []byte, lease int64, req InvocationStreamRequest) (*InvocationStreamProjection, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = j.checkInvocationSubscriber(ctx, tx, lease, req); err != nil {
		return nil, err
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, req.Source)
	if err != nil {
		return nil, err
	}
	defer clear(h.Key)
	if h.Closed {
		return nil, ErrInvocationStreamExpired
	}
	return h.Pending, tx.Commit()
}
func (j *Journal) ackInvocationStream(ctx context.Context, key []byte, lease int64, req InvocationStreamRequest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = j.checkInvocationSubscriber(ctx, tx, lease, req); err != nil {
		return err
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, req.Source)
	if err != nil {
		return err
	}
	defer clear(h.Key)
	if h.Pending == nil {
		if req.ProjectionOrdinal == h.AckOrdinal && req.Digest == h.AckDigest && req.Digest != "" {
			return tx.Commit()
		}
		return ErrConflict
	}
	if h.Pending.Ordinal != req.ProjectionOrdinal || h.Pending.Digest != req.Digest {
		return ErrConflict
	}
	h.Cursor = h.PendingCursor
	h.AckOrdinal = h.Pending.Ordinal
	h.AckDigest = h.Pending.Digest
	h.Pending = nil
	if h.PendingTerminal {
		h.Closed = true
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_invocation_stream_deltas WHERE sequence=? AND ordinal<?`, req.Source.Sequence, h.Cursor.Ordinal); err != nil {
		return err
	}
	if err = j.writeInvocationCheckpoint(ctx, tx, key, h); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(ctx)
}
func (j *Journal) unsubscribeInvocationStream(ctx context.Context, key []byte, lease int64, req InvocationStreamRequest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = j.checkInvocationSubscriber(ctx, tx, lease, req); err != nil {
		return err
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, req.Source)
	if err != nil {
		return err
	}
	defer clear(h.Key)
	if !h.Closed {
		h.UnavailableReason = "consumer_cancelled"
	}
	h.Closed = true
	h.Pending = nil
	if _, err = tx.ExecContext(ctx, `DELETE FROM worker_invocation_stream_deltas WHERE sequence=?`, req.Source.Sequence); err != nil {
		return err
	}
	if err = j.writeInvocationCheckpoint(ctx, tx, key, h); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return j.reclaimSourceStreamsLocked(ctx)
}
func invocationProjectionDigest(p InvocationStreamProjection) string {
	p.Digest = ""
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// OpenInvocationStreamProjection checks the encrypted inner source association.
// Callers supply their remembered original source, never trust response labels.
func OpenInvocationStreamProjection(p InvocationStreamProjection, expected NativeTurnSource, instanceID string, key [32]byte) (InvocationStreamRange, error) {
	var r InvocationStreamRange
	if p.Digest != invocationProjectionDigest(p) || p.Ordinal < 1 || expected.SourceInvocation == nil {
		return r, ErrConflict
	}
	aad := expected.SourceInvocation.InputAAD
	aad.ObjectType = e2ee.ObjectTypeInvocationOutput
	aad.Sender = instanceID
	aad.CreatedAt = p.AAD.CreatedAt
	if !reflect.DeepEqual(aad, p.AAD) {
		return r, ErrConflict
	}
	plain, err := e2ee.Decrypt(p.Ciphertext, key, p.AAD)
	if err != nil {
		return r, err
	}
	defer clear(plain)
	if len(plain) > maxFrame || decodeClosed(plain, &r) != nil || !reflect.DeepEqual(r.Source, expected) || r.Ordinal != p.Ordinal || len(r.Data) > invocationStreamChunkBytes || r.ByteOffset < 0 {
		return InvocationStreamRange{}, ErrConflict
	}
	return r, nil
}

// Only the worker calls this timer. The sole input is an existing committed
// original capture range; no native SessionEvent is synthesized for projection.
func (o *SessionOwner) runInvocationStreamTimer() {
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		ticker := time.NewTicker(invocationStreamTick)
		defer ticker.Stop()
		for {
			select {
			case <-o.ctx.Done():
				return
			case <-ticker.C:
				err := o.projectInvocationStreams(o.ctx)
				if err != nil && !errors.Is(err, context.Canceled) {
					o.failPersistence(fmt.Errorf("original invocation projection: %w", err))
				}
			}
		}
	}()
}

// Status is original private source evidence, not a delivery/native outcome
// synthesized from the controller's connection or a missing output chunk.
type InvocationStreamState struct {
	Source         InvocationStreamIdentity `json:"source"`
	DeliveredBytes int64                    `json:"deliveredBytes"`
	AckOrdinal     int64                    `json:"ackOrdinal"`
	AckDigest      string                   `json:"ackDigest,omitempty"`
	DeliveryError  string                   `json:"deliveryError,omitempty"`
	Closed         bool                     `json:"closed"`
	Terminal       *NativeObservation       `json:"terminal,omitempty"`
}

func (j *Journal) invocationStreamStatus(ctx context.Context, key []byte, lease int64, req InvocationStreamRequest) (*InvocationStreamState, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, _, err = checkLease(ctx, tx, lease); err != nil {
		return nil, err
	}
	if _, err = j.invocationSourceTx(ctx, tx, req.Source); err != nil {
		return nil, err
	}
	h, err := j.readInvocationCheckpoint(ctx, tx, key, req.Source)
	if err != nil {
		return nil, err
	}
	defer clear(h.Key)
	return &InvocationStreamState{Source: req.Source, DeliveredBytes: h.Cursor.Bytes, AckOrdinal: h.AckOrdinal, AckDigest: h.AckDigest, DeliveryError: h.UnavailableReason, Closed: h.Closed, Terminal: h.Terminal}, tx.Commit()
}

func validInvocationDeliveryReason(reason string) bool {
	switch reason {
	case "", "delivery_window_exhausted", "consumer_expired", "consumer_cancelled", "consumer_unclaimed":
		return true
	}
	return false
}
