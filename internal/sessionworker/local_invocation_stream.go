package sessionworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// LocalStreamConfig is fixed before native work starts. These budgets govern
// retained delivery evidence, independently of native acceptance and completion.
type LocalStreamConfig struct {
	MaxFrames  int   `json:"maxFrames"`
	MaxBytes   int64 `json:"maxBytes"`
	MaxSources int   `json:"maxSources"`
}

func DefaultLocalStreamConfig() LocalStreamConfig {
	return LocalStreamConfig{4096, 128 << 20, maxCommands}
}
func (c LocalStreamConfig) valid() bool {
	return c.MaxFrames > 0 && c.MaxFrames <= 4096 && c.MaxBytes >= 4096 && c.MaxBytes <= 128<<20 && c.MaxSources > 0 && c.MaxSources <= maxCommands
}

type LocalStreamSource struct {
	Authority           AuthorityScope           `json:"authority"`
	Turn                NativeTurnSource         `json:"turn"`
	Original            LocalIntentSource        `json:"original"`
	ActivationOrigin    fabricidentity.Origin    `json:"activationOrigin"`
	ActivationAdmission fabricidentity.Admission `json:"activationAdmission"`
}
type LocalInvocationCipherFrame struct {
	Cursor     int64  `json:"cursor,string"`
	Ciphertext []byte `json:"ciphertext"`
	Digest     string `json:"digest"`
}
type LocalInvocationPage struct {
	Readiness ReadinessToken               `json:"readiness"`
	Source    LocalStreamSource            `json:"source"`
	Frames    []LocalInvocationCipherFrame `json:"frames"`
	Floor     int64                        `json:"floor,string"`
	Terminal  bool                         `json:"terminal"`
}
type localStreamMeta struct {
	Version           string
	Config            LocalStreamConfig
	Frames            int
	Bytes             int64
	Sources           int
	PendingTerminals  int
	LastBegunSequence int64
}
type localStreamHead struct {
	Source      LocalStreamSource
	Next        int64
	Floor       int64
	FloorDigest string
	HeadDigest  string
	Frames      int
	Bytes       int64
	Terminal    bool
	LastDelta   int64
}
type localStreamPlainFrame struct {
	Previous string
	Frame    fabric.InvocationFrame
}

const localStreamVersion = "pagnet-worker-local-invocation-stream-v1"
const localStreamCipherLimit = 64 << 10

func localStreamAAD(scope AuthorityScope, directory, purpose string, sequence, cursor int64, sourceDigest string) ([]byte, error) {
	if scope.Kind() != nativeauthority.Local || scope.Validate() != nil {
		return nil, ErrFenced
	}
	return canonicalNativeJSON(struct {
		Version            string
		Authority          AuthorityScope
		Directory, Purpose string
		Sequence, Cursor   int64
		SourceDigest       string
	}{localStreamVersion, scope, directory, purpose, sequence, cursor, sourceDigest})
}
func sealLocalStream(key []byte, scope AuthorityScope, dir, purpose string, seq, cursor int64, sourceDigest string, value any) ([]byte, error) {
	raw, e := canonicalNativeJSON(value)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	if len(raw) > localStreamCipherLimit-128 {
		return nil, ErrFull
	}
	aad, e := localStreamAAD(scope, dir, purpose, seq, cursor, sourceDigest)
	if e != nil {
		return nil, e
	}
	a, e := captureAEADBound(key, scope, dir)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, raw, aad), nil
}
func openLocalStream(key []byte, scope AuthorityScope, dir, purpose string, seq, cursor int64, sourceDigest string, ciphertext []byte, value any) error {
	if len(ciphertext) == 0 || len(ciphertext) > localStreamCipherLimit {
		return ErrConflict
	}
	aad, e := localStreamAAD(scope, dir, purpose, seq, cursor, sourceDigest)
	if e != nil {
		return e
	}
	a, e := captureAEADBound(key, scope, dir)
	if e != nil {
		return e
	}
	if len(ciphertext) < a.NonceSize()+a.Overhead() {
		return ErrConflict
	}
	raw, e := a.Open(nil, ciphertext[:a.NonceSize()], ciphertext[a.NonceSize():], aad)
	if e != nil {
		return ErrConflict
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, value, fabric.WireLimits{MaxBytes: localStreamCipherLimit, MaxDepth: 32, MaxMembers: 4096}) != nil {
		return ErrConflict
	}
	return nil
}
func localStreamDigest(value any) (string, error) {
	raw, e := canonicalNativeJSON(value)
	if e != nil {
		return "", e
	}
	defer clear(raw)
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:]), nil
}
func localCipherDigest(raw []byte) string { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }
func validateLocalStreamSource(s LocalStreamSource) error {
	if s.Authority.Kind() != nativeauthority.Local || s.Authority.Validate() != nil || s.Turn.InputKind != "local-native" || s.Turn.SourceTask != nil || s.Turn.SourceInvocation != nil || s.Turn.Sequence <= 0 || s.Turn.LogicalTurnID != logicalWorkerTurn(s.Turn.Sequence) || s.Turn.NativeGeneration == "" || s.Turn.NativeSessionID == "" || s.Turn.SourceCommandID != s.Original.Commitment.CommandID || s.Turn.SourceAdmissionID != s.Original.Admission.ID || s.Turn.Sequence != s.Original.Commitment.Sequence || validateLocalReservation(s.Authority, s.Original) != nil || nativeauthority.ValidateOriginalOrigin(s.Authority, s.ActivationAdmission, s.ActivationOrigin, s.Turn.NativeGeneration) != nil {
		return ErrConflict
	}
	return nil
}
func (j *Journal) readLocalStreamMeta(ctx context.Context, tx *sql.Tx, key []byte) (localStreamMeta, error) {
	var m localStreamMeta
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN length(payload)<=? THEN payload END FROM worker_local_stream_meta WHERE singleton=1`, localStreamCipherLimit).Scan(&raw)
	if e != nil {
		return m, e
	}
	e = openLocalStream(key, j.authority, j.dir, "metadata", 0, 0, "", raw, &m)
	if e != nil || m.Version != localStreamVersion || !m.Config.valid() || m.Frames < 0 || m.Frames > m.Config.MaxFrames || m.Bytes < 1024 || m.Bytes > m.Config.MaxBytes || m.Sources < 0 || m.Sources > m.Config.MaxSources || m.LastBegunSequence < 0 || m.PendingTerminals < 0 || m.PendingTerminals > m.Sources {
		return m, ErrConflict
	}
	return m, nil
}
func (j *Journal) writeLocalStreamMeta(ctx context.Context, tx *sql.Tx, key []byte, m localStreamMeta) error {
	raw, e := sealLocalStream(key, j.authority, j.dir, "metadata", 0, 0, "", m)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE worker_local_stream_meta SET payload=? WHERE singleton=1`, raw)
	return e
}
func (j *Journal) readLocalStreamHead(ctx context.Context, tx *sql.Tx, key []byte, sequence int64) (localStreamHead, error) {
	var h localStreamHead
	var raw []byte
	var closed bool
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN length(payload)<=? THEN payload END,closed FROM worker_local_stream_heads WHERE sequence=?`, localStreamCipherLimit, sequence).Scan(&raw, &closed)
	if e != nil {
		return h, e
	}
	e = openLocalStream(key, j.authority, j.dir, "head", sequence, 0, "", raw, &h)
	if e != nil || h.Source.Authority != j.authority || h.Source.Turn.Sequence != sequence || validateLocalStreamSource(h.Source) != nil || h.Next < 0 || h.Floor < -1 || h.Floor >= h.Next || h.Frames < 0 || int64(h.Frames) != h.Next-h.Floor-1 || h.Bytes < 0 || h.LastDelta < 0 || closed != (h.Terminal && h.Frames == 0) {
		return h, ErrConflict
	}
	return h, nil
}
func (j *Journal) writeLocalStreamHead(ctx context.Context, tx *sql.Tx, key []byte, h localStreamHead, m *localStreamMeta) error {
	raw, e := sealLocalStream(key, j.authority, j.dir, "head", h.Source.Turn.Sequence, 0, "", h)
	if e != nil {
		return e
	}
	var previousSize int64
	if e = tx.QueryRowContext(ctx, `SELECT length(payload) FROM worker_local_stream_heads WHERE sequence=?`, h.Source.Turn.Sequence).Scan(&previousSize); e != nil {
		return e
	}
	growth := int64(len(raw)) - previousSize
	if growth > m.Config.MaxBytes-m.Bytes {
		return ErrFull
	}
	m.Bytes += growth
	_, e = tx.ExecContext(ctx, `UPDATE worker_local_stream_heads SET payload=?,closed=? WHERE sequence=?`, raw, h.Terminal && h.Frames == 0, h.Source.Turn.Sequence)
	return e
}

// InitializeLocalInvocationStreams must finish before owner launch/admission.
// Restart validates every retained frame in bounded pages before exposing pages.
func (j *Journal) InitializeLocalInvocationStreams(ctx context.Context, key []byte, config LocalStreamConfig) error {
	if ctx == nil || !j.isLocal() || len(key) != 32 || !config.valid() {
		return ErrFenced
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	tx, e := j.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var exists bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_local_stream_meta')`).Scan(&exists); e != nil {
		return e
	}
	if !exists {
		var next int64
		if e = tx.QueryRowContext(ctx, `SELECT next_sequence FROM worker_meta WHERE singleton=1`).Scan(&next); e != nil {
			return e
		}
		if next != 1 {
			return ErrConflict
		}
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS worker_local_stream_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),payload BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS worker_local_stream_heads(sequence INTEGER PRIMARY KEY,payload BLOB NOT NULL,closed INTEGER NOT NULL CHECK(closed IN (0,1)))`,
		`CREATE TABLE IF NOT EXISTS worker_local_stream_frames(sequence INTEGER NOT NULL,cursor INTEGER NOT NULL,ciphertext BLOB NOT NULL,PRIMARY KEY(sequence,cursor)) WITHOUT ROWID`,
		`CREATE TRIGGER IF NOT EXISTS worker_local_stream_source_fence BEFORE DELETE ON worker_turn_sources WHEN EXISTS(SELECT 1 FROM worker_local_stream_heads WHERE sequence=OLD.sequence AND closed=0) BEGIN SELECT RAISE(ABORT,'original local invocation stream remains retained'); END`,
	} {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	if !exists {
		raw, e := sealLocalStream(key, j.authority, j.dir, "metadata", 0, 0, "", localStreamMeta{Version: localStreamVersion, Config: config, Bytes: 1024})
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO worker_local_stream_meta VALUES(1,?)`, raw); e != nil {
			return e
		}
	}
	m, e := j.readLocalStreamMeta(ctx, tx, key)
	if e != nil {
		return e
	}
	if m.Config != config {
		return ErrConflict
	}
	var seq int64
	var totalFrames, totalSources, pendingTerminals int
	totalBytes := int64(1024)
	var totalHeadBytes int64
	for {
		var next int64
		e = tx.QueryRowContext(ctx, `SELECT sequence FROM worker_local_stream_heads WHERE sequence>? ORDER BY sequence LIMIT 1`, seq).Scan(&next)
		if errors.Is(e, sql.ErrNoRows) {
			break
		}
		if e != nil {
			return e
		}
		seq = next
		totalSources++
		if totalSources > config.MaxSources {
			return ErrConflict
		}
		var headBytes int64
		if e = tx.QueryRowContext(ctx, `SELECT length(payload) FROM worker_local_stream_heads WHERE sequence=?`, seq).Scan(&headBytes); e != nil {
			return e
		}
		totalBytes += headBytes
		totalHeadBytes += headBytes
		h, e := j.readLocalStreamHead(ctx, tx, key, seq)
		if e != nil {
			return e
		}
		if !h.Terminal {
			pendingTerminals++
		}
		if seq > m.LastBegunSequence {
			return ErrConflict
		}
		previous := h.FloorDigest
		cursor := h.Floor
		var count int
		var bytes int64
		for cursor < h.Next-1 {
			var raw []byte
			var nextCursor int64
			e = tx.QueryRowContext(ctx, `SELECT cursor,CASE WHEN length(ciphertext)<=? THEN ciphertext END FROM worker_local_stream_frames WHERE sequence=? AND cursor>? ORDER BY cursor LIMIT 1`, localStreamCipherLimit, seq, cursor).Scan(&nextCursor, &raw)
			if e != nil || nextCursor != cursor+1 {
				return ErrConflict
			}
			f, e := openLocalInvocationFrame(key, j.authority, j.dir, h.Source, LocalInvocationCipherFrame{nextCursor, raw, localCipherDigest(raw)})
			if e != nil || f.Previous != previous {
				return ErrConflict
			}
			if (nextCursor == 0) != (f.Frame.Kind == fabric.FrameStart) || (nextCursor < h.Next-1 && (f.Frame.Kind == fabric.FrameComplete || f.Frame.Kind == fabric.FrameError)) {
				return ErrConflict
			}
			previous = localCipherDigest(raw)
			cursor = nextCursor
			count++
			bytes += int64(len(raw))
			if count > config.MaxFrames || bytes > config.MaxBytes {
				return ErrConflict
			}
			if cursor == h.Next-1 && h.Terminal != (f.Frame.Kind == fabric.FrameComplete || f.Frame.Kind == fabric.FrameError) {
				return ErrConflict
			}
		}
		if count != h.Frames || bytes != h.Bytes || previous != h.HeadDigest {
			return ErrConflict
		}
		totalFrames += count
		totalBytes += bytes
	}
	var actualFrames int
	var actualBytes int64
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(size),0) FROM (SELECT length(ciphertext) AS size FROM worker_local_stream_frames LIMIT ?)`, config.MaxFrames+1).Scan(&actualFrames, &actualBytes); e != nil {
		return e
	}
	if pendingTerminals != m.PendingTerminals || totalSources != m.Sources || totalFrames != m.Frames || totalBytes != m.Bytes || actualFrames != totalFrames || actualBytes+totalHeadBytes+1024 != totalBytes {
		return ErrConflict
	}
	return tx.Commit()
}
func openLocalInvocationFrame(key []byte, authority AuthorityScope, dir string, source LocalStreamSource, c LocalInvocationCipherFrame) (localStreamPlainFrame, error) {
	var p localStreamPlainFrame
	if validateLocalStreamSource(source) != nil || source.Authority != authority || c.Cursor < 0 || c.Digest != localCipherDigest(c.Ciphertext) {
		return p, ErrConflict
	}
	digest, e := localStreamDigest(source)
	if e != nil {
		return p, e
	}
	e = openLocalStream(key, authority, dir, "frame", source.Turn.Sequence, c.Cursor, digest, c.Ciphertext, &p)
	if e != nil || p.Frame.InvocationID != source.Original.Admission.InvocationID || p.Frame.Sequence != uint64(c.Cursor) || len(p.Frame.Data) > fabric.MaxFrameBytes {
		return p, ErrConflict
	}
	switch p.Frame.Kind {
	case fabric.FrameStart:
		if c.Cursor != 0 || len(p.Frame.Data) != 0 || p.Frame.Error != nil {
			return p, ErrConflict
		}
	case fabric.FrameChunk, fabric.FrameProgress:
		if c.Cursor == 0 || p.Frame.Error != nil {
			return p, ErrConflict
		}
	case fabric.FrameComplete:
		if c.Cursor == 0 || p.Frame.Error != nil {
			return p, ErrConflict
		}
	case fabric.FrameError:
		if c.Cursor == 0 || p.Frame.Error == nil || len(p.Frame.Data) != 0 {
			return p, ErrConflict
		}
	default:
		return p, fmt.Errorf("%w: local frame kind", ErrConflict)
	}
	return p, nil
}

// OpenLocalInvocationFrame decrypts one exact source/cursor frame. Consumers
// still require a fresh current-authority gate; immutable evidence is not access.
func OpenLocalInvocationFrame(key []byte, authority AuthorityScope, dir string, source LocalStreamSource, c LocalInvocationCipherFrame) (fabric.InvocationFrame, error) {
	p, e := openLocalInvocationFrame(key, authority, dir, source, c)
	return p.Frame, e
}

// Trusted fixed SQL only: Cloud journals do not bootstrap a local namespace.
func (j *Journal) localStreamRetentionPredicate() string {
	if !j.isLocal() {
		return ""
	}
	return " AND NOT EXISTS(SELECT 1 FROM worker_local_stream_heads l WHERE l.sequence=t.sequence AND l.closed=0)"
}
