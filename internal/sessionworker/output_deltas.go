package sessionworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/pagnet-code/pagnet/internal/session"
)

// Each original callback is durable independently. Only compact authenticated
// counters are rewritten; a growing plaintext tail is never rewritten per byte.
// The ordinal AAD and authenticated metadata bind order, completeness and scope.
func outputDeltaAAD(scope Scope, directory, generation string, sequence, ordinal int64) []byte {
	raw, _ := canonicalNativeJSON(struct {
		Domain                string
		Scope                 Scope
		Directory, Generation string
		Sequence, Ordinal     int64
	}{"pagnet-worker-private-output-delta-v1", scope, directory, generation, sequence, ordinal})
	return raw
}

func sealOutputDelta(key []byte, scope Scope, directory string, source NativeTurnSource, ordinal int64, raw []byte) ([]byte, error) {
	aead, err := captureAEAD(key, scope, directory)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, raw, outputDeltaAAD(scope, directory, source.NativeGeneration, source.Sequence, ordinal)), nil
}

type outputDeltaReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Called only under the journal lock. Assembly is linear in captured bytes and
// occurs at projection/recovery, not on every native callback. Missing, reordered,
// transplanted or modified rows never become an original output observation.
func (j *Journal) assembleOutputDeltas(ctx context.Context, reader outputDeltaReader, key []byte, data *nativeOutputSpool, storedSize, headBytes int) error {
	if data.PendingDeltas == 0 {
		var stray bool
		if err := reader.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM worker_output_deltas WHERE sequence=?)`, data.Source.Sequence).Scan(&stray); err != nil {
			return err
		}
		if stray || storedSize != headBytes {
			return ErrConflict
		}
		return nil
	}
	if data.PendingDeltas < 0 || data.PendingDeltas > data.DeltaCount || data.PendingBytes < 0 || len(data.Text)+data.PendingBytes > data.NativeBytes {
		return ErrConflict
	}
	aead, err := captureAEAD(key, j.scope, j.dir)
	if err != nil {
		return err
	}
	rows, err := reader.QueryContext(ctx, `SELECT ordinal,ciphertext FROM worker_output_deltas WHERE sequence=? ORDER BY ordinal`, data.Source.Sequence)
	if err != nil {
		return err
	}
	defer rows.Close()
	var text strings.Builder
	text.Grow(len(data.Text) + data.PendingBytes)
	text.WriteString(data.Text)
	digest, err := hex.DecodeString(data.PendingBaseDigest)
	if err != nil || (data.DeltaCount == data.PendingDeltas && len(digest) != 0) || (data.DeltaCount > data.PendingDeltas && len(digest) != sha256.Size) {
		return ErrConflict
	}
	expected := data.DeltaCount - data.PendingDeltas + 1
	var count int64
	var size int
	physical := headBytes
	for rows.Next() {
		var ordinal int64
		var cipher []byte
		if err = rows.Scan(&ordinal, &cipher); err != nil {
			return err
		}
		if ordinal != expected+count || count >= data.PendingDeltas || len(cipher) < aead.NonceSize()+aead.Overhead() {
			return ErrConflict
		}
		physical += len(cipher)
		raw, err := aead.Open(nil, cipher[:aead.NonceSize()], cipher[aead.NonceSize():], outputDeltaAAD(j.scope, j.dir, data.Source.NativeGeneration, data.Source.Sequence, ordinal))
		if err != nil {
			return ErrConflict
		}
		var event session.SessionEvent
		err = json.Unmarshal(raw, &event)
		chain := sha256.New()
		chain.Write(digest)
		chain.Write(raw)
		digest = chain.Sum(nil)
		clear(raw)
		if err != nil || event.Type != session.EventTurnOutput || !event.NativeOutput || event.SessionID != data.Source.NativeSessionID || event.TurnID != data.Source.LogicalTurnID || len(event.Output) > data.PendingBytes-size {
			return ErrConflict
		}
		text.WriteString(event.Output)
		size += len(event.Output)
		count++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if count != data.PendingDeltas || size != data.PendingBytes || physical != storedSize || hex.EncodeToString(digest) != data.RollingDigest {
		return ErrConflict
	}
	data.Text = text.String()
	return nil
}
