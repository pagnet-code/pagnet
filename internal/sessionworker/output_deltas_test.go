//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func outputDeltaFixture(t *testing.T) (*Journal, []byte, *nativeSourceProducer, NativeTurnSource) {
	t.Helper()
	j, _ := testJournal(t)
	p, _ := retiredFixture(t, j, "original-output", "native-output")
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: p.generation, NativeSessionID: "actual-output", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), InputKind: "task"}
	tx, err := j.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.reserveTerminalTx(context.Background(), tx, 1, "prompt"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{17}, 32)
	for n, output := range []string{"first-private-", "second-private-", "third-private"} {
		event := session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID, Output: output}
		data, err := j.appendOutputDelta(context.Background(), p, key, source, event, domain.NewID().String(), [32]byte{}, false)
		clear(data.Key)
		if err != nil {
			t.Fatalf("append %d: %v", n, err)
		}
	}
	return j, key, p, source
}

func TestNativeOutputDeltasAuthenticateCompletenessOrderAndScope(t *testing.T) {
	for name, mutation := range map[string]string{
		"missing":   `DELETE FROM worker_output_deltas WHERE ordinal=2`,
		"reordered": `UPDATE worker_output_deltas SET ciphertext=(SELECT ciphertext FROM worker_output_deltas WHERE ordinal=3) WHERE ordinal=2`,
		"extra":     `INSERT INTO worker_output_deltas SELECT sequence,ordinal+1,ciphertext FROM worker_output_deltas WHERE ordinal=3`,
		"corrupt":   `UPDATE worker_output_deltas SET ciphertext=X'0001' WHERE ordinal=2`,
		"size":      `UPDATE worker_output_spools SET size=size-1 WHERE sequence=1`,
	} {
		t.Run(name, func(t *testing.T) {
			j, key, _, source := outputDeltaFixture(t)
			data, _, err := j.readOutputSpool(context.Background(), key, source.NativeGeneration, source.Sequence)
			if err != nil || data.Text != "first-private-second-private-third-private" {
				t.Fatal("original deltas did not assemble", err)
			}
			if _, err = j.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, _, err = j.readOutputSpool(context.Background(), key, source.NativeGeneration, source.Sequence); !errors.Is(err, ErrConflict) {
				t.Fatal("changed original deltas were accepted", err)
			}
		})
	}
}

func TestNativeOutputDeltasProjectionRollbackSizeAndCleanup(t *testing.T) {
	j, key, _, source := outputDeltaFixture(t)
	ctx := context.Background()
	data, cipher, err := j.readOutputSpool(ctx, key, source.NativeGeneration, source.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	var size, physical, beforeReserve int
	if err = j.db.QueryRow(`SELECT size,length(ciphertext)+(SELECT SUM(length(ciphertext)) FROM worker_output_deltas WHERE sequence=1) FROM worker_output_spools WHERE sequence=1`).Scan(&size, &physical); err != nil || size != physical {
		t.Fatal("aggregate ciphertext quota drift", size, physical, err)
	}
	if err = j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&beforeReserve); err != nil {
		t.Fatal(err)
	}
	// A partial UTF-8-safe projection leaves an authenticated ordinary head
	// snapshot, while consumed original rows are removed only at COMMIT.
	data.Text = data.Text[6:]
	data.ByteOffset += 6
	data.PendingDeltas, data.PendingBytes, data.PendingBaseDigest = 0, 0, ""
	remaining, err := j.outputEncoder.seal(key, j.scope, j.dir, data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cipher)
	p := &outputSpoolProjection{Sequence: 1, Generation: source.NativeGeneration, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: remaining}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.projectOutputSpoolTx(ctx, tx, p); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_output_deltas") != 3 {
		t.Fatal("rollback deleted original deltas")
	}
	var reserve int
	if err = j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&reserve); err != nil || reserve != beforeReserve {
		t.Fatal("rollback changed reserved bytes", err)
	}
	tx, err = j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.projectOutputSpoolTx(ctx, tx, p); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_output_deltas") != 0 {
		t.Fatal("committed projection orphaned ciphertext")
	}
	if err = j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&reserve); err != nil || reserve != beforeReserve+size-len(remaining) {
		t.Fatal("aggregate ciphertext refund drift", err)
	}
	data, _, err = j.readOutputSpool(ctx, key, source.NativeGeneration, source.Sequence)
	if err != nil || data.Text != "private-second-private-third-private" {
		t.Fatal("partial projection lost residual output", data.Text, err)
	}
	if _, err = j.db.Exec(`INSERT INTO worker_output_deltas VALUES(1,4,X'0102')`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.readOutputSpool(ctx, key, source.NativeGeneration, source.Sequence); !errors.Is(err, ErrConflict) {
		t.Fatal("snapshot head accepted stray ciphertext", err)
	}
	if _, err = j.db.Exec(`DELETE FROM worker_output_spools WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_output_deltas") != 0 {
		t.Fatal("parent cleanup left orphaned ciphertext")
	}
}

func TestNativeOutputDeltasRejectAuthenticatedHeadInconsistency(t *testing.T) {
	for name, mutate := range map[string]func(*nativeOutputSpool){
		"negative_offset":     func(s *nativeOutputSpool) { s.ByteOffset = -1 },
		"wrong_byte_count":    func(s *nativeOutputSpool) { s.PendingBytes++ },
		"missing_base_digest": func(s *nativeOutputSpool) { s.PendingDeltas-- },
		"zero_pending_count":  func(s *nativeOutputSpool) { s.PendingDeltas = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			j, key, _, source := outputDeltaFixture(t)
			var cipher []byte
			if err := j.db.QueryRow(`SELECT ciphertext FROM worker_output_spools WHERE sequence=1`).Scan(&cipher); err != nil {
				t.Fatal(err)
			}
			data, err := openOutputSpool(key, j.scope, j.dir, source.NativeGeneration, 1, cipher)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&data)
			changed, err := j.outputEncoder.seal(key, j.scope, j.dir, data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = j.db.Exec(`UPDATE worker_output_spools SET ciphertext=?,size=size+? WHERE sequence=1`, changed, len(changed)-len(cipher)); err != nil {
				t.Fatal(err)
			}
			if _, _, err = j.readOutputSpool(context.Background(), key, source.NativeGeneration, 1); !errors.Is(err, ErrConflict) {
				t.Fatal("inconsistent authenticated head projected", err)
			}
		})
	}
}

func TestEmptyNativeOutputCallbackDoesNotCreatePendingCapture(t *testing.T) {
	j, _ := testJournal(t)
	owner := &SessionOwner{journal: j}
	var projected bool
	if err := owner.observeOutputDelta(nil, NativeTurnSource{}, session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true}, func(session.SessionEvent, *NativeOutputStreamProof, *outputSpoolProjection) error {
		projected = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if projected || sourceCount(t, j, "worker_output_spools") != 0 || sourceCount(t, j, "worker_output_deltas") != 0 {
		t.Fatal("empty callback created output or blocked EOF cleanup")
	}
}

func TestNativeOutputDeltasReadyPinPreservesAggregateQuota(t *testing.T) {
	j, key, _, source := outputDeltaFixture(t)
	ctx := context.Background()
	data, cipher, err := j.readOutputSpool(ctx, key, source.NativeGeneration, 1)
	if err != nil {
		t.Fatal(err)
	}
	text := data.Text
	data.ByteOffset += int64(len(data.Text))
	data.Text = ""
	data.PendingDeltas, data.PendingBytes, data.PendingBaseDigest = 0, 0, ""
	remaining, err := j.outputEncoder.seal(key, j.scope, j.dir, data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cipher)
	p := &outputSpoolProjection{Sequence: 1, Generation: source.NativeGeneration, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: remaining}
	ready := &nativeOutputReady{Observation: NativeObservation{ID: "original-capture-ready"}, Capture: []byte("original-private-ready-capture"), Remaining: remaining}
	if err = j.prepareOutputReady(ctx, key, p, ready); err != nil {
		t.Fatal(err)
	}
	var size, physical, reserve int
	if err = j.db.QueryRow(`SELECT size,length(ciphertext)+(SELECT SUM(length(ciphertext)) FROM worker_output_deltas WHERE sequence=1) FROM worker_output_spools WHERE sequence=1`).Scan(&size, &physical); err != nil || size != physical {
		t.Fatal("ready pin lost aggregate quota", size, physical, err)
	}
	if err = j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&reserve); err != nil {
		t.Fatal(err)
	}
	data, _, err = j.readOutputSpool(ctx, key, source.NativeGeneration, 1)
	if err != nil || data.Text != text || data.Ready == nil || !bytes.Equal(data.Ready.Capture, ready.Capture) {
		t.Fatal("ready pin lost exact original evidence", err)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.projectOutputSpoolTx(ctx, tx, p); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var after int
	if err = j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&after); err != nil || after != reserve+size-len(remaining) {
		t.Fatal("ready projection refund drift", err)
	}
	if sourceCount(t, j, "worker_output_deltas") != 0 {
		t.Fatal("ready projection orphaned ciphertext")
	}
}

func TestNativeOutputDeltaCiphertextCannotMoveBetweenScopes(t *testing.T) {
	for _, name := range []string{"key", "directory", "generation", "sequence", "ordinal"} {
		t.Run(name, func(t *testing.T) {
			j, key, _, source := outputDeltaFixture(t)
			event := session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID, Output: "second-private-"}
			raw, err := canonicalNativeJSON(event)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			foreignKey, directory, foreignSource, ordinal := key, j.dir, source, int64(2)
			switch name {
			case "key":
				foreignKey = bytes.Repeat([]byte{18}, 32)
			case "directory":
				directory += "-foreign"
			case "generation":
				foreignSource.NativeGeneration = "foreign-native"
			case "sequence":
				foreignSource.Sequence++
			case "ordinal":
				ordinal++
			}
			cipher, err := sealOutputDelta(foreignKey, j.scope, directory, foreignSource, ordinal, raw)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(cipher, []byte(event.Output)) {
				t.Fatal("delta retained plaintext")
			}
			if _, err = j.db.Exec(`UPDATE worker_output_deltas SET ciphertext=? WHERE ordinal=2`, cipher); err != nil {
				t.Fatal(err)
			}
			if _, _, err = j.readOutputSpool(context.Background(), key, source.NativeGeneration, source.Sequence); !errors.Is(err, ErrConflict) {
				t.Fatal("foreign ciphertext acquired original source authority", err)
			}
		})
	}
}
