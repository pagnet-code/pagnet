//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func outputBatchFixture(t *testing.T) (*Journal, *nativeSourceProducer, NativeTurnSource, []byte, []session.SessionEvent) {
	t.Helper()
	j, _ := testJournal(t)
	p, _ := retiredFixture(t, j, "source-A", "generation-A")
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: p.generation, NativeSessionID: "session-A", SourceCommandID: "command-A", SourceAdmissionID: "admission-A", InputKind: "task"}
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
	var events []session.SessionEvent
	for _, text := range []string{"original one", "original two", "original three"} {
		events = append(events, session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID, Output: text})
	}
	return j, p, source, bytes.Repeat([]byte{19}, 32), events
}

func TestNativeOutputCaptureBatchOriginalOrdinalsRetryAndSourceFence(t *testing.T) {
	j, p, source, key, events := outputBatchFixture(t)
	data, n, err := j.appendOutputDeltas(context.Background(), p, key, source, events, "same-original-batch", [32]byte{}, false)
	if err != nil || n != len(events) || data.DeltaCount != int64(len(events)) {
		t.Fatal("batch original count", n, err)
	}
	var digest []byte
	for _, event := range events {
		raw, _ := canonicalNativeJSON(event)
		h := sha256.New()
		h.Write(digest)
		h.Write(raw)
		digest = h.Sum(nil)
	}
	if data.RollingDigest != hex.EncodeToString(digest) {
		t.Fatal("batch replaced per-frame rolling hash")
	}
	recovered, _, err := j.readOutputSpool(context.Background(), key, source.NativeGeneration, source.Sequence)
	if err != nil || recovered.Text != "original oneoriginal twooriginal three" || recovered.DeltaCount != 3 {
		t.Fatal("batch original evidence", err)
	}
	retry, n, err := j.appendOutputDeltas(context.Background(), p, key, source, events, "same-original-batch", [32]byte{}, false)
	if err != nil || n != 3 || retry.DeltaCount != 3 || sourceCount(t, j, "worker_output_deltas") != 3 {
		t.Fatal("ambiguous commit retry duplicated frames", n, err)
	}
	modified := append([]session.SessionEvent(nil), events...)
	modified[0].Output = "substituted"
	if _, _, err = j.appendOutputDeltas(context.Background(), p, key, source, modified, "same-original-batch", [32]byte{}, false); !errors.Is(err, ErrConflict) {
		t.Fatal("batch accepted substituted first frame", err)
	}
	modified = append([]session.SessionEvent(nil), events...)
	modified[1].SessionID = "another-session"
	if _, _, err = j.appendOutputDeltas(context.Background(), p, key, source, modified, "foreign-batch", [32]byte{}, false); !errors.Is(err, ErrConflict) {
		t.Fatal("mixed session batch accepted", err)
	}
	if err = j.retireNativeSource(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.appendOutputDeltas(context.Background(), p, key, source, events, "retired-batch", [32]byte{}, false); !errors.Is(err, ErrFenced) {
		t.Fatal("retired source appended batch", err)
	}
}

func TestNativeOutputCaptureBatchInsertFailureRollsBackAllFramesAndQuota(t *testing.T) {
	j, p, source, key, events := outputBatchFixture(t)
	var before, after int
	if err := j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := j.db.Exec(`CREATE TRIGGER fail_original_second_frame BEFORE INSERT ON worker_output_deltas WHEN NEW.ordinal=2 BEGIN SELECT RAISE(ABORT,'injected exact original frame failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.appendOutputDeltas(context.Background(), p, key, source, events, "failed-batch", [32]byte{}, false); err == nil {
		t.Fatal("injected frame failure ignored")
	}
	if err := j.db.QueryRow(`SELECT capture_left FROM worker_terminal_reservations WHERE sequence=1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after || sourceCount(t, j, "worker_output_deltas") != 0 || sourceCount(t, j, "worker_output_spools") != 0 {
		t.Fatal("rejected batch accepted evidence or consumed quota")
	}
	if _, err := j.db.Exec(`DROP TRIGGER fail_original_second_frame`); err != nil {
		t.Fatal(err)
	}
	if _, n, err := j.appendOutputDeltas(context.Background(), p, key, source, events, "failed-batch", [32]byte{}, false); err != nil || n != 3 {
		t.Fatal("exact original batch could not recover", n, err)
	}
}

func TestNativeOutputCaptureBatchBoundaryAmbiguousCommitKeepsExactPrefix(t *testing.T) {
	j, p, source, key, events := outputBatchFixture(t)
	first := events[0]
	first.Output = strings.Repeat("x", nativeOutputBatchBytes-8)
	if _, err := j.appendOutputDelta(context.Background(), p, key, source, first, "before-boundary", [32]byte{}, false); err != nil {
		t.Fatal(err)
	}
	for i := range events {
		events[i].Output = "12345678"
	}
	data, n, err := j.appendOutputDeltas(context.Background(), p, key, source, events, "boundary-attempt", [32]byte{}, false)
	if err != nil || n != 1 || data.NativeBytes != nativeOutputBatchBytes || data.DeltaCount != 2 {
		t.Fatal("boundary prefix", n, err)
	}
	data, n, err = j.appendOutputDeltas(context.Background(), p, key, source, events, "boundary-attempt", [32]byte{}, false)
	if err != nil || n != 1 || data.DeltaCount != 2 || sourceCount(t, j, "worker_output_deltas") != 2 {
		t.Fatal("ambiguous prefix retry duplicated", n, err)
	}
	modified := append([]session.SessionEvent(nil), events...)
	modified[2].Output = "different-last-uncommitted-frame"
	if _, _, err = j.appendOutputDeltas(context.Background(), p, key, source, modified, "boundary-attempt", [32]byte{}, false); !errors.Is(err, ErrConflict) {
		t.Fatal("attempt commitment lost uncaptured original suffix", err)
	}
	// Project the FULL original prefix once, using the exact encrypted-head CAS.
	data, cipher, err := j.readOutputSpool(context.Background(), key, source.NativeGeneration, 1)
	if err != nil {
		t.Fatal(err)
	}
	data.Text = ""
	data.ByteOffset = nativeOutputBatchBytes
	data.PendingDeltas = 0
	data.PendingBytes = 0
	data.PendingBaseDigest = ""
	remaining, err := sealOutputSpool(key, j.scope, j.dir, data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cipher)
	projection := &outputSpoolProjection{Sequence: 1, Generation: source.NativeGeneration, PreviousDigest: hex.EncodeToString(sum[:]), Remaining: remaining}
	tx, err := j.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.projectOutputSpoolTx(context.Background(), tx, projection); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = j.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.projectOutputSpoolTx(context.Background(), tx, projection); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate projection accepted", err)
	}
	_ = tx.Rollback()
	data, n, err = j.appendOutputDeltas(context.Background(), p, key, source, events[1:], "remaining-attempt", [32]byte{}, false)
	if err != nil || n != 2 || data.DeltaCount != 4 || data.NativeBytes != nativeOutputBatchBytes+16 {
		t.Fatal("original suffix changed", n, err)
	}
	data, _, err = j.readOutputSpool(context.Background(), key, source.NativeGeneration, 1)
	if err != nil || data.Text != "1234567812345678" || data.ByteOffset != nativeOutputBatchBytes {
		t.Fatal("suffix replay lost exact original evidence", err)
	}
}

func TestRetiredNativeBatchUnavailableSourceCannotRefreshActivity(t *testing.T) {
	j, p, source, key, events := outputBatchFixture(t)
	manager := session.NewManager()
	sess := manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	sess.LastActivity = time.Unix(123, 0)
	owner := &SessionOwner{ctx: context.Background(), journal: j, captureKey: key, manager: manager, generation: source.NativeGeneration}
	_, _, batch := owner.nativeCapturedSourceObservers(j.scope.InstanceID, p, source.NativeGeneration, p.origin)
	if err := j.retireNativeSource(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	events[0].TurnID = "human-unbound"
	if err := batch(events[:1]); !errors.Is(err, ErrFenced) {
		t.Fatal("retired unavailable source not fenced", err)
	}
	if !sess.LastActivity.Equal(time.Unix(123, 0)) || sourceCount(t, j, "worker_observations") != 0 {
		t.Fatal("retired batch changed activity/evidence")
	}
}
