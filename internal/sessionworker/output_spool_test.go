//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func TestNativeOutputTailOriginalKeyReopenBoundAndQuiescence(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	p, _ := retiredFixture(t, j, "original-A", "native-A")
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "native-A", NativeSessionID: "actual-A", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), InputKind: "task"}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.reserveTerminalTx(ctx, tx, 1, "prompt"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{17}, 32)
	var epochKey [32]byte
	copy(epochKey[:], bytes.Repeat([]byte{29}, 32))
	event := session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: source.LogicalTurnID, SessionID: source.NativeSessionID, Output: "genuine private native delta"}
	data, err := j.appendOutputDelta(ctx, p, key, source, event, "original-callback-id", epochKey, true)
	if err != nil {
		t.Fatal(err)
	}
	originalCount := data.DeltaCount
	clear(data.Key)
	// Exact callback retries recover uncertain COMMIT, without duplicating text.
	data, err = j.appendOutputDelta(ctx, p, key, source, event, "original-callback-id", epochKey, true)
	if err != nil || data.Text != event.Output || data.DeltaCount != originalCount {
		t.Fatal("callback retry duplicated original", err)
	}
	clear(data.Key)
	modified := event
	modified.Output = "different original evidence"
	if _, err = j.appendOutputDelta(ctx, p, key, source, modified, "original-callback-id", epochKey, true); !errors.Is(err, ErrConflict) {
		t.Fatal("same callback mutated", err)
	}
	var cipher []byte
	if err = j.db.QueryRow(`SELECT ciphertext FROM worker_output_spools WHERE sequence=1`).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte(event.Output)) || bytes.Contains(cipher, epochKey[:]) {
		t.Fatal("private tail leaked")
	}
	if err = j.retireNativeSource(ctx, p); err != nil {
		t.Fatal(err)
	}
	if sourceCount(t, j, "worker_source_registration") != 1 {
		t.Fatal("pending tail lost original generation watermark")
	}
	if _, err = j.appendOutputDelta(ctx, p, key, source, event, "late-callback", epochKey, true); !errors.Is(err, ErrFenced) {
		t.Fatal("retired reader appended", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	data, cipher2, err := j.readOutputSpool(ctx, key, "native-A", 1)
	if err != nil || data.Text != event.Output || !bytes.Equal(data.Key, epochKey[:]) || !bytes.Equal(cipher, cipher2) {
		t.Fatal("reopen lost original source/key/cipher", err)
	}
	clear(data.Key)
	if _, _, err = j.readOutputSpool(ctx, bytes.Repeat([]byte{5}, 32), "native-A", 1); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong private key opened original tail", err)
	}
	// Transactional tail advancement must roll back with its observation.
	sum := sha256.Sum256(cipher)
	tx, err = j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection := &outputSpoolProjection{Sequence: 1, Generation: "native-A", PreviousDigest: hex.EncodeToString(sum[:]), Close: true}
	if err = j.projectOutputSpoolTx(ctx, tx, projection); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if sourceCount(t, j, "worker_output_spools") != 1 {
		t.Fatal("rolled-back projection erased original")
	}
}

func TestNativeOutputStreamCaptureCompressedProofAndLegacy(t *testing.T) {
	j, dir := testJournal(t)
	defer j.Close()
	key := bytes.Repeat([]byte{7}, 32)
	proof := &NativeOutputStreamProof{Format: NativeOutputStreamCaptureFormat, StreamID: domain.NewID().String(), BatchID: domain.NewID().String(), DeltaCount: 8192, RollingDigest: strings.Repeat("a", 64), ByteLength: 65536, FirstObservedAt: time.Now().UTC(), LastObservedAt: time.Now().UTC()}
	observation := NativeObservation{ID: proof.BatchID, NativeGeneration: "original-A", NativeSessionID: "actual-A", Origin: json.RawMessage(`{"id":"origin-A"}`), ObservedAt: proof.FirstObservedAt, OutputStream: proof}
	source := NativeSourceCapture{Format: NativeSourceCaptureFormat, OutputStream: proof, Event: session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, Output: strings.Repeat("é", 32768)}}
	ref, cipher, err := sealNativeCapture(key, j.scope, dir, observation, source)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Version != 3 || len(cipher) > 4096 {
		t.Fatal("captured stream was not compressed", ref.Version, len(cipher))
	}
	observation.Capture = ref
	recovered, err := OpenNativeSourceCapture(key, j.scope, dir, observation, cipher)
	if err != nil || recovered.Event.Output != source.Event.Output || recovered.OutputStream.DeltaCount != 8192 {
		t.Fatal("original stream content/provenance changed", err)
	}
	altered := observation
	changed := *proof
	changed.DeltaCount++
	altered.OutputStream = &changed
	if _, err = OpenNativeSourceCapture(key, j.scope, dir, altered, cipher); err == nil {
		t.Fatal("stream provenance unauthenticated")
	}
	observation.OutputStream = nil
	source.OutputStream = nil
	ref, cipher, err = sealNativeCapture(key, j.scope, dir, observation, source)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Version != 2 {
		t.Fatal("legacy capture format changed")
	}
	observation.Capture = ref
	if _, err = OpenNativeSourceCapture(key, j.scope, dir, observation, cipher); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSourceReservationPrecedesAcceptanceAndSurvivesReopen(t *testing.T) {
	j, dir := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	authority := &Admission{Scope: j.scope}
	authorize := func() (*Admission, error) { return authority, nil }
	if _, err := j.db.Exec(`CREATE TRIGGER fail_accept BEFORE INSERT ON worker_intent BEGIN SELECT RAISE(ABORT,'isolated accept failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, run, err := j.admit(ctx, a, 1, "original-command-A", "prompt", json.RawMessage(`{}`), authorize); err == nil || run {
		t.Fatal("failed acceptance executed effect", err)
	}
	if sourceCount(t, j, "worker_terminal_reservations") != 0 {
		t.Fatal("failed acceptance stranded budget")
	}
	j.db.Exec(`DROP TRIGGER fail_accept`)
	out, run, err := j.admit(ctx, a, 1, "original-command-A", "prompt", json.RawMessage(`{}`), authorize)
	if err != nil || !run || out.SourceAdmission == nil || sourceCount(t, j, "worker_terminal_reservations") != 1 {
		t.Fatal("native effect lacks durable original reservation", err)
	}
	// Accepted native binding still has no genuine final capture: outcome
	// settlement alone must not free this original producer's future budget.
	if err = j.BindNativeTurn(ctx, NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "original-A", NativeSessionID: "session-A", SourceCommandID: "original-command-A", SourceAdmissionID: "original-admission-A", InputKind: "task"}); err != nil {
		t.Fatal(err)
	}
	if err = j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, run, err = j.admit(ctx, a, 2, "new-command-B", "prompt", json.RawMessage(`{}`), authorize); !errors.Is(err, ErrFull) || run {
		t.Fatal("later effect stole pending original source budget", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	b := lease(t, j)
	if _, run, err = j.admit(ctx, b, 1, "original-command-A", "prompt", json.RawMessage(`{}`), authorize); err != nil || run {
		t.Fatal("reconnect replayed original effect", err)
	}
	if sourceCount(t, j, "worker_terminal_reservations") != 1 {
		t.Fatal("reopen discarded accepted source claim")
	}
	if _, err = j.db.Exec(`UPDATE worker_terminal_reservations SET capture_left=-1`); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	if corrupt, err := OpenJournal(dir, testScope()); err == nil {
		corrupt.Close()
		t.Fatal("negative reservation reopened to authorize new effects")
	}
}
