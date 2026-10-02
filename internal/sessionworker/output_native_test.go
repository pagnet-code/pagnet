//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
)

func TestActualTinyNativeOutputFullOrdinaryQuotaCompletesReopensAndStops(t *testing.T) {
	runActualNativeReservedSource(t, false, false)
}
func TestActualNativeResourceCaptureLimitRetainsPrefixAndGenuineOriginalEOF(t *testing.T) {
	runActualNativeReservedSource(t, true, false)
}
func TestActualNativeDeclaredOutputOverflowPreservesBoundedPrefixAndGenuineEOF(t *testing.T) {
	runActualNativeReservedSource(t, true, true)
}
func runActualNativeReservedSource(t *testing.T, resourceLimit bool, outputOverflow bool) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "b", "bin", "native")
	if err = os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	testBinary(t, root, binary, "./cmd/pagnet-fake-runtime", "")
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	dir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	keydir := t.TempDir()
	network := uuid.NewString()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	private := bytes.Repeat([]byte{7}, 32)
	chunkBytes := "8"
	if resourceLimit {
		chunkBytes = "65536"
	}
	extraEnv := []string{"PAGNET_FAKE_OUTPUT_CHUNK_BYTES=" + chunkBytes, "PAGNET_FAKE_FULL_OUTPUT=1"}
	if !resourceLimit {
		extraEnv = append(extraEnv, "PAGNET_FAKE_FINAL_OUTPUT=1")
	}
	if outputOverflow {
		extraEnv = append(extraEnv, "PAGNET_FAKE_OUTPUT_REPEAT=256")
	}
	owner, err := NewSessionOwner(context.Background(), j, NativeSpec{Runtime: domain.RuntimeFakePersistent, Binary: binary, MCPExecutable: binary, Workspace: t.TempDir(), NetworkID: network, NetworkTenantID: j.scope.TenantID, NetworkStateDir: keydir, TenantID: j.scope.TenantID, Kind: "worker", Env: extraEnv}, private)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.generation = "actual-original-A"
	origin := uuid.NewString()
	owner.origin = json.RawMessage(`{"id":"` + origin + `","instanceId":"` + j.scope.InstanceID + `","runtime":"fake-persistent","nativeGeneration":"actual-original-A"}`)
	owner.sess.Env, err = owner.launchEnvironment("private-fixture-nonce")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if _, err = owner.driver.Activate(ctx, owner.sess, make(chan session.SessionEvent, 64)); err != nil {
		t.Fatal(err)
	}
	sid := owner.sess.NativeID
	task := uuid.NewString()
	source := NativeTurnSource{Sequence: 1, SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: j.scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	leaseA := lease(t, j)
	if _, _, err = j.Admit(ctx, leaseA, 1, "actual-accepted-source-A", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Reserve before any native accepted effect. Admission integration invokes
	// this same transaction helper for actual original controller admissions.
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
	owner.candidateTurnSource = source
	if resourceLimit && !outputOverflow {
		// Model exhausted declared prefix capacity. The actual parsed original
		// tail must use unused final reserve after FULL resource marker, then EOF.
		if _, err = j.db.Exec(`UPDATE worker_terminal_reservations SET content_left=? WHERE sequence=1`, terminalContentReserveBytes/2); err != nil {
			t.Fatal(err)
		}
	}
	var producer *nativeSourceProducer
	j.mu.Lock()
	for p := range j.sourceProducers {
		producer = p
	}
	j.mu.Unlock()
	if producer == nil {
		t.Fatal("no actual original native producer")
	}
	// Pressure is synthetic; all accepted source callbacks below and EOF are
	// emitted and parsed from a genuine independent native subprocess.
	// Build bounded synthetic pressure in one FULL transaction, to avoid
	// thousands of unrelated fsync/query scans hiding native callback behavior.
	tx, err = j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var count, total int
	if err = tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size),0)+(SELECT COALESCE(SUM(size),0) FROM worker_source_captures) FROM worker_observations`).Scan(&count, &total); err != nil {
		t.Fatal(err)
	}
	total += count*sourceDispositionReserveBytes + sourceStopReserveBytes + terminalCaptureReserveBytes
	for n := 0; n < maxPendingObservations; n++ {
		o := NativeObservation{ID: uuid.NewString(), NativeGeneration: producer.generation, NativeSessionID: sid, Origin: producer.origin, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: sid}}
		o.SourceDigest, _ = observationDigest(o)
		raw, _ := json.Marshal(o)
		if count+1+terminalSourceReserveRows >= maxPendingObservations || total+len(raw)+sourceDispositionReserveBytes > maxPendingObservationBytes {
			break
		}
		if _, err = tx.Exec(`INSERT INTO worker_observations(id,digest,payload,size) VALUES(?,?,?,?)`, o.ID, o.SourceDigest, raw, len(raw)); err != nil {
			t.Fatal(err)
		}
		count++
		total += len(raw) + sourceDispositionReserveBytes
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	extra := NativeObservation{ID: uuid.NewString(), NativeGeneration: producer.generation, NativeSessionID: sid, Origin: producer.origin, ObservedAt: time.Now().UTC(), Event: session.SessionEvent{Type: session.EventPlanUpdated, SessionID: sid}}
	extra.SourceDigest, _ = observationDigest(extra)
	if err = j.journalCapturedObservation(ctx, producer, extra, nil); !errors.Is(err, ErrFull) {
		t.Fatal("ordinary setup did not exercise full quota", err)
	}
	events := make(chan session.SessionEvent, 64)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range events {
		}
	}()
	input := strings.Repeat("tiny-original-private ", 1800)
	if outputOverflow {
		input = strings.Repeat("tiny-original-private ", 1900)
	}
	wrapped := &ownedDriver{Driver: owner.driver, owner: owner}
	err = wrapped.Submit(ctx, owner.sess, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: logicalWorkerTurn(1), InputKind: "task", Input: input}, events)
	if !resourceLimit && err != nil {
		t.Fatal("accepted genuine source stranded by ordinary quota", err)
	}
	if resourceLimit && !errors.Is(err, session.ErrTurnInterrupted) {
		t.Fatal("resource stop invented successful/vendor outcome", err)
	}
	close(events)
	<-drained
	owner.Close()
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	leaseB := lease(t, j)
	rows, err := j.db.Query(`SELECT payload FROM worker_observations ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	var observations []NativeObservation
	for rows.Next() {
		var raw []byte
		var o NativeObservation
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			t.Fatal(err)
		}
		observations = append(observations, o)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	key, _ := epoch.KeyArray()
	var text, finalText bytes.Buffer
	chunks, completed, stopped := 0, 0, 0
	var interruption *transport.NativeResourceInterruption
	for _, o := range observations {
		if o.Event.Type == session.EventSessionStopped {
			stopped++
			interruption = o.ResourceInterruption
			if o.NativeGeneration != producer.generation || o.NativeSessionID != sid {
				t.Fatal("EOF changed source")
			}
		}
		if o.Event.Type == session.EventTurnCompleted {
			completed++
		}
		if o.OutputContent == nil {
			continue
		}
		if o.Event.Type == session.EventTurnCompleted {
			if o.OutputStream != nil {
				t.Fatal("final native body masqueraded as stream batch")
			}
			var finalFragments []transport.NativeContentFragment
			for ordinal := 0; ordinal < o.OutputContent.FragmentCount; ordinal++ {
				f, readErr := j.ReadContentFragment(ctx, leaseB, o.ID, o.SourceDigest, o.OutputContent.ContentID, ordinal)
				if readErr != nil {
					t.Fatal(readErr)
				}
				finalFragments = append(finalFragments, *f)
			}
			plain, _, openErr := nativecontent.Open(*o.OutputContent, finalFragments, key)
			if openErr != nil {
				t.Fatal(openErr)
			}
			finalText.Write(plain)
			continue
		}
		chunks++
		if o.OutputStream == nil || (!resourceLimit && o.OutputStream.DeltaCount <= 4096) || o.OutputStream.ByteOffset != int64(text.Len()) {
			t.Fatal("tiny parser delta provenance/ordered range lost", o.OutputStream)
		}
		f, err := j.ReadContentFragment(ctx, leaseB, o.ID, o.SourceDigest, o.OutputContent.ContentID, 0)
		if err != nil {
			t.Fatal(err)
		}
		plain, _, err := nativecontent.Open(*o.OutputContent, []transport.NativeContentFragment{*f}, key)
		if err != nil {
			t.Fatal(err)
		}
		text.Write(plain)
	}
	expected := fmt.Sprintf("[fake-persist task] handled %s: %s", input, input)
	if resourceLimit {
		expectedCause := transport.NativeResourceCaptureLimit
		if outputOverflow {
			expected = strings.Repeat(expected, 256)[:transport.NativeContentMaxPlaintextBytes]
			expectedCause = transport.NativeResourceOutputLimit
		} else {
			expected = expected[:65536]
		}
		if completed != 0 || stopped != 1 || interruption == nil || interruption.Cause != expectedCause || interruption.Source.SourceCommandID != source.SourceCommandID || interruption.Source.SourceAdmissionID != source.SourceAdmissionID || interruption.Source.NativeGeneration != producer.generation || interruption.Source.SessionID != sid || interruption.Source.LogicalTurnID != logicalWorkerTurn(1) {
			t.Fatal("original resource EOF source lost or vendor completion fabricated", completed, stopped, interruption)
		}
		if sourceCount(t, j, "worker_resource_interruptions") != 1 || sourceCount(t, j, "worker_output_spools") != 1 {
			t.Fatal("resource stop discarded retained original evidence")
		}
	} else if completed != 1 || interruption != nil || finalText.String() != expected {
		t.Fatal("genuine completion/final output changed", completed, interruption, finalText.Len(), len(expected))
	}
	if text.String() != expected || (!outputOverflow && chunks > 3) || (outputOverflow && chunks != 320) || stopped != 1 {
		t.Fatal("genuine bounded source completion lost", text.Len(), len(expected), chunks, completed, stopped)
	}
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		if bytes.Contains(raw, []byte("tiny-original-private")) {
			t.Fatal("private native output leaked")
		}
	}
}
