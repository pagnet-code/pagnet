package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestActualProducerTaskTextAndPlanOriginalCipherSurviveRotationReopen(t *testing.T) {
	ctx := context.Background()
	scope := testScope()
	scope.InstanceID = uuid.NewString()
	dir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	network := uuid.NewString()
	keydir := t.TempDir()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	task := uuid.NewString()
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "original-native-A", NativeSessionID: "authentic-native-session", SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: bytes.Repeat([]byte{3}, 32), manager: session.NewManager(), generation: source.NativeGeneration, origin: json.RawMessage(`{"id":"` + uuid.NewString() + `","nativeGeneration":"original-native-A"}`), spec: NativeSpec{NetworkID: network, NetworkTenantID: scope.TenantID, NetworkStateDir: keydir}, pending: map[string]*nativeApproval{}}
	owner.manager.Session(scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	current := lease(t, j)
	if _, _, err = j.Admit(ctx, current, 1, "original-task-operation", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.reserveTerminalTx(ctx, tx, source.Sequence, "prompt"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	owner.pinOriginalTaskContent(source)
	registration := owner.nativeEventRegistration(scope.InstanceID)
	emit := func(event session.SessionEvent) {
		t.Helper()
		event.SessionID = source.NativeSessionID
		event.TurnID = source.LogicalTurnID
		if err := registration.Observe(event); err != nil {
			t.Fatal(err)
		}
	}
	emit(session.SessionEvent{Type: session.EventTurnStarted})
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("private original output €\n"), 4000)
	emit(session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, Output: string(secret)})
	emit(session.SessionEvent{Type: session.EventTurnOutput, Output: "diagnostic note must remain transient"})
	plan := &session.PlanSnapshot{Source: "codex", NativeTurnID: "actual-vendor-turn", Entries: []session.PlanEntry{{Text: "private original plan", Status: "in_progress"}}}
	emit(session.SessionEvent{Type: session.EventPlanUpdated, Plan: plan})
	emit(session.SessionEvent{Type: session.EventTurnCompleted})
	if err = j.Settle(ctx, 1, "completed", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	retained := sourceCount(t, j, "worker_observations")
	// A full genuine final capture releases unused future capacity, while
	// every original source cipher remains unacknowledged and recoverable.
	if _, run, err := j.admit(ctx, current, 2, "next-original-operation", "prompt", json.RawMessage(`{}`), func() (*Admission, error) { return &Admission{Scope: scope}, nil }); err != nil || !run {
		t.Fatal("captured final kept unused capacity hostage", err)
	}
	if sourceCount(t, j, "worker_observations") != retained {
		t.Fatal("capacity release deleted original evidence")
	}
	registration.Retire()
	owner.nativeObserverWG.Wait()
	if len(owner.taskContentPins) != 0 {
		t.Fatal("terminal/retired producer retained task key")
	}
	rows, err := j.PendingObservations(ctx, 32)
	if err != nil || len(rows) != 5 {
		t.Fatal("native text/plan capture invented or dropped events", err, len(rows))
	}
	for i, o := range rows {
		if o.SourceSequence != int64(i+1) || !reflect.DeepEqual(o.TurnSource.SourceTask, source.SourceTask) {
			t.Fatal("original source or sequence changed")
		}
	}
	if rows[1].OutputContent == nil || rows[3].PlanContent == nil || rows[1].Event.Output != "" || rows[3].Event.Plan != nil {
		t.Fatal("private task content projection leaked or lost original references")
	}
	originals := make([][]byte, len(rows))
	for i, o := range rows {
		originals[i], _ = json.Marshal(o)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	current = lease(t, j)
	rows, err = j.PendingObservationsForLease(ctx, current, 32)
	if err != nil || len(rows) != 5 {
		t.Fatal(err)
	}
	key, _ := epoch.KeyArray()
	var reconstructed bytes.Buffer
	for i, o := range rows {
		raw, _ := json.Marshal(o)
		if !bytes.Equal(raw, originals[i]) {
			t.Fatal("reopen changed immutable source/cipher")
		}
		ref := o.OutputContent
		if ref == nil {
			ref = o.PlanContent
		}
		if ref == nil {
			continue
		}
		if ref.ManifestAAD.KeyEpochID != epoch.ID || ref.ManifestAAD.NativeContent.SourceCommandID != source.SourceCommandID || ref.ManifestAAD.NativeContent.SourceAdmissionID != source.SourceAdmissionID {
			t.Fatal("rotation or replacement rebound original authority")
		}
		var fragments []transport.NativeContentFragment
		for n := 0; n < ref.FragmentCount; n++ {
			f, err := j.ReadContentFragment(ctx, current, o.ID, o.SourceDigest, ref.ContentID, n)
			if err != nil {
				t.Fatal(err)
			}
			fragments = append(fragments, *f)
		}
		opened, mime, err := nativecontent.Open(*ref, fragments, key)
		if err != nil {
			t.Fatal(err)
		}
		if o.OutputContent != nil {
			if mime != "text/plain; charset=utf-8" {
				t.Fatal("original text MIME changed")
			}
			if o.OutputStream == nil || o.OutputStream.ByteOffset != int64(reconstructed.Len()) || o.OutputStream.ByteLength != len(opened) {
				t.Fatal("original captured batch order/provenance lost")
			}
			reconstructed.Write(opened)
		}
		if o.PlanContent != nil {
			var recovered session.PlanSnapshot
			if json.Unmarshal(opened, &recovered) != nil || !reflect.DeepEqual(&recovered, plan) {
				t.Fatal("full original native plan changed")
			}
		}
		cipher, err := j.ReadCaptureChunk(ctx, current, o.ID, o.SourceDigest, 0)
		if err != nil {
			t.Fatal(err)
		}
		original, err := OpenNativeSourceCapture(owner.captureKey, scope, dir, o, cipher.Data)
		if err != nil {
			t.Fatal(err)
		}
		if original.Event.Output != "" || original.Event.Plan != nil {
			t.Fatal("source duplicated full content instead of authenticated complete reference")
		}
	}
	if !bytes.Equal(reconstructed.Bytes(), secret) {
		t.Fatal("full original concatenated native text changed")
	}
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		raw, _ := os.ReadFile(filepath.Join(dir, name))
		if bytes.Contains(raw, []byte("private original output")) || bytes.Contains(raw, []byte("private original plan")) {
			t.Fatal("private task body leaked to SQLite")
		}
	}
}

func TestMissingOriginalTaskEpochRejectsNativeEffectBeforeTurnBinding(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	a := lease(t, j)
	if _, _, err := j.Admit(ctx, a, 1, "task-operation", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	driver := &provenanceSubmitDriver{}
	source := NativeTurnSource{Sequence: 1, SourceCommandID: "command", SourceAdmissionID: "admission", InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: "task", InputAAD: e2ee.AAD{ObjectType: e2ee.ObjectTypeTask, ObjectID: "task", NetworkID: "network", KeyEpochID: "unavailable-original"}}}
	owner := &SessionOwner{journal: j, generation: "native", candidateTurnSource: source}
	wrapped := &ownedDriver{Driver: driver, owner: owner}
	if err := wrapped.Submit(ctx, &session.RuntimeSession{NativeID: "session"}, session.SubmitRequest{Kind: session.SubmitPrompt, TurnID: logicalWorkerTurn(1)}, nil); err == nil {
		t.Fatal("native task accepted without original crypto authority")
	}
	if driver.effects.Load() != 0 {
		t.Fatal("native effect preceded original key authority")
	}
	var count int
	if err := j.db.QueryRow(`SELECT count(*) FROM worker_turn_sources`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unaccepted native task invented durable turn source", err)
	}
	if err := j.BindNativeTurn(ctx, NativeTurnSource{}); !errors.Is(err, ErrConflict) && err == nil {
		t.Fatal("invalid source accepted")
	}
}
