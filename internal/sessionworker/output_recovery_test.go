//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestCapturedOutputPreparedCipherRollbackReopenOriginalEpochOnly(t *testing.T) {
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
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "original-A", NativeSessionID: "original-SID-A", SourceCommandID: uuid.NewString(), SourceAdmissionID: uuid.NewString(), InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	key := bytes.Repeat([]byte{11}, 32)
	origin := json.RawMessage(`{"id":"` + uuid.NewString() + `","instanceId":"` + scope.InstanceID + `","runtime":"fake-persistent","nativeGeneration":"original-A"}`)
	owner := &SessionOwner{ctx: ctx, journal: j, captureKey: key, manager: session.NewManager(), generation: source.NativeGeneration, origin: origin, spec: NativeSpec{NetworkID: network, NetworkTenantID: scope.TenantID, NetworkStateDir: keydir}, pending: map[string]*nativeApproval{}}
	owner.manager.Session(scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	a := lease(t, j)
	if _, _, err = j.Admit(ctx, a, 1, "original-task-A", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
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
	owner.pinOriginalTaskContent(source)
	reader := owner.nativeEventRegistration(scope.InstanceID)
	if err = reader.Observe(session.SessionEvent{Type: session.EventTurnStarted, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID}); err != nil {
		t.Fatal(err)
	}
	if _, err = j.db.Exec(`CREATE TRIGGER fail_output_projection BEFORE INSERT ON worker_observations WHEN json_extract(NEW.payload,'$.event.Type')='runtime.turn.output' BEGIN SELECT RAISE(ABORT,'isolated projection failure'); END`); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("original private encrypted output €\n", 2200)
	err = reader.Observe(session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, Output: secret})
	if err == nil {
		t.Fatal("aborted source projection invented commit")
	}
	data, _, err := j.readOutputSpool(ctx, key, source.NativeGeneration, source.Sequence)
	if err != nil || data.Ready == nil {
		t.Fatal("failed projection lost original prepared cipher", err)
	}
	originalReady := data.Ready
	originalTransfer, _ := json.Marshal(originalReady.Transfers)
	privateDigest := originalReady.Observation.SourceDigest
	clear(data.Key)
	if sourceCount(t, j, "worker_observations") != 1 {
		t.Fatal("failed projection published source")
	}
	reader.Retire()
	owner.nativeObserverWG.Wait()
	if _, err = j.db.Exec(`DROP TRIGGER fail_output_projection`); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = ring.Rotate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err = ring.Revoke(epoch.ID); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(keydir, ring); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadOriginalTaskKey(owner.spec, source.SourceTask.InputAAD); ok {
		t.Fatal("revoked key still authorizes original input")
	}
	j, err = OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	recovery := &SessionOwner{ctx: ctx, journal: j, captureKey: key, manager: session.NewManager(), generation: "fresh-B", origin: json.RawMessage(`{"id":"fresh-B"}`), spec: owner.spec, pending: map[string]*nativeApproval{}}
	recovery.manager.Session(scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	if err = recovery.recoverCapturedNativeOutput(); err != nil {
		t.Fatal(err)
	}
	b := lease(t, j)
	page, err := j.PendingObservationsForLease(ctx, b, 32)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	found := false
	epochKey, _ := epoch.KeyArray()
	for _, o := range page {
		if o.OutputContent == nil {
			continue
		}
		if o.NativeGeneration != source.NativeGeneration || o.NativeSessionID != source.NativeSessionID || !bytes.Equal(o.Origin, origin) || o.TurnSource.SourceCommandID != source.SourceCommandID || o.TurnSource.SourceAdmissionID != source.SourceAdmissionID || o.OutputContent.ManifestAAD.KeyEpochID != epoch.ID {
			t.Fatal("recovery rewrote original source to freshB")
		}
		var fragments []transport.NativeContentFragment
		for n := 0; n < o.OutputContent.FragmentCount; n++ {
			f, err := j.ReadContentFragment(ctx, b, o.ID, o.SourceDigest, o.OutputContent.ContentID, n)
			if err != nil {
				t.Fatal(err)
			}
			fragments = append(fragments, *f)
		}
		transfer := []nativecontent.Transfer{{Reference: *o.OutputContent, Fragments: fragments}}
		if o.ID == originalReady.Observation.ID {
			current, _ := json.Marshal(transfer)
			if !bytes.Equal(current, originalTransfer) || o.SourceDigest != privateDigest {
				t.Fatal("reopen re-encrypted prepared original ciphertext or digest")
			}
			found = true
		}
		plain, _, err := nativecontent.Open(*o.OutputContent, fragments, epochKey)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(plain)
	}
	if !found || output.String() != secret {
		t.Fatal("recovery lost captured native tail", found, output.Len(), len(secret))
	}
	if len(j.sourceProducers) != 0 {
		t.Fatal("recovery resurrected native producer capability")
	}
	if err = reader.Observe(session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, SessionID: source.NativeSessionID, TurnID: source.LogicalTurnID, Output: "late callback"}); !errors.Is(err, ErrFenced) {
		t.Fatal("oldreader appended after recovery", err)
	}
}
