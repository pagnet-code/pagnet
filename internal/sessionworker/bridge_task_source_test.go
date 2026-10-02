package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/session"
	"github.com/pagnet-code/pagnet/transport"
)

func TestBridgeTaskSourceRequiresActualBoundTurnAndOriginalProducerPin(t *testing.T) {
	j, _ := testJournal(t)
	ctx := context.Background()
	current := lease(t, j)
	dir := t.TempDir()
	network := uuid.NewString()
	task := uuid.NewString()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{journal: j, manager: session.NewManager(), generation: "original-gen", spec: NativeSpec{NetworkID: network, NetworkTenantID: j.scope.TenantID, NetworkStateDir: dir}}
	sess := owner.manager.Session(j.scope.InstanceID, domain.RuntimeFakePersistent, "workspace")
	sess.NativeID = "actual-original-session"
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: owner.generation, NativeSessionID: sess.NativeID, SourceCommandID: "original-command", SourceAdmissionID: "original-admission", InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: task, InputAAD: e2ee.AAD{TenantID: j.scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeTask, ObjectID: task, KeyEpochID: epoch.ID}}}
	owner.candidateTurnSource = source
	owner.pinOriginalTaskContent(source)
	if got := owner.activeBridgeTurnSource(ctx, owner.generation); got != nil {
		t.Fatal("unbound candidate granted task source")
	}
	if _, _, err = j.Admit(ctx, current, 1, "original-command", "prompt", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.BindNativeTurn(ctx, source); err != nil {
		t.Fatal(err)
	}
	got := owner.activeBridgeTurnSource(ctx, owner.generation)
	if got == nil || got.SourceCommandID != source.SourceCommandID || !bytes.Equal(got.SourceTask.InputAAD.CanonicalBytes(), source.SourceTask.InputAAD.CanonicalBytes()) {
		t.Fatal("actual original source not forwarded")
	}
	got.SourceTask.InputAAD.KeyEpochID = "mutated callback copy"
	if next := owner.activeBridgeTurnSource(ctx, owner.generation); next == nil || next.SourceTask.InputAAD.KeyEpochID != epoch.ID {
		t.Fatal("call mutated original producer descriptor")
	}
	if got = owner.activeBridgeTurnSource(ctx, "replacement-generation"); got != nil {
		t.Fatal("replacement native callback inherited original source")
	}
	owner.releaseNativeTaskTurnPin(&source)
	if got = owner.activeBridgeTurnSource(ctx, owner.generation); got != nil {
		t.Fatal("settled native callback resurrected original task authority")
	}
}
