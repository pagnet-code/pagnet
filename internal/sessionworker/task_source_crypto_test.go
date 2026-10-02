package sessionworker

import (
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestOriginalTaskKeyPinSurvivesRotationAndCannotFollowFreshEpoch(t *testing.T) {
	dir := t.TempDir()
	ring := hostcrypto.NewKeyring("00000000-0000-0000-0000-000000000001")
	original, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	owner := &SessionOwner{spec: NativeSpec{NetworkStateDir: dir, NetworkID: "00000000-0000-0000-0000-000000000001", NetworkTenantID: "tenant-test"}}
	source := NativeTurnSource{NativeGeneration: "native-A", LogicalTurnID: "pagnet-worker-turn-1", SourceTask: &transport.NativeTaskSource{TaskID: "task-test", InputAAD: e2ee.AAD{TenantID: "tenant-test", NetworkID: "00000000-0000-0000-0000-000000000001", ObjectType: e2ee.ObjectTypeTask, ObjectID: "task-test", KeyEpochID: original.ID}}}
	owner.pinOriginalTaskContent(source)
	expected, _ := original.KeyArray()
	fresh, err := ring.Rotate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	owner.pinOriginalTaskContent(source)
	key, ok := owner.originalTaskContentPin(&source)
	if !ok || key != expected {
		t.Fatal("rotation replaced original producer key")
	}
	changed := source
	changed.SourceTask = cloneNativeTaskSource(source.SourceTask)
	changed.SourceTask.InputAAD.KeyEpochID = fresh.ID
	if _, ok = owner.originalTaskContentPin(&changed); ok {
		t.Fatal("fresh admission descriptor inherited old producer pin")
	}
	if err = ring.Revoke(original.ID); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	if _, ok = loadOriginalTaskKey(owner.spec, source.SourceTask.InputAAD); ok {
		t.Fatal("new producer accepted revoked epoch")
	}
	owner.releaseNativeTaskPins("native-A")
	if _, ok = owner.originalTaskContentPin(&source); ok || len(owner.taskContentPins) != 0 {
		t.Fatal("retired producer retained usable key")
	}
	wrong := source.SourceTask.InputAAD
	wrong.NetworkID = "foreign-network"
	if _, ok = loadOriginalTaskKey(owner.spec, wrong); ok {
		t.Fatal("foreign original task key accepted")
	}
}
