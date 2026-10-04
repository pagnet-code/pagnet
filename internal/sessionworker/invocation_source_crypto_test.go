package sessionworker

import (
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestOriginalInvocationKeyPinSurvivesRotationAndCannotFollowFreshEpoch(t *testing.T) {
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
	source := NativeTurnSource{NativeGeneration: "native-A", LogicalTurnID: "pagnet-worker-turn-1", InputKind: "invocation", SourceInvocation: &transport.NativeInvocationSource{InvocationID: "invocation-test", InputAAD: e2ee.AAD{TenantID: "tenant-test", NetworkID: "00000000-0000-0000-0000-000000000001", ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "invocation-test", KeyEpochID: original.ID}}}
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
	changed.SourceInvocation = cloneNativeInvocationSource(source.SourceInvocation)
	changed.SourceInvocation.InputAAD.KeyEpochID = fresh.ID
	if _, ok = owner.originalTaskContentPin(&changed); ok {
		t.Fatal("fresh admission descriptor inherited old producer pin")
	}
	if err = ring.Revoke(original.ID); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	if _, ok = loadOriginalTaskKey(owner.spec, source.SourceInvocation.InputAAD); ok {
		t.Fatal("new producer accepted revoked epoch")
	}
	owner.releaseNativeTaskPins("native-A")
	if _, ok = owner.originalTaskContentPin(&source); ok || len(owner.taskContentPins) != 0 {
		t.Fatal("retired producer retained usable key")
	}
	wrong := source.SourceInvocation.InputAAD
	wrong.NetworkID = "foreign-network"
	if _, ok = loadOriginalTaskKey(owner.spec, wrong); ok {
		t.Fatal("foreign original task key accepted")
	}
}

func TestInvocationProtectedContextCannotReadForeignAuthority(t *testing.T) {
	context := &e2ee.ProtectedContext{Kind: e2ee.OwnerContextKind, ID: "00000000-0000-0000-0000-000000000001", TenantID: "00000000-0000-0000-0000-000000000002", OwnerUserID: "00000000-0000-0000-0000-000000000003", HostID: "00000000-0000-0000-0000-000000000004"}
	dir := t.TempDir()
	ring := &hostcrypto.ContextKeyring{Context: *context}
	epoch, err := ring.Activate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := hostcrypto.SaveContextKeyring(dir, ring); err != nil {
		t.Fatal(err)
	}
	spec := NativeSpec{ProtectedContext: context, ContextStateDir: dir}
	aad := e2ee.AAD{TenantID: context.TenantID, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "invocation", KeyEpochID: epoch.ID, ProtectedContext: context}
	expected, _ := epoch.KeyArray()
	if key, available := loadOriginalTaskKey(spec, aad); !available || key != expected {
		t.Fatal("exact original context unavailable")
	}
	foreign := *context
	foreign.HostID = "00000000-0000-0000-0000-000000000005"
	aad.ProtectedContext = &foreign
	if _, available := loadOriginalTaskKey(spec, aad); available {
		t.Fatal("foreign context inherited source key")
	}
	aad.ProtectedContext = context
	aad.NetworkID = "network"
	if _, available := loadOriginalTaskKey(spec, aad); available {
		t.Fatal("network scope acquired private context key")
	}
}
