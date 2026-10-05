package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestHostedOriginalProjectionPinsOriginalEpochAndSource(t *testing.T) {
	stateDir := t.TempDir()
	network := domain.NewID().String()
	ring := hostcrypto.NewKeyring(network)
	epoch, err := ring.Activate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := epoch.KeyArray()
	profile := fabricagent.HostedProfile{DefinitionID: domain.NewID().String(), PrincipalID: domain.NewID().String(), NetworkID: network, OwnershipID: domain.NewID().String(), NativeProfile: sha256.Sum256([]byte("original")), WorkerDirectory: filepath.Join(stateDir, "original"), Scope: sessionworker.Scope{ServerURL: "https://app.pagnet.dev", TenantID: domain.NewID().String(), AccountID: domain.NewID().String(), HostID: domain.NewID().String(), InstanceID: domain.NewID().String(), Generation: "original"}}
	id := domain.NewID().String()
	inputAAD := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: profile.Scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: id, Sender: "original-caller", Recipient: profile.Scope.InstanceID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyEpochID: epoch.ID}
	source := sessionworker.NativeTurnSource{Sequence: 1, LogicalTurnID: "original-turn", NativeGeneration: "genuine-native-generation", NativeSessionID: "genuine-original-session", SourceCommandID: domain.NewID().String(), SourceAdmissionID: domain.NewID().String(), InputKind: "invocation", SourceInvocation: &transport.NativeInvocationSource{InvocationID: id, InputAAD: inputAAD}}
	aad := inputAAD
	aad.ObjectType = e2ee.ObjectTypeInvocationOutput
	aad.Sender = profile.Scope.InstanceID
	rangeValue := sessionworker.InvocationStreamRange{Source: source, Ordinal: 1, Data: []byte("original assistant content")}
	plain, _ := json.Marshal(rangeValue)
	env, err := e2ee.Encrypt(plain, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	projection := sessionworker.InvocationStreamProjection{Ordinal: 1, AAD: aad, Ciphertext: env}
	digest := func(p *sessionworker.InvocationStreamProjection) {
		p.Digest = ""
		raw, _ := json.Marshal(p)
		sum := sha256.Sum256(raw)
		p.Digest = hex.EncodeToString(sum[:])
	}
	digest(&projection)
	if _, err = ring.Rotate(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = hostcrypto.SaveKeyring(stateDir, ring); err != nil {
		t.Fatal(err)
	}
	host := &Daemon{Config: Config{StateDir: stateDir}}
	got, err := host.OpenHostedOriginalProjection(profile, source, projection)
	if err != nil || !bytes.Equal(got.Data, rangeValue.Data) {
		t.Fatal("rotated original epoch history", err)
	}
	changedSource := source
	changedSource.NativeSessionID = "different-session"
	if _, err = host.OpenHostedOriginalProjection(profile, changedSource, projection); err == nil {
		t.Fatal("transplanted session")
	}
	wrongNetwork := profile
	wrongNetwork.NetworkID = domain.NewID().String()
	if _, err = host.OpenHostedOriginalProjection(wrongNetwork, source, projection); err == nil {
		t.Fatal("cross-network output")
	}
	changedProjection := projection
	newEpoch, _ := ring.ActiveEpoch()
	changedProjection.AAD.KeyEpochID = newEpoch.ID
	digest(&changedProjection)
	if _, err = host.OpenHostedOriginalProjection(profile, source, changedProjection); err == nil {
		t.Fatal("active epoch substituted for pinned original epoch")
	}
	changedProjection = projection
	changedProjection.Ordinal = 2
	digest(&changedProjection)
	if _, err = host.OpenHostedOriginalProjection(profile, source, changedProjection); err == nil {
		t.Fatal("outer cursor substitution")
	}
}
