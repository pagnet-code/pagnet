package sessionworker

import (
	"bytes"
	"encoding/json"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/nativecontent"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestOriginalTaskContentProducerUsesAcceptedEpochAndStableTurn(t *testing.T) {
	instance := "00000000-0000-0000-0000-000000000004"
	source := &NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "native-original", NativeSessionID: "native-session", SourceCommandID: "00000000-0000-0000-0000-000000000008", SourceAdmissionID: "00000000-0000-0000-0000-000000000009", InputKind: "task", SourceTask: &transport.NativeTaskSource{TaskID: "00000000-0000-0000-0000-000000000003", InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: "tenant", NetworkID: "network", ObjectType: e2ee.ObjectTypeTask, ObjectID: "00000000-0000-0000-0000-000000000003", KeyEpochID: "epoch-original-A"}}}
	observation := NativeObservation{ID: "00000000-0000-0000-0000-000000000006", NativeGeneration: source.NativeGeneration, NativeSessionID: source.NativeSessionID, Origin: json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000007"}`), ObservedAt: time.Now().UTC(), TurnSource: source}
	plain := bytes.Repeat([]byte("private original native output\n"), 5000)
	transfer, err := buildOriginalTurnContent(observation, instance, "native_turn_output", "text/plain; charset=utf-8", plain, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if transfer.Reference.ManifestAAD.KeyEpochID != "epoch-original-A" || len(transfer.Fragments) < 2 {
		t.Fatal("producer lost original epoch or full output")
	}
	opened, _, err := nativecontent.Open(transfer.Reference, transfer.Fragments, [32]byte{1})
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("original output lost", err)
	}
	raw, _ := json.Marshal(transfer)
	if bytes.Contains(raw, []byte("private original native output")) {
		t.Fatal("plaintext output exposed")
	}
	broken := observation
	copy := *source
	broken.TurnSource = &copy
	copy.NativeSessionID = "replacement-session"
	if _, err = buildOriginalTurnContent(broken, instance, "native_turn_output", "text/plain", plain, [32]byte{1}); err == nil {
		t.Fatal("replacement session obtained original task content")
	}
}
