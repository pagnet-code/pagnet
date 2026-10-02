package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeTaskReadPinsOriginalAADBeforePrivateDecryption(t *testing.T) {
	d, network, epoch := newLaunchCryptoDaemon(t, t.TempDir())
	id := domain.NewID()
	secret := "actual private original task"
	env, aad, err := d.encryptProtected(NetworkCryptoState{TenantID: "tenant", NetworkID: network, EpochID: epoch}, e2ee.ObjectTypeTask, id.String(), "sender", "recipient", secret)
	if err != nil {
		t.Fatal(err)
	}
	source := &transport.NativeTaskSource{TaskID: id.String(), InputAAD: aad}
	args, _ := json.Marshal(map[string]string{"taskId": id.String()})
	row := &InstanceRow{NetworkID: network}
	result := func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"task": domain.Task{ID: id, NetworkID: domain.ID(network), Metadata: map[string]any{"e2ee_envelope": env, "e2ee_aad": aad}}, "history": []any{}})
		return raw
	}
	raw := result(env, aad)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("fixture plaintext reached relay")
	}
	out, msg := d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, raw, source)
	if msg != "" || !bytes.Contains(out, []byte(secret)) || bytes.Contains(out, []byte("e2ee_envelope")) {
		t.Fatal("original task not privately decrypted", msg)
	}
	changed := *source
	changed.InputAAD.Sender = "mutable replacement sender"
	if out, msg = d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, raw, &changed); out != nil || msg == "" {
		t.Fatal("original AAD replacement exposed content")
	}
	changed = *source
	changed.InputAAD.KeyEpochID = "replacement epoch"
	if out, msg = d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, raw, &changed); out != nil || msg == "" {
		t.Fatal("original epoch replacement exposed content")
	}
	env.Ciphertext = "corrupt"
	if out, msg = d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, result(env, aad), source); out != nil || msg == "" {
		t.Fatal("corrupt task exposed content")
	}
	if out, msg = d.NativeTaskReadResult(context.Background(), &InstanceRow{NetworkID: "foreign"}, "network_task_get", args, raw, source); out != nil || msg == "" {
		t.Fatal("foreign task exposed content")
	}
	plain, _ := json.Marshal(map[string]any{"task": domain.Task{ID: id, NetworkID: domain.ID(network), Objective: "unauthenticated replacement"}})
	if out, msg = d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, plain, source); out != nil || msg == "" {
		t.Fatal("original task plaintext fallback exposed content")
	}
	other := *source
	other.TaskID = domain.NewID().String()
	if out, msg = d.NativeTaskReadResult(context.Background(), row, "network_task_get", args, raw, &other); msg != "" || !bytes.Contains(out, []byte(secret)) {
		t.Fatal("other currently authorized encrypted task read lost", msg)
	}
}
