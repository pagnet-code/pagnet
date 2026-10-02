package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// NativeTaskReadResult decrypts only an already-authorized task_get response.
// The caller passes the worker's bound turn descriptor, never tool arguments.
// The original target must still match the full immutable original input AAD.
func (d *Daemon) NativeTaskReadResult(ctx context.Context, row *InstanceRow, tool string, args, raw json.RawMessage, original *transport.NativeTaskSource) (json.RawMessage, string) {
	if tool != "network_task_get" {
		return raw, ""
	}
	var request struct {
		TaskID string `json:"taskId"`
	}
	var result map[string]json.RawMessage
	var task domain.Task
	if row == nil || json.Unmarshal(args, &request) != nil || request.TaskID == "" || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result["task"], &task) != nil || task.ID.String() != request.TaskID || row.NetworkID == "" || task.NetworkID.String() != row.NetworkID {
		return nil, "task read identity differs from authorized request"
	}
	originalTarget := original != nil && original.TaskID == request.TaskID
	envelopeRaw, encrypted := task.Metadata["e2ee_envelope"]
	if !encrypted {
		if originalTarget {
			return nil, "original task encrypted input unavailable"
		}
		return raw, ""
	}
	var envelope e2ee.EncryptedPayloadV1
	var aad e2ee.AAD
	envelopeJSON, _ := json.Marshal(envelopeRaw)
	aadJSON, _ := json.Marshal(task.Metadata["e2ee_aad"])
	if json.Unmarshal(envelopeJSON, &envelope) != nil || json.Unmarshal(aadJSON, &aad) != nil || aad.ValidateScope() != nil || aad.ProtectedContext != nil || aad.NetworkID != row.NetworkID || aad.ObjectID != request.TaskID || aad.ObjectType != e2ee.ObjectTypeTask || aad.KeyEpochID != envelope.KeyEpochID || aad.TenantID == "" {
		return nil, "task read authenticated input differs from its identity"
	}
	if originalTarget && !bytes.Equal(aad.CanonicalBytes(), original.InputAAD.CanonicalBytes()) {
		return nil, "original task input changed after accepted command"
	}
	var plain []byte
	err := hostcrypto.WithNetworkKeyring(ctx, d.StateDir, row.NetworkID, func(ring *hostcrypto.Keyring) error {
		epoch, available := ring.EpochByID(aad.KeyEpochID)
		if !available || epoch.State == hostcrypto.EpochRevoked {
			return errors.New("task content authority unavailable")
		}
		key, err := epoch.KeyArray()
		if err != nil {
			return err
		}
		defer clear(key[:])
		plain, err = e2ee.Decrypt(envelope, key, aad)
		return err
	})
	if err != nil {
		return nil, "task content could not be authenticated"
	}
	defer clear(plain)
	content, err := domain.DecodeTaskContent(string(plain))
	if err != nil {
		return nil, "task content format is invalid"
	}
	task.Objective = content.Objective
	delete(task.Metadata, "e2ee_envelope")
	delete(task.Metadata, "e2ee_aad")
	if len(content.Attachments) > 0 {
		task.Metadata["attachments"] = content.Attachments
	}
	result["task"], err = json.Marshal(task)
	if err != nil {
		return nil, "task content response is invalid"
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, "task content response is invalid"
	}
	return out, ""
}
