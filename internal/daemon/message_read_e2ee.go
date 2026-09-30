package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// Message read tools return ciphertext from the relay. Only this authorized
// local edge may turn it into content for the runtime, just like delivery.
func (d *Daemon) decryptMessageToolResult(row *InstanceRow, tool string, raw json.RawMessage) (json.RawMessage, string) {
	if tool != "network_inbox" && tool != "control_get_thread" && tool != "control_get_history" {
		return raw, ""
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, "invalid message read response"
	}
	var messages []domain.Message
	if err := json.Unmarshal(result["messages"], &messages); err != nil {
		return nil, "invalid message read response"
	}
	changed := false
	for index := range messages {
		m := &messages[index]
		envRaw, encrypted := m.Metadata["e2ee_envelope"]
		if !encrypted {
			continue
		}
		var env e2ee.EncryptedPayloadV1
		var aad e2ee.AAD
		envJSON, err := json.Marshal(envRaw)
		if err != nil || json.Unmarshal(envJSON, &env) != nil {
			return nil, "invalid encrypted message envelope"
		}
		aadRaw, ok := m.Metadata["e2ee_aad"]
		if !ok {
			return nil, "encrypted message has no authenticated context"
		}
		aadJSON, err := json.Marshal(aadRaw)
		if err != nil || json.Unmarshal(aadJSON, &aad) != nil || aad.ObjectType != e2ee.ObjectTypeMessage || aad.ObjectID != m.ID.String() || aad.NetworkID != m.NetworkID.String() || (row.NetworkID != "" && row.NetworkID != m.NetworkID.String()) {
			return nil, "encrypted message authenticated context does not match its identity"
		}
		// Sender/recipient and all other AAD fields are relayed verbatim.
		// Reconstructing them would invalidate authentication or invent context.
		plain, err := d.decryptProtected(m.NetworkID.String(), env, aad)
		if err != nil {
			return nil, fmt.Sprintf("cannot decrypt message %s: %v", m.ID, err)
		}
		m.Parts, err = domain.DecodeMessageContent([]byte(plain))
		if err != nil {
			return nil, fmt.Sprintf("invalid message %s content: %v", m.ID, err)
		}
		changed = true
		delete(m.Metadata, "e2ee_envelope")
		delete(m.Metadata, "e2ee_aad")
	}
	if !changed {
		return raw, ""
	}
	var err error
	result["messages"], err = json.Marshal(messages)
	if err != nil {
		return nil, "invalid decrypted message response"
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, "invalid decrypted message response"
	}
	return out, ""
}
