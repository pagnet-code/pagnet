package daemon

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// handleNetworkCrypto caches the server-announced E2EE lifecycle state for a
// network (host.network_crypto, LIVE). It is the daemon's input for the
// customer-side encryption decision: whether to encrypt (status=active) and
// under which epoch (epochId). A decode failure is dropped (the state is
// re-pushed on the next connect / state change).
func (d *Daemon) handleNetworkCrypto(env transport.Envelope) {
	var p transport.NetworkCryptoPayload
	if err := env.DecodePayload(&p); err != nil || p.NetworkID == "" {
		return
	}
	d.cryptoManager().SetNetworkCrypto(p.NetworkID, NetworkCryptoState{
		TenantID: p.TenantID,
		Status:   p.Status,
		EpochID:  p.EpochID,
	})
}

// errKeyEpochUnavailable is the clean availability error for a send that
// cannot be encrypted: the server-announced epoch is not in the local keyring
// (the host has not yet installed the re-keyed key package). The BINDING
// epoch rule forbids falling back to a newer local epoch — the send fails
// clean and the operator/agent retries once the key package lands.
const errKeyEpochUnavailable = "crypto: key_epoch_unavailable"

// newObjectID mints a client-generated UUIDv7 for a protected object. The ID
// must exist at encryption time (the AAD binds object_id), so the SOURCE
// daemon generates it before the server persists the row; the server adopts
// it. The ID's embedded timestamp is the single clock source for the AAD's
// CreatedAt (see buildAAD).
func newObjectID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// uuid.NewV7 only fails if the system clock is broken; fall back to
		// a random v4 (the AAD's CreatedAt then uses the wall clock).
		id, _ = uuid.NewRandom()
	}
	return id.String()
}

// uuidV7Time extracts the Unix timestamp (milliseconds) embedded in a
// UUIDv7's most-significant 48 bits. For a non-v7 id it returns the zero
// time (buildAAD then falls back to the wall clock).
func uuidV7Time(id uuid.UUID) (time.Time, bool) {
	if id.Version() != 7 {
		return time.Time{}, false
	}
	ms := uint64(id[0])<<40 | uint64(id[1])<<32 | uint64(id[2])<<24 |
		uint64(id[3])<<16 | uint64(id[4])<<8 | uint64(id[5])
	return time.UnixMilli(int64(ms)).UTC(), true
}

// buildAAD builds the AAD for a protected object. objectID is the
// client-generated UUIDv7; its embedded timestamp becomes CreatedAt (the
// single clock source, so the AAD's time and the ID's time agree). The AAD is
// the GCM associated-data: tampering with ANY bound field makes decryption
// fail.
func buildAAD(tenantID, networkID, objectType, objectID, sender, recipient, epochID string) (e2ee.AAD, error) {
	aad := e2ee.AAD{
		ProtocolVersion: e2ee.AADVersion,
		TenantID:        tenantID,
		NetworkID:       networkID,
		ObjectType:      objectType,
		ObjectID:        objectID,
		Sender:          sender,
		Recipient:       recipient,
		KeyEpochID:      epochID,
	}
	if id, err := uuid.Parse(objectID); err == nil {
		if t, ok := uuidV7Time(id); ok {
			aad.CreatedAt = t.Format(time.RFC3339)
		}
	}
	if aad.CreatedAt == "" {
		aad.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return aad, nil
}

// encryptProtected encrypts plaintext for a protected object on an active
// private network, under the server-announced current epoch (st.EpochID). It
// returns the envelope + the AAD used (the server stores/relays both
// verbatim). The BINDING epoch rule: the sender ALWAYS encrypts under the
// announced epoch; if that epoch is absent from the local keyring the send
// fails clean (errKeyEpochUnavailable) — never a fallback to a newer local
// epoch.
func (d *Daemon) encryptProtected(st NetworkCryptoState, objectType, objectID, sender, recipient, plaintext string) (e2ee.EncryptedPayloadV1, e2ee.AAD, error) {
	kr, err := crypto.LoadKeyring(d.StateDir, st.NetworkID)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	epoch, ok := kr.EpochByID(st.EpochID)
	if !ok {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, fmt.Errorf("%s: epoch %s not in local keyring", errKeyEpochUnavailable, st.EpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	aad, err := buildAAD(st.TenantID, st.NetworkID, objectType, objectID, sender, recipient, st.EpochID)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	env, err := e2ee.Encrypt([]byte(plaintext), key, aad)
	if err != nil {
		return e2ee.EncryptedPayloadV1{}, e2ee.AAD{}, err
	}
	return env, aad, nil
}

// decryptProtected decrypts an envelope using the epoch key named by the
// envelope's key_epoch_id (ANY known epoch — history: in-flight deliveries
// under a rotated epoch keep decrypting). aad is the AAD the server relayed
// verbatim; if the server altered any bound field, GCM authentication fails.
func (d *Daemon) decryptProtected(networkID string, env e2ee.EncryptedPayloadV1, aad e2ee.AAD) (string, error) {
	kr, err := crypto.LoadKeyring(d.StateDir, networkID)
	if err != nil {
		return "", err
	}
	epoch, ok := kr.EpochByID(env.KeyEpochID)
	if !ok {
		return "", fmt.Errorf("%s: epoch %s not in local keyring", errKeyEpochUnavailable, env.KeyEpochID)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return "", err
	}
	plain, err := e2ee.Decrypt(env, key, aad)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// encryptedField is the wire shape of one protected field the daemon has
// encrypted before relaying a tool call: the client-generated object id, the
// envelope (ciphertext), and the AAD (relayed verbatim by the server).
type encryptedField struct {
	ID       string                  `json:"id"`
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD      e2ee.AAD                `json:"aad"`
}

// encryptToolArgs rewrites a tool call's protected fields into encryptedField
// values when the instance's network is an active private network. It returns
// the (possibly rewritten) args, or an error message ("" on success). For
// standard networks — or when the daemon has not yet received the network's
// crypto state — the args are returned unchanged (byte-identical standard
// behavior).
//
// The mapping (plan §12):
//   - network_ask / network_reply / control_ask / control_reply: body ->
//     message (recipient = threadId when set, else empty).
//   - network_delegate / control_delegate: objective + title +
//     acceptanceCriteria -> one task envelope (the criteria ride inside).
//   - network_task_update: reason -> task envelope (the blocked reason).
//   - network_publish_artifact: label -> artifact envelope.
func (d *Daemon) encryptToolArgs(row *InstanceRow, tool string, args json.RawMessage) (json.RawMessage, string) {
	if row.NetworkID == "" {
		return args, ""
	}
	st, ok := d.cryptoManager().NetworkCrypto(row.NetworkID)
	if !ok || st.Status != "active" || st.EpochID == "" {
		return args, "" // standard / unknown / not-yet-announced: plaintext
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return args, "" // unparseable: relay as-is (the server validates)
	}
	sender := row.AgentName
	if sender == "" {
		sender = row.InstanceID
	}
	switch tool {
	case "network_ask", "network_reply", "control_ask", "control_reply":
		body, _ := m["body"].(string)
		if body == "" {
			return args, ""
		}
		threadID, _ := m["threadId"].(string)
		id := newObjectID()
		env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeMessage, id, sender, threadID, body)
		if err != nil {
			return nil, err.Error()
		}
		delete(m, "body")
		m["messageId"] = id
		m["envelope"] = env
		m["aad"] = aad
	case "network_delegate", "control_delegate":
		objective, _ := m["objective"].(string)
		if objective == "" {
			return args, ""
		}
		// The protected task text is the objective + title + criteria,
		// encrypted as ONE envelope (a single task object). The criteria are
		// carried inside the envelope so they never cross in plaintext.
		title, _ := m["title"].(string)
		crits, _ := m["acceptanceCriteria"].([]any)
		plain := objective
		if title != "" {
			plain = title + "\n\n" + objective
		}
		if len(crits) > 0 {
			var sb string
			for i, c := range crits {
				if s, ok := c.(string); ok {
					if i > 0 {
						sb += "\n"
					}
					sb += s
				}
			}
			if sb != "" {
				plain += "\n\nAcceptance criteria:\n" + sb
			}
		}
		id := newObjectID()
		env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeTask, id, sender, "", plain)
		if err != nil {
			return nil, err.Error()
		}
		delete(m, "objective")
		delete(m, "title")
		delete(m, "acceptanceCriteria")
		m["taskId"] = id
		m["envelope"] = env
		m["aad"] = aad
	case "network_task_update":
		reason, _ := m["reason"].(string)
		if reason == "" {
			return args, ""
		}
		taskID, _ := m["taskId"].(string)
		if taskID == "" {
			return args, ""
		}
		env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeTask, taskID, sender, "", reason)
		if err != nil {
			return nil, err.Error()
		}
		delete(m, "reason")
		m["reasonEnvelope"] = env
		m["reasonAAD"] = aad
	case "network_publish_artifact":
		label, _ := m["label"].(string)
		if label == "" {
			return args, ""
		}
		id := newObjectID()
		env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeArtifact, id, sender, "", label)
		if err != nil {
			return nil, err.Error()
		}
		delete(m, "label")
		m["artifactId"] = id
		m["labelEnvelope"] = env
		m["labelAAD"] = aad
	default:
		return args, ""
	}
	out, err := json.Marshal(m)
	if err != nil {
		return args, ""
	}
	return out, ""
}

// sendRuntimeOutput emits one non-PTY turn output chunk (host.runtime_output).
// On an active private network the chunk payload is encrypted into an envelope
// (object_type=runtime_output, the per-turn stream id as object id) and the
// server stores ciphertext only; consumers decrypt at the edge (CLI attach in
// p9, browser in p10). Standard networks — or an unknown/not-yet-announced
// crypto state — are byte-identical (plaintext output). A runtime-output
// encryption failure drops the chunk (observational, at-most-once) rather than
// failing the turn: the protected deliverables (messages/tasks) are durably
// encrypted separately.
func (d *Daemon) sendRuntimeOutput(conn *websocket.Conn, row *InstanceRow, streamID, output string) {
	plaintext := map[string]any{"instanceId": row.InstanceID, "output": output}
	if row.NetworkID == "" || streamID == "" {
		_ = d.send(conn, transport.MsgRuntimeOutput, plaintext)
		return
	}
	st, ok := d.cryptoManager().NetworkCrypto(row.NetworkID)
	if !ok || st.Status != "active" || st.EpochID == "" {
		_ = d.send(conn, transport.MsgRuntimeOutput, plaintext)
		return
	}
	sender := row.AgentName
	if sender == "" {
		sender = row.InstanceID
	}
	env, aad, err := d.encryptProtected(st, e2ee.ObjectTypeRuntimeOutput, streamID, sender, "", output)
	if err != nil {
		d.Log.Warn("runtime output encrypt failed; chunk dropped", "instance", row.InstanceID, "err", err)
		return
	}
	_ = d.send(conn, transport.MsgRuntimeOutput, map[string]any{
		"instanceId": row.InstanceID, "envelope": env, "aad": aad,
	})
}
