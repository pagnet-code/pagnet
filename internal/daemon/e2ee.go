package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// ErrNetworkCryptoNotReady is the clear, user-facing error state for a
// content operation on a network whose crypto is not active (plan D6:
// networks are ALWAYS encrypted). "provisioning" is the pre-activation
// window (the network is being secured), "degraded" and "unknown" fail
// closed the same way. There is NO plaintext fallback path: the content
// stays durable server-side and the operation is retried once the network
// reports active (the host.network_crypto re-push on every reconnect).
var ErrNetworkCryptoNotReady = errors.New("network is being secured — encryption is not active yet; content operations are unavailable (no plaintext mode)")

// cryptoNotReadyError wraps the not-ready state with the network id and
// the announced status (public-safe operational metadata, never key
// material).
func cryptoNotReadyError(networkID, status string) error {
	if status == "" {
		return fmt.Errorf("%w (%s: crypto state not yet announced)", ErrNetworkCryptoNotReady, networkID)
	}
	return fmt.Errorf("%w (%s: status %q)", ErrNetworkCryptoNotReady, networkID, status)
}

// contentCryptoReady returns the network's crypto state when it is ACTIVE
// with an announced epoch (the only state in which content may be
// encrypted), or a clear not-ready error otherwise. Plan D6: the
// standard/plaintext branch is GONE — every network is encrypted, and a
// provisioning (or degraded, or unannounced) network refuses content.
func (d *Daemon) contentCryptoReady(networkID string) (NetworkCryptoState, error) {
	if networkID == "" {
		return NetworkCryptoState{}, cryptoNotReadyError("", "")
	}
	st, ok := d.cryptoManager().NetworkCrypto(networkID)
	if !ok || st.Status != "active" || st.EpochID == "" {
		status := ""
		if ok {
			status = st.Status
		}
		return NetworkCryptoState{}, cryptoNotReadyError(networkID, status)
	}
	return st, nil
}

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
	st := NetworkCryptoState{
		TenantID: p.TenantID,
		Status:   p.Status,
		EpochID:  p.EpochID,
	}
	d.cryptoManager().SetNetworkCrypto(p.NetworkID, st)
	// Persist the announced state in the daemon's local DB: the CLI
	// reuses the host's crypto path for client-side encryption (pagnet
	// invoke / event publish) and needs the announced status + epoch +
	// tenant from the same state dir (the in-memory cache dies with the
	// daemon process).
	_ = d.state.SaveNetworkCrypto(p.NetworkID, st)
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
//
// ProtocolVersion is the CONTENT protocol version — transport.ProtocolVersion
// (= 2) for all V2 objects (the V2 cutover moves every content path to 2;
// the SDK and the daemon MUST agree, and the committed e2ee vectors carry
// the binding). The AAD VERSION (serialization) stays e2ee.AADVersion=1.
func buildAAD(tenantID, networkID, objectType, objectID, sender, recipient, epochID string) (e2ee.AAD, error) {
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
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

// setRepNetwork stores the active network for a rep instance (set when
// control_use_network succeeds).
func (d *Daemon) setRepNetwork(instanceID, networkID string) {
	d.repNetworkMu.Lock()
	defer d.repNetworkMu.Unlock()
	d.repNetworks[instanceID] = networkID
}

// getRepNetwork returns the active network for a rep instance ("" if not set).
func (d *Daemon) getRepNetwork(instanceID string) string {
	d.repNetworkMu.Lock()
	defer d.repNetworkMu.Unlock()
	return d.repNetworks[instanceID]
}

// encryptToolArgs rewrites a tool call's protected fields into encrypted
// values. It returns the (possibly rewritten) args, or an error message
// ("" on success).
//
// Plan D6 (V2 cutover): networks are ALWAYS encrypted — the standard/
// plaintext branch is GONE. A tool call that carries protected CONTENT on a
// network whose crypto is not active (provisioning / degraded / not yet
// announced) is refused with the clear not-ready error; the content never
// crosses the boundary in plaintext. The failure is clean (the bridge
// answers the agent with the error; the work stays with the agent to
// retry), never a silent plaintext fallback. Tools that carry NO protected
// content (metadata-only: whoami, discover, register_capabilities, search,
// ...) are unaffected — they may run on a provisioning network.
//
// The refusal applies to network-SCOPED instances (workers): the instance
// is a member of its network by construction, so a not-ready crypto state
// is unambiguous and the daemon fails closed. A network-NULL instance (a
// representative) names a TARGET network whose membership the daemon cannot
// see; refusing there would mask the control plane's "no active membership"
// rejection (which the server evaluates BEFORE its content gate). A rep
// therefore only encrypts when it can and otherwise defers to the control
// plane, which always refuses plaintext content (D6 holds end to end).
//
// The mapping (plan §12):
//   - network_ask / network_reply / control_ask / control_reply: body ->
//     message (recipient = threadId when set, else empty).
//   - network_delegate / control_delegate: objective + title +
//     acceptanceCriteria -> one task envelope (the criteria ride inside).
//   - network_task_update: reason -> task envelope (the blocked reason).
//   - network_publish_artifact: label -> artifact envelope.
//   - network_event_publish: payload -> event_payload envelope (V2).
//   - network_invoke: input -> invocation_input envelope (V2).
func (d *Daemon) encryptToolArgs(row *InstanceRow, tool string, args json.RawMessage) (json.RawMessage, string) {
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return args, "" // unparseable: relay as-is (the server validates)
	}
	// The effective network for the crypto decision: the instance's own
	// network, or — for a network-NULL instance (a representative) driving a
	// control tool — the target network the call names explicitly, or the
	// rep's active network (set by control_use_network). Without this a
	// rep's control_ask/control_reply/control_delegate would skip
	// encryption (row.NetworkID is empty) and send a plaintext body that the
	// active target network rejects (private_network_plaintext_rejected).
	networkID := row.NetworkID
	if networkID == "" {
		networkID, _ = m["networkId"].(string)
	}
	if networkID == "" {
		networkID = d.getRepNetwork(row.InstanceID)
	}
	if networkID == "" {
		return args, ""
	}
	// The protected field(s) this tool call carries, extracted first: a
	// tool call with NO protected content is metadata-only and runs on any
	// network state; one WITH content requires the crypto to be active.
	var (
		plainContent string
		setEncrypted func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string)
	)
	switch tool {
	case "network_ask", "network_reply", "control_ask", "control_reply":
		plainContent, _ = m["body"].(string)
		if plainContent == "" {
			return args, "" // no content in this call: nothing to protect
		}
		threadID, _ := m["threadId"].(string)
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string) {
			delete(m, "body")
			m["messageId"] = objectID
			m["envelope"] = env
			m["aad"] = aad
			_ = threadID
		}
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
		plainContent = plain
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string) {
			delete(m, "objective")
			delete(m, "title")
			delete(m, "acceptanceCriteria")
			m["taskId"] = objectID
			m["envelope"] = env
			m["aad"] = aad
		}
	case "network_task_update":
		reason, _ := m["reason"].(string)
		if reason == "" {
			return args, ""
		}
		taskID, _ := m["taskId"].(string)
		if taskID == "" {
			return args, ""
		}
		plainContent = reason
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, _ string) {
			delete(m, "reason")
			m["reasonEnvelope"] = env
			m["reasonAAD"] = aad
			_ = taskID
		}
	case "network_publish_artifact":
		label, _ := m["label"].(string)
		if label == "" {
			return args, ""
		}
		plainContent = label
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string) {
			delete(m, "label")
			m["artifactId"] = objectID
			m["labelEnvelope"] = env
			m["labelAAD"] = aad
		}
	case "network_event_publish":
		payloadRaw, hasPayload := m["payload"]
		if !hasPayload {
			return args, ""
		}
		payloadBytes, err := json.Marshal(payloadRaw)
		if err != nil || len(payloadBytes) == 0 {
			return args, ""
		}
		plainContent = string(payloadBytes)
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string) {
			delete(m, "payload")
			m["eventId"] = objectID
			m["envelope"] = env
			m["aad"] = aad
		}
	case "network_invoke":
		inputRaw, hasInput := m["input"]
		if !hasInput {
			return args, ""
		}
		inputBytes, err := json.Marshal(inputRaw)
		if err != nil || len(inputBytes) == 0 {
			return args, ""
		}
		plainContent = string(inputBytes)
		setEncrypted = func(env e2ee.EncryptedPayloadV1, aad e2ee.AAD, objectID string) {
			delete(m, "input")
			// The client-minted object id the AAD binds travels under the
			// name the control plane decodes ("invocationId" —
			// agent_requests.go toolInvoke), the same contract the CLI's REST
			// path and sdk/rest.go use. The agent-command decode is LENIENT,
			// so a foreign key is silently DROPPED rather than rejected: the
			// server then mints its own invocation id and the AAD's bound
			// object id no longer matches the row it protects.
			m["invocationId"] = objectID
			m["envelope"] = env
			m["aad"] = aad
		}
	default:
		return args, "" // metadata-only tool: no protected content
	}

	// The call carries content: the network crypto MUST be active (D6 —
	// no plaintext path). Provisioning networks refuse with the clear
	// "being secured" state.
	//
	// WHO may refuse is the question. A network-SCOPED instance (a worker)
	// is a member of its network by construction (it was launched there), so
	// a not-ready crypto state is unambiguous: the daemon fails closed and
	// the agent sees the clear "being secured" state.
	//
	// A network-NULL instance (a representative) names a TARGET network it
	// may or may not hold an active membership in — and the daemon does not
	// know the membership; that is the control plane's decision
	// (requirePermission), which runs BEFORE the content gate
	// (networkCryptoGateMessage) on the server. If the daemon refused here on
	// a not-ready crypto state, it would mask the server's "no active
	// membership in that network" rejection with a "being secured" error. So
	// a network-NULL instance only encrypts when it CAN; otherwise the args
	// pass through unchanged and the control plane returns the correct error
	// (the membership rejection, or the content gate when there IS a
	// membership). The control plane always refuses plaintext content — it
	// never persists or delivers it — so D6 holds end to end.
	st, err := d.contentCryptoReady(networkID)
	if err != nil {
		if row.NetworkID != "" {
			return nil, err.Error() // worker: fail closed (pinned behavior)
		}
		return args, "" // rep: defer to the control plane
	}
	sender := row.AgentName
	if sender == "" {
		sender = row.InstanceID
	}
	var (
		objectType string
		objectID   = newObjectID()
		recipient  string
	)
	switch tool {
	case "network_ask", "network_reply", "control_ask", "control_reply":
		objectType = e2ee.ObjectTypeMessage
		recipient, _ = m["threadId"].(string)
	case "network_delegate", "control_delegate":
		objectType = e2ee.ObjectTypeTask
	case "network_task_update":
		objectType = e2ee.ObjectTypeTask
		objectID, _ = m["taskId"].(string)
	case "network_publish_artifact":
		objectType = e2ee.ObjectTypeArtifact
	case "network_event_publish":
		objectType = e2ee.ObjectTypeEventPayload
		if t, _ := m["target"].(string); t != "" {
			recipient = t
		}
	case "network_invoke":
		objectType = e2ee.ObjectTypeInvocationInput
		// The AAD's recipient names the ADDRESSED principal — the same
		// binding the CLI and SDK use (their AAD recipient is the target
		// principal id). When the call names no principal id, fall back to
		// the capability id the agent asked for. The AGENT-FACING name is
		// read on purpose (wireArgs renames it onto the control plane's
		// "capabilityId" afterwards): the AAD must bind what the agent
		// actually asked for, so the encryption layer always sees the
		// tool's own argument names and only the bytes crossing the cloud
		// boundary are renamed — the same ordering that makes
		// network_event_publish bind its recipient from "target".
		// ("toPrincipalId" is already the wire name; wireArgs passes it
		// through unchanged.)
		if t, _ := m["toPrincipalId"].(string); t != "" {
			recipient = t
		} else if t, _ := m["capability"].(string); t != "" {
			recipient = t
		}
	}
	env, aad, err := d.encryptProtected(st, objectType, objectID, sender, recipient, plainContent)
	if err != nil {
		if row.NetworkID != "" {
			return nil, err.Error() // worker: fail closed (pinned behavior)
		}
		// Rep: the announced epoch is not in the local keyring yet (an
		// enrollment in flight). Defer to the control plane the same way as
		// the not-ready case above — it refuses the plaintext, so nothing is
		// persisted unencrypted.
		return args, ""
	}
	setEncrypted(env, aad, objectID)
	out, err := json.Marshal(m)
	if err != nil {
		return args, ""
	}
	return out, ""
}

// sendRuntimeOutput emits one non-PTY turn output chunk (host.runtime_output).
// Plan D6 (V2 cutover): networks are ALWAYS encrypted — there is NO plaintext
// output path. On an active network the chunk payload is encrypted into an
// envelope (object_type=runtime_output, the per-turn stream id as object id)
// and the server stores ciphertext only; consumers decrypt at the edge (CLI
// attach, browser console). A network whose crypto is not active (provisioning
// / degraded / not yet announced) drops the chunk with a warning (observational,
// at-most-once, never a plaintext fallback): the protected deliverables
// (messages/tasks/events) are durably encrypted separately, so the turn's
// outcome is unaffected by a dropped stream chunk.
func (d *Daemon) sendRuntimeOutput(conn *websocket.Conn, row *InstanceRow, streamID, output string) {
	if row.NetworkID == "" || streamID == "" {
		_ = d.send(conn, transport.MsgRuntimeOutput, map[string]any{
			"instanceId": row.InstanceID, "output": output,
		})
		return
	}
	st, err := d.contentCryptoReady(row.NetworkID)
	if err != nil {
		// The chunk is DROPPED — never sent in plaintext (D6). The turn
		// itself is unaffected; the durable, protected outputs are separate.
		d.Log.Warn("runtime output dropped: network crypto not active (no plaintext path)",
			"instance", row.InstanceID, "network", row.NetworkID, "err", err)
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
