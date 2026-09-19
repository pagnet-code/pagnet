// Package transport defines the pagnet host + endpoint protocol wire
// format.
//
// This is the public protocol contract shared with pagnet-server.
//
// Transport is a serialization boundary: domain objects (Task, Message,
// Artifact, ...) are defined in the domain package and NEVER shaped around
// this wire format. Future transports (REST, A2A, Matrix, NATS) serialize
// the same domain objects.
//
// Protocol v2 (the V2 cutover) covers both the host connection (daemons)
// and the endpoint connection (SDK participants). A peer that speaks an
// unsupported version is answered with protocol.upgrade_required and
// closed — never silently misinterpreted.
package transport

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// ProtocolVersion is the current protocol envelope version. V2 is the V2
// architecture cutover: principals/endpoints/memberships replace the v1
// agent-kind + grant model, and the endpoint WS (SDK participants) is new.
// A peer that sends any other version must be answered with
// protocol.upgrade_required (UpgradeRequiredPayload) and then closed.
const ProtocolVersion = 2

// Envelope is the single versioned wrapper for every daemon/control-plane
// command and event on the host connection. Domain fields never appear at
// the top level.
type Envelope struct {
	ProtocolVersion int             `json:"protocolVersion"`
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Timestamp       time.Time       `json:"timestamp"`
	CorrelationID   *string         `json:"correlationId,omitempty"`
	CausationID     *string         `json:"causationId,omitempty"`
	Payload         json.RawMessage `json:"payload"`
}

// NewEnvelope wraps a payload in a versioned envelope with a fresh id.
func NewEnvelope(messageType string, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		id, _ = uuid.NewRandom()
	}
	return Envelope{
		ProtocolVersion: ProtocolVersion,
		ID:              id.String(),
		Type:            messageType,
		Timestamp:       time.Now().UTC(),
		Payload:         raw,
	}, nil
}

// WithContext attaches correlation/causation ids carried in ctx (if any).
func (e Envelope) WithContext(ctx context.Context) Envelope {
	if id, ok := domain.CorrelationID(ctx); ok {
		s := id.String()
		e.CorrelationID = &s
	}
	if id, ok := domain.CausationID(ctx); ok {
		s := id.String()
		e.CausationID = &s
	}
	return e
}

// DecodePayload unmarshals the envelope payload into v.
func (e Envelope) DecodePayload(v any) error {
	return json.Unmarshal(e.Payload, v)
}

// IsVersionSupported reports whether the envelope was sent with the current
// protocol version. A peer that sends an unsupported version must be
// answered with protocol.upgrade_required (UpgradeRequiredPayload) and then
// closed — its messages must never be interpreted (v1 and v2 share the
// envelope shape but NOT the type vocabulary).
func (e Envelope) IsVersionSupported() bool {
	return e.ProtocolVersion == ProtocolVersion
}

// MsgUpgradeRequired is sent to a peer whose protocol version is not
// supported. The receiver must stop and surface the user-facing message;
// the sender closes the connection immediately after.
const MsgUpgradeRequired = "protocol.upgrade_required"

// UpgradeRequiredMessage is the user-facing message for a v1 peer.
const UpgradeRequiredMessage = "Pagnet client is outdated. Please update."

// UpgradeRequiredPayload tells a peer which protocol version is required
// and how to say it to the user.
type UpgradeRequiredPayload struct {
	// Required is the protocol version the server speaks.
	Required int `json:"required"`
	// Message is the user-facing explanation.
	Message string `json:"message"`
}

// Message types: control plane -> host. Commands are STRUCTURED only; the
// daemon decides locally how to translate them into process invocations.
// The server never sends shell commands.
const (
	MsgLaunchAgent         = "host.launch_agent"
	MsgStopAgent           = "host.stop_agent"
	MsgRestartAgent        = "host.restart_agent"
	MsgForgetInstance      = "host.forget_instance" // instance deleted server-side: clean up locally
	MsgWakeAgent           = "agent.wake"           // wake a hibernated instance (resume session)
	MsgDeliverNetworkEvent = "host.deliver_network_event"
	MsgRequestInventory    = "host.request_inventory"
	// MsgHostUnenrolled tells a LIVE daemon that its host was removed from
	// the control plane (deleted or unenrolled). The credential is dead —
	// reconnecting would only 401 — so the daemon stops itself with a
	// message the operator can see. Live (at-most-once): a daemon that
	// misses it will 401 on its next dial and stop the same way.
	MsgHostUnenrolled = "host.unenrolled"
	// CloseCodeSuperseded is the WebSocket close code the control plane
	// sends to a host connection that a NEWER connection from the same
	// host just replaced. The daemon that receives it must stop: its
	// identity is now owned by another daemon process, and reconnecting
	// would only fight that daemon forever (each connect supersedes the
	// other, in an endless backoff loop).
	CloseCodeSuperseded = 4001
	// MsgUpdateRoots replaces the daemon's allowed workspace roots at
	// runtime. The server-side root list (PUT /hosts/{id}/roots) is the
	// source of truth; without this command the daemon would keep
	// enforcing its startup config forever after a root change.
	// Durable + idempotent.
	MsgUpdateRoots = "host.update_roots"
	// MsgAttachTerminal opens an attach session for an instance and, if the
	// instance's PTY terminal is not running, starts it (resume stored
	// session when the runtime supports it). Durable + idempotent.
	MsgAttachTerminal = "host.attach_terminal"
	// MsgDetachTerminal closes an attach session. Detach is observational:
	// the PTY keeps running (addendum §10). Durable + idempotent.
	MsgDetachTerminal = "host.detach_terminal"
	// MsgTerminalStop kills the instance's PTY session (user closed the
	// terminal, or the instance was stopped/restarted/forgotten).
	// Durable + idempotent.
	MsgTerminalStop = "host.terminal_stop"
	// MsgTerminalSnapshot asks the daemon to re-emit the PTY snapshot
	// frame (bounded ring + lastSeq) for an attach session. The server
	// uses it when a client connects AFTER live output has already
	// flowed (the cached attach-time snapshot is stale): the new
	// snapshot is a superset the late client renders before live output
	// (addendum §11 replay → live). Durable + idempotent (re-emitting
	// the ring is side-effect free).
	MsgTerminalSnapshot = "host.terminal_snapshot"
	// MsgTerminalInput / MsgTerminalResize are LIVE messages: written
	// directly onto the host connection (at-most-once, dropped under
	// back-pressure, never durably queued or acked). Keystroke semantics
	// do not survive a Postgres round-trip or a busy-deferral.
	MsgTerminalInput  = "host.terminal_input"
	MsgTerminalResize = "host.terminal_resize"
	// MsgListDirs is a LIVE request (at-most-once, not durably queued or
	// acked): the control plane asks the daemon to list the subdirectories
	// of a path, for the click-to-select directory picker. The daemon
	// validates the path against its allowed roots (the enforcement point)
	// and answers with MsgListDirsResult, correlated by RequestID.
	MsgListDirs = "host.list_dirs"
	// MsgLatestVersion advertises the latest worker release version to
	// the daemon (worker auto-update, P6). Live (at-most-once): sent on
	// connect and with every heartbeat. The daemon's update check is
	// idempotent and self-gating (idle gate + 1h failure backoff), so a
	// missed or duplicated advertisement is harmless.
	MsgLatestVersion = "host.latest_version"
	// MsgNetworkCrypto is a LIVE server->host signal carrying one network's
	// E2EE lifecycle state (status + current epoch id + tenant id). The
	// daemon caches it per network and uses it to decide whether to encrypt
	// protected content (status=active) and under which epoch (epochId). It
	// is re-sent on every (re)connect and on state changes (activation,
	// rotation), so a daemon that misses it re-receives it on reconnect.
	// Live (at-most-once): it is a state signal, not a durable command.
	MsgNetworkCrypto = "host.network_crypto"

	// E2EE / Private Network crypto commands (plan §11.6/§11.7/§11.8). All
	// are DURABLE + idempotent (commandId) and network-scoped (they carry a
	// networkId, not an instanceId). The daemon runs the customer-side
	// cryptography locally; the control plane only relays the opaque
	// payloads (key package / challenge / proof) and never sees key
	// material. The ack carries the leg's result in the ack's `result`
	// field (see the crypto *Result payloads below).
	//
	// MsgCryptoActivate: the selected host creates the first Network Key
	// Authority / key epoch locally, runs the crypto self-test, and reports
	// its public identity + epoch id (plan §11.6 step 4–6).
	MsgCryptoActivate = "host.crypto_activate"
	// MsgCryptoKeyPackage: the NKA host builds the HPKE key package sealed
	// to the target host's X25519 public key (enrollment leg 1, §11.7).
	MsgCryptoKeyPackage = "host.crypto_key_package"
	// MsgCryptoInstallKeyPackage: the target host opens the key package with
	// its X25519 private key and stores the network keyring (enrollment leg
	// 2, §11.7).
	MsgCryptoInstallKeyPackage = "host.crypto_install_key_package"
	// MsgCryptoChallenge: the NKA host issues a decryption challenge for the
	// target host (enrollment leg 3, §11.7 step 7).
	MsgCryptoChallenge = "host.crypto_challenge"
	// MsgCryptoProve: the target host decrypts the challenge and returns the
	// proof (enrollment leg 4, §11.7 step 7).
	MsgCryptoProve = "host.crypto_prove"
	// MsgCryptoVerify: the NKA host verifies the target host's proof
	// (enrollment leg 5, §11.7 step 8). A clean ack marks the host
	// crypto-ready.
	MsgCryptoVerify = "host.crypto_verify"
	// MsgCryptoRotate: the NKA host mints a new key epoch, marking the
	// previous one rotated (plan §11.8). The old epoch is retained
	// customer-side to read history; the control plane only records the new
	// epoch id.
	MsgCryptoRotate = "host.crypto_rotate"

	// Browser key-session commands (plan §13, p10). These are the
	// request/response crypto operations a browser (or any non-daemon
	// client) performs against an active private network. Like the
	// lifecycle commands above they are DURABLE + idempotent (commandId)
	// and network-scoped, and the control plane is an OPAQUE RELAY: it
	// dispatches the command to a selected key host and relays the ack's
	// result byte-for-byte. The daemon runs the customer-side cryptography
	// (HPKE base-mode ephemeral-static over the network keyring); the
	// control plane never sees plaintext or a CEK.
	//
	// MsgCryptoSessionStart: the daemon records an in-memory browser
	// session (authorization record) and reports its static X25519 public
	// key (the wrap target for browser-originated writes).
	MsgCryptoSessionStart = "host.crypto_session_start"
	// MsgCryptoUnwrapCek: the daemon unwraps each object's CEK with the
	// customer-side network epoch key and re-wraps it under the browser's
	// session ephemeral-static X25519 public key (HPKE base, fresh sender
	// ephemeral per object). The browser decrypts the CEK and then the
	// object payload with its own AAD.
	MsgCryptoUnwrapCek = "host.crypto_unwrap_cek"
	// MsgCryptoWrapCek: the daemon unwraps the browser's HPKE-wrapped CEK
	// with its static X25519 private key and wraps it under the CURRENT
	// network epoch (the p8 keyring format). The browser fills the
	// EncryptedPayloadV1 envelope and submits it through the normal
	// protected-field write path (authorization is enforced THERE).
	MsgCryptoWrapCek = "host.crypto_wrap_cek"
	// MsgCryptoSessionEnd: explicit session teardown (optional — the TTL
	// covers it). Idempotent (an unknown session is a clean no-op ack).
	MsgCryptoSessionEnd = "host.crypto_session_end"
)

// Message types: host -> control plane (events).
const (
	MsgHeartbeat            = "host.heartbeat"
	MsgAgentStarted         = "host.agent_started"
	MsgAgentStopped         = "host.agent_stopped"
	MsgAgentStatus          = "host.agent_status"
	MsgAgentHibernated      = "host.agent_hibernated" // process exited after turn; session preserved
	MsgRuntimeOutput        = "host.runtime_output"
	MsgRuntimeTurnStarted   = "host.runtime_turn_started"
	MsgRuntimeTurnCompleted = "host.runtime_turn_completed"
	MsgRuntimeTurnFailed    = "host.runtime_turn_failed"
	MsgWorkspaceDetected    = "host.workspace_detected"
	MsgHostInventory        = "host.host_inventory"
	// MsgTerminalOutput streams PTY bytes for an attach session: raw
	// terminal output (base64), session-keyed, in order. Snapshot frames
	// (Snapshot=true) replay the bounded ring buffer for a (re)attaching
	// client; LastSeq marks where live output resumes, so replay → live
	// never duplicates (addendum §11).
	MsgTerminalOutput = "host.terminal_output"
	MsgCommandAck     = "host.command_ack"
	MsgRuntimeSession = "host.runtime_session"
	MsgAgentRequest   = "agent.request" // agent -> control plane, relayed by the daemon bridge socket
	// MsgListDirsResult is the daemon's reply to MsgListDirs, correlated by
	// RequestID. Carries the subdirectory listing (or an error when the
	// path is not under an allowed root / not a directory / unreadable).
	MsgListDirsResult = "host.list_dirs_result"
	// MsgInteractionStarted / MsgInteractionResolved carry a normalized
	// native runtime interaction (question, permission prompt, ...) the
	// adapter observed. Phase 5: pagnet OBSERVES the interaction — it does
	// not render it; the native TUI stays the place a human answers. These
	// are fire-and-forget observations (at-most-once), like the other
	// runtime turn events: a missed event means the interaction is not
	// recorded, never a corrupted one.
	MsgInteractionStarted  = "interaction.started"
	MsgInteractionResolved = "interaction.resolved"
)

// MsgAgentResponse is control plane -> host: the result of an
// MsgAgentRequest, correlated by RequestID (the request envelope's id).
const MsgAgentResponse = "agent.response"

// MsgEndpointStatus is host -> control plane: the daemon reports a managed
// agent's endpoint liveness (the managed_agent PrincipalEndpoint row is
// derived from these reports + the instance state). Live (at-most-once):
// a missed report is corrected by the next one and by heartbeats.
const MsgEndpointStatus = "host.endpoint_status"

// Message types: the endpoint WS (SDK participants, path /wss/endpoints,
// bearer principal credential). The endpoint is the generic live-presence
// unit of a principal; the control plane routes deliveries and invocations
// to ONE eligible endpoint per operation.
//
// The connection lifecycle is: connect (auth) -> endpoint.register ->
// endpoint.auth_ok -> live (deliveries/invocations/heartbeats) ->
// endpoint.disconnect (graceful) or drop.
const (
	// MsgEndpointRegister is c->s: the endpoint registers on (re)connect
	// with its crypto identity, SDK version and advertised capabilities.
	// On first use with an ACTIVATION credential the server issues the
	// durable endpoint credential (returned in endpoint.auth_ok).
	MsgEndpointRegister = "endpoint.register"
	// MsgEndpointAuthOK is s->c: the registration was accepted; carries
	// the endpoint's identity, its networks and (only on activation) the
	// durable credential.
	MsgEndpointAuthOK = "endpoint.auth_ok"
	// MsgEndpointMessageDeliver is s->c: one durable message for the
	// endpoint's principal (encrypted parts, AAD-bound).
	MsgEndpointMessageDeliver = "endpoint.message_deliver"
	// MsgEndpointMessageAcked is c->s: the message was processed.
	MsgEndpointMessageAcked = "endpoint.message_acked"
	// MsgEndpointEventDeliver is s->c: one event delivery for a
	// subscription (encrypted payload, AAD-bound). Durable: the delivery
	// row survives disconnects; the live push is an optimization.
	MsgEndpointEventDeliver = "endpoint.event_deliver"
	// MsgEndpointEventAck is c->s: the delivery was processed.
	MsgEndpointEventAck = "endpoint.event_ack"
	// MsgEndpointInvocationDispatch is s->c: one capability invocation
	// for the endpoint's principal (encrypted input, AAD-bound).
	MsgEndpointInvocationDispatch = "endpoint.invocation_dispatch"
	// MsgEndpointInvocationAccept is c->s: the endpoint accepted the
	// invocation (it will produce a result).
	MsgEndpointInvocationAccept = "endpoint.invocation_accept"
	// MsgEndpointInvocationResult is c->s: the invocation's outcome
	// (encrypted output OR error, AAD-bound).
	MsgEndpointInvocationResult = "endpoint.invocation_result"
	// MsgEndpointHeartbeat is c->s: liveness + load (inflight). The
	// control plane answers with MsgEndpointHeartbeatAck.
	MsgEndpointHeartbeat = "endpoint.heartbeat"
	// MsgEndpointHeartbeatAck is s->c: the heartbeat was received.
	MsgEndpointHeartbeatAck = "endpoint.heartbeat_ack"
	// MsgEndpointDisconnect is c->s: graceful shutdown (the endpoint is
	// going away on purpose; pending work stays durable).
	MsgEndpointDisconnect = "endpoint.disconnect"
)

// LaunchAgentPayload is a structured launch command (never shell).
type LaunchAgentPayload struct {
	// CommandID provides idempotency across reconnects/resends.
	CommandID string `json:"commandId"`
	// InstanceID is pre-allocated by the control plane.
	InstanceID   string `json:"instanceId"`
	DefinitionID string `json:"definitionId"`
	Runtime      string `json:"runtime"`
	// Workspace must belong to the host and sit under an allowed root;
	// the daemon validates both locally.
	WorkspaceID   string `json:"workspaceId"`
	WorkspacePath string `json:"workspacePath"`
	// CWD is the agent's working directory: an absolute path that is a
	// subdirectory of WorkspacePath (the agent sees only from here
	// forward). Empty = run at the workspace root (the default). The
	// daemon validates it against the allowed roots and keeps the
	// repo/worktree keying on WorkspacePath.
	CWD     string `json:"cwd,omitempty"`
	Profile string `json:"profile"`
	// Transcript: metadata | network | full (default network).
	Transcript string         `json:"transcript"`
	Options    map[string]any `json:"options,omitempty"`
	// AgentName is the definition's name (used for worktree branch names,
	// §29: pagnet/<agent-name>/<task-short-id>).
	AgentName string `json:"agentName,omitempty"`
	// NetworkID scopes the agent's network identity (injected into the
	// runtime environment for the MCP bridge).
	NetworkID string `json:"networkId,omitempty"`
	// Access: read_write (default) or read_only. Second+ RW agents on the
	// same repository get an automatic git worktree (§29); read-only
	// agents share the checkout.
	Access string `json:"access,omitempty"`
	// Kind: worker (default) or representative. Representatives have no
	// workspace (WorkspacePath is empty) and run in an pagnet-managed
	// state directory (§37); the daemon selects their MCP surface
	// (the control bridge) from this.
	Kind string `json:"kind,omitempty"`
	// Mission is the agent's initial instruction (north-star §15). The
	// daemon runs it as the FIRST turn of a fresh instance; a resumed
	// session never receives it again.
	Mission string `json:"mission,omitempty"`
	// Model is the resolved model for this launch ("" = the runtime's own
	// default). Precedence: launch request > definition default > runtime.
	Model string `json:"model,omitempty"`
	// AgentMD is the standing instruction (AGENT.md-style) for this launch
	// ("" = none). The daemon materializes it in its state dir — never the
	// workspace: claude receives it via --append-system-prompt-file, other
	// runtimes have it appended to a fresh session's first turn (exactly
	// how the coordination contract reaches them).
	AgentMD string `json:"agentMd,omitempty"`
}

// WakeAgentPayload wakes a hibernated instance: the daemon resumes the
// stored runtime session and starts a turn for the queued work.
// wakeRequestId provides idempotency across reconnects/resends.
type WakeAgentPayload struct {
	WakeRequestID string `json:"wakeRequestId"`
	InstanceID    string `json:"instanceId"`
	Reason        string `json:"reason"`
}

// RequestInventoryPayload asks the host to rescan runtimes/workspaces and
// reply with host.host_inventory. CommandID provides idempotency across
// reconnects/resends — without it the daemon cannot ack the command and
// the dispatcher would re-send it forever.
type RequestInventoryPayload struct {
	CommandID string `json:"commandId"`
}

// UpdateRootsPayload replaces the host's allowed workspace roots and their
// enforcement mode. Empty Roots is a valid value (an allow_list host then
// allows nothing; an allow_all host allows any path regardless).
type UpdateRootsPayload struct {
	CommandID string   `json:"commandId"`
	Roots     []string `json:"roots"`
	// Mode is the roots enforcement mode (allow_all by default, allow_list
	// to confine to Roots). Empty = allow_all.
	Mode string `json:"mode,omitempty"`
}

// LatestVersionPayload advertises the latest worker release version to a
// daemon (auto-update, P6). The operator sets PAGNET_RELEASE_VERSION on
// the control plane when publishing a release (e.g. v0.3.0); empty means
// nothing is advertised and auto-update is a no-op (the safe default).
type LatestVersionPayload struct {
	LatestVersion string `json:"latestVersion"`
}

// NetworkCryptoPayload carries one network's E2EE lifecycle state to the
// daemon (the customer-side encryption decision input, plan §12). The daemon
// uses Status to decide whether to encrypt protected content (only when
// "active") and EpochID to choose the epoch to encrypt under (the BINDING
// epoch rule: the sender always encrypts under the announced epoch).
// TenantID is carried so the daemon can bind it into the AAD (the daemon
// does not otherwise know the tenant id). The control plane stores only this
// routing metadata — never key material.
type NetworkCryptoPayload struct {
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	// Status: standard | activating | active.
	Status  string `json:"status"`
	EpochID string `json:"epochId,omitempty"`
}

// ListDirsPayload is a LIVE request to list the subdirectories of Path
// (the click-to-select directory picker). The daemon validates Path
// against its allowed roots before reading it.
type ListDirsPayload struct {
	RequestID string `json:"requestId"`
	Path      string `json:"path"`
}

// DirEntry is one subdirectory in a ListDirsResultPayload.
type DirEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
}

// ListDirsResultPayload is the daemon's reply to ListDirsPayload,
// correlated by RequestID. Path is the directory that was listed (the
// picker's current location); Entries are its subdirectories (sorted,
// capped). Error is set when the path is not under an allowed root, is
// not a directory, or cannot be read.
type ListDirsResultPayload struct {
	RequestID string     `json:"requestId"`
	Path      string     `json:"path"`
	Entries   []DirEntry `json:"entries"`
	Error     string     `json:"error,omitempty"`
}

// StopAgentPayload stops an agent instance.
type StopAgentPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
}

// RestartAgentPayload restarts an agent instance.
type RestartAgentPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
}

// ForgetInstancePayload tells the daemon an instance was deleted on the
// control plane: stop any process, remove the isolated worktree (branch
// kept), drop the local row.
type ForgetInstancePayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
}

// NetworkEventPayload is an inbound work/notification for a managed agent
// (ASK, TASK, NOTICE, STATUS, or user terminal input).
type NetworkEventPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
	// MessageID is set when the work is a durable message: a clean command
	// ack marks that message delivered (message.delivered). A failed turn
	// acks with an error, so the message stays pending for re-delivery.
	MessageID string `json:"messageId,omitempty"`
	// Kind: ask | task | notice | status | user_input
	Kind string `json:"kind"`
	// ThreadID is set for ask/notice messages.
	ThreadID string `json:"threadId,omitempty"`
	// TaskID is set for task events.
	TaskID string `json:"taskId,omitempty"`
	// FromAgent is the logical sender name (for the rendered turn prompt).
	FromAgent string `json:"fromAgent,omitempty"`
	// ConversationID is set for channel deliveries (a human conversation
	// with a representative).
	ConversationID string `json:"conversationId,omitempty"`
	// NetworkID is set for channel deliveries: the conversation's active
	// network ("" when none selected yet).
	NetworkID string `json:"networkId,omitempty"`
	// Resource is the canonical resource key, when relevant.
	Resource string `json:"resource,omitempty"`
	// Body is the rendered text of the turn input. On an active private
	// network this is EMPTY for encrypted deliveries: the protected text
	// crosses the boundary only as Envelope (ciphertext), and the recipient
	// daemon decrypts it just before the turn input.
	Body string `json:"body"`
	// AcceptanceCriteria for task events. On an active private network the
	// criteria ride inside the task Envelope (encrypted with the objective),
	// so this is empty for encrypted deliveries.
	AcceptanceCriteria []string `json:"acceptanceCriteria,omitempty"`
	// Envelope is the E2EE envelope for an encrypted delivery (private
	// networks, plan §12). When set, the recipient daemon decrypts it (with
	// AAD) before rendering the turn input. The control plane relays it
	// byte-for-byte and never reads the ciphertext.
	Envelope *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	// AAD is the associated-data the Envelope was bound to, relayed verbatim
	// from the sender (the AAD server obligation, PROTOCOL §3). The recipient
	// reconstructs the AAD from these server-relayed fields and decrypts; if
	// the server altered any bound field, GCM authentication fails.
	AAD *e2ee.AAD `json:"aad,omitempty"`

	// --- protocol v2 (event delivery to managed agents) ---
	//
	// These fields carry the v2 event-delivery identity. The v1 fields
	// above stay for the existing daemon delivery path; the daemon-side
	// meaning change (deterministic trigger turn) is a later wave.
	// EventID is the network event this delivery carries.
	EventID string `json:"eventId,omitempty"`
	// DeliveryID is the event delivery row id (the ack idempotency key).
	DeliveryID string `json:"deliveryId,omitempty"`
	// EventType is the event's dot-separated type.
	EventType string `json:"eventType,omitempty"`
	// TargetPrincipalID is the event's target principal (the managed
	// agent's principal).
	TargetPrincipalID string `json:"targetPrincipalId,omitempty"`
	// DeliveryMode: deliver | wake (domain.EventDeliveryMode).
	DeliveryMode string `json:"deliveryMode,omitempty"`
}

// HeartbeatPayload carries host liveness + machine metrics.
type HeartbeatPayload struct {
	HostID    string `json:"hostId"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	DaemonVer string `json:"daemonVersion"`
	Metrics   struct {
		CPUCount      int     `json:"cpuCount"`
		CPULoad       float64 `json:"cpuLoad"`
		MemTotalBytes int64   `json:"memTotalBytes"`
		MemUsedBytes  int64   `json:"memUsedBytes"`
		DiskFreeBytes int64   `json:"diskFreeBytes"`
	} `json:"metrics"`
	Instances []InstanceStatus `json:"instances,omitempty"`
}

// InstanceStatus is per-agent liveness piggybacked on heartbeats.
type InstanceStatus struct {
	InstanceID string `json:"instanceId"`
	Status     string `json:"status"`
	PID        int    `json:"pid,omitempty"`
}

// InventoryPayload reports detected runtimes and workspaces.
type InventoryPayload struct {
	HostID       string                `json:"hostId"`
	Runtimes     []RuntimeInstallation `json:"runtimes"`
	Workspaces   []WorkspaceReport     `json:"workspaces"`
	AllowedRoots []string              `json:"allowedRoots"`
	// Crypto is the host's stable per-host E2EE public identity (plan
	// §11.5), reported so the control plane knows the host is crypto-capable
	// and can address it for Private Network activation/enrollment. Public
	// keys only — the private keys never leave the host. Nil when the host
	// has no crypto identity material.
	Crypto *InventoryCrypto `json:"crypto,omitempty"`
}

// InventoryCrypto is the host's public E2EE identity (the HPKE receiver key
// and the signing key), base64-encoded. It is a property of the stable Host,
// not the ephemeral Runner, and is stable across daemon restarts.
type InventoryCrypto struct {
	// X25519Pub is the HPKE receiver public key (base64, 32 bytes).
	X25519Pub string `json:"x25519Pub"`
	// Ed25519Pub is the signing public key (base64, 32 bytes).
	Ed25519Pub string `json:"ed25519Pub"`
}

// RuntimeInstallation describes a detected runtime on the host.
type RuntimeInstallation struct {
	Runtime string `json:"runtime"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	// Capabilities are the OBSERVED native-interaction capability flags the
	// daemon reports from its adapter (Phase 5, plan §8.6): the persisted
	// compatibility matrix. Empty when the adapter does not implement the
	// capability model (the conservative "cannot observe" default).
	Capabilities *RuntimeCapabilities `json:"capabilities,omitempty"`
}

// RuntimeCapabilities is one adapter's observed native-interaction
// capability flags, reported per (runtime, version). deferredInteraction /
// remoteResolve are per-kind bool maps (absent kind = not supported).
type RuntimeCapabilities struct {
	ObserveInteractions bool            `json:"observeInteractions"`
	NativeInteractiveUI bool            `json:"nativeInteractiveUi"`
	DeferredInteraction map[string]bool `json:"deferredInteraction,omitempty"`
	RemoteResolve       map[string]bool `json:"remoteResolve,omitempty"`
}

// WorkspaceReport describes a workspace discovered under an allowed root.
type WorkspaceReport struct {
	Path   string `json:"path"`
	Branch string `json:"branch,omitempty"`
	Remote string `json:"remote,omitempty"`
	// ResourceKey is the canonical resource key when Git metadata was
	// detected (e.g. "github.com/xemahq/dsl").
	ResourceKey string `json:"resourceKey,omitempty"`
}

// TerminalAttachPayload opens a terminal/attach session for an instance:
// the daemon records the attach, starts the instance's PTY if it is not
// running (resuming the stored runtime session when possible), and streams
// the PTY snapshot as terminal_output frames before resuming live output.
// Terminal is always true — kept on the wire because an in-flight older
// daemon still branches on it.
type TerminalAttachPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
	Terminal   bool   `json:"terminal,omitempty"`
}

// DetachTerminalPayload closes an attach session. Detach is observational —
// the PTY keeps running (addendum §10). When it was the last attach, the
// instance may return to hibernation only if no PTY is active (§35: do not
// hibernate underneath an attached user or a live terminal).
type DetachTerminalPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
}

// TerminalStopPayload kills the instance's PTY session. Durable and
// idempotent (a second stop is an acknowledged no-op).
type TerminalStopPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
}

// TerminalSnapshotPayload requests one PTY snapshot frame for an attach
// session. The daemon answers with a host.terminal_output snapshot frame
// when the PTY is live (no frame when it is not — in that case the
// session's teardown owns the waiting client).
type TerminalSnapshotPayload struct {
	CommandID  string `json:"commandId"`
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
}

// TerminalInputPayload is raw user input on an attach session: base64 PTY
// stdin bytes (keystrokes, control sequences, pasted text). LIVE message —
// no CommandID, never acked, delivered at most once.
type TerminalInputPayload struct {
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
	Data       string `json:"data"` // base64
}

// TerminalResizePayload updates the PTY window size (SIGWINCH). LIVE
// message; the client debounces.
type TerminalResizePayload struct {
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
	Cols       uint16 `json:"cols"`
	Rows       uint16 `json:"rows"`
}

// TerminalOutputPayload is one ordered chunk of PTY output for an attach
// session.
//
//   - Live frames: Data = raw bytes (base64), Seq = the session's
//     monotonically increasing output counter after this chunk.
//   - Snapshot frames (Snapshot=true, sent right after an attach): Data =
//     the bounded ring buffer so far ("" when empty), LastSeq = the counter
//     at snapshot time. The server switches the attaching client to live
//     output immediately after forwarding the snapshot, so no byte is ever
//     delivered twice (addendum §11).
type TerminalOutputPayload struct {
	InstanceID string `json:"instanceId"`
	SessionID  string `json:"sessionId"`
	Data       string `json:"data"` // base64
	Seq        uint64 `json:"seq,omitempty"`
	Snapshot   bool   `json:"snapshot,omitempty"`
	LastSeq    uint64 `json:"lastSeq,omitempty"`
	// ConfigStale (snapshot frames only, P6): the instance's PTY was
	// started under a different runtime-injected config (MCP bridge +
	// identity env) than the daemon renders now — the main trigger is an
	// auto-update re-exec. The UI shows a "restart the terminal to apply"
	// hint next to the existing Restart action (no auto-restart).
	ConfigStale bool `json:"configStale,omitempty"`
}

// AgentRequestPayload is one agent tool call relayed by the daemon to the
// control plane (the agent talks to the network only through the MCP
// bridge -> daemon Unix socket -> this envelope; the host credential never
// reaches the agent). The control plane derives the acting instance from
// the host connection and validates it against the payload.
type AgentRequestPayload struct {
	InstanceID string          `json:"instanceId"`
	Tool       string          `json:"tool"` // fixed network_* tool name (PROTOCOL §6)
	Args       json.RawMessage `json:"args"`
}

// AgentResponsePayload answers one AgentRequest. RequestID is the
// request envelope's id; the daemon correlates it with the waiting
// bridge-socket client.
type AgentResponsePayload struct {
	RequestID string          `json:"requestId"`
	OK        bool            `json:"ok"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// InteractionEventPayload is a normalized native runtime interaction the
// adapter observed (Phase 5). The daemon mints InteractionID (idempotency
// across reconnect/resend); the control plane stores it and orchestrates
// around it. The vendor payload stays opaque — never parsed server-side
// for correctness.
type InteractionEventPayload struct {
	// InteractionID is the pagnet-side id (daemon-minted; idempotency key).
	InteractionID string `json:"interactionId"`
	InstanceID    string `json:"instanceId"`
	// SessionID is the runtime-native session the interaction belongs to.
	SessionID string `json:"sessionId,omitempty"`
	Runtime   string `json:"runtime"`
	// NativeInteractionID is the runtime's own id for the interaction
	// ("" when the runtime does not name them).
	NativeInteractionID string `json:"nativeInteractionId,omitempty"`
	// Kind: question | permission | plan_approval | authentication |
	// confirmation | other.
	Kind string `json:"kind"`
	// Summary is a public-safe one-liner (never protected content).
	Summary string `json:"summary,omitempty"`
	// NativePayload is the opaque, versioned vendor payload (as-is).
	NativePayload json.RawMessage `json:"nativePayload,omitempty"`
	// CorrelationID links the started/resolved pair.
	CorrelationID string `json:"correlationId,omitempty"`
	// Resolved marks a resolution (MsgInteractionResolved).
	Resolved bool `json:"resolved,omitempty"`
	// Decision is the resolution outcome (resolved|declined|cancelled).
	Decision string `json:"decision,omitempty"`
	// Answer is the (opaque) answer, when the runtime reported one. On an
	// active private network this is EMPTY for encrypted observations: the
	// answer (with Summary + NativePayload) crosses only as DetailEnvelope.
	Answer string `json:"answer,omitempty"`
	// DetailEnvelope is the E2EE envelope for the interaction's protected
	// detail (summary + native payload + answer) on an active private network
	// (plan §12.3). Kind + state + ids stay plaintext; the detail is
	// ciphertext. The control plane relays it byte-for-byte.
	DetailEnvelope *e2ee.EncryptedPayloadV1 `json:"detailEnvelope,omitempty"`
	// DetailAAD is the associated-data the DetailEnvelope was bound to,
	// relayed verbatim (the AAD server obligation, PROTOCOL §3).
	DetailAAD *e2ee.AAD `json:"detailAAD,omitempty"`
}

// --- E2EE / Private Network crypto commands (plan §11.6/§11.7/§11.8) --------
//
// These are the durable, idempotent, network-scoped commands the control
// plane uses to activate a Private Network and enroll additional hosts. The
// daemon runs the customer-side cryptography locally; the control plane
// relays the opaque payloads (key package / challenge / proof) and never
// sees key material. Every payload carries:
//   - CommandID: the idempotency key (the daemon dedups + acks on it).
//   - NetworkID: the Private Network the operation targets.
//   - TenantID: the tenant, carried so the daemon can bind it into the AAD
//     (the daemon does not otherwise know the tenant id).
//
// The control plane fills TenantID from the authenticated identity / network
// ownership; it is routing metadata, not a secret.

// CryptoActivatePayload asks the selected host to create the first Network
// Key Authority / key epoch for the network, run the crypto self-test, and
// report its public identity + epoch id (plan §11.6 step 4–6).
type CryptoActivatePayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
}

// CryptoKeyPackagePayload asks the NKA host to build the HPKE key package
// sealed to the target host's X25519 public key (enrollment leg 1, §11.7).
type CryptoKeyPackagePayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	// TargetHostID is the enrolling host (the package recipient).
	TargetHostID string `json:"targetHostId"`
	// TargetX25519Pub is the target host's HPKE receiver public key (base64).
	TargetX25519Pub string `json:"targetX25519Pub"`
}

// CryptoInstallKeyPackagePayload carries the HPKE key package to the target
// host, which opens it with its X25519 private key and stores the network
// keyring (enrollment leg 2, §11.7).
type CryptoInstallKeyPackagePayload struct {
	CommandID  string          `json:"commandId"`
	TenantID   string          `json:"tenantId"`
	NetworkID  string          `json:"networkId"`
	KeyPackage e2ee.KeyPackage `json:"keyPackage"`
}

// CryptoChallengePayload asks the NKA host to issue a decryption challenge
// for the target host (enrollment leg 3, §11.7 step 7).
type CryptoChallengePayload struct {
	CommandID    string `json:"commandId"`
	TenantID     string `json:"tenantId"`
	NetworkID    string `json:"networkId"`
	TargetHostID string `json:"targetHostId"`
}

// CryptoProvePayload carries the challenge to the target host, which decrypts
// it and returns the proof (enrollment leg 4, §11.7 step 7).
type CryptoProvePayload struct {
	CommandID string         `json:"commandId"`
	TenantID  string         `json:"tenantId"`
	NetworkID string         `json:"networkId"`
	Challenge e2ee.Challenge `json:"challenge"`
}

// CryptoVerifyPayload carries the challenge + the target host's proof to the
// NKA host, which verifies it (enrollment leg 5, §11.7 step 8).
type CryptoVerifyPayload struct {
	CommandID string         `json:"commandId"`
	TenantID  string         `json:"tenantId"`
	NetworkID string         `json:"networkId"`
	Challenge e2ee.Challenge `json:"challenge"`
	Proof     e2ee.Proof     `json:"proof"`
}

// CryptoRotatePayload asks the NKA host to mint a new key epoch for the
// network (plan §11.8). The previous epoch is marked rotated and retained
// customer-side to read history; the control plane records only the new
// epoch id.
type CryptoRotatePayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
}

// --- crypto ack results ------------------------------------------------------
//
// The daemon reports a crypto command's outcome in the command ack's
// `result` field (a JSON object). These are the result shapes per command.
// They carry public keys and opaque ciphertext only — never key material.

// CryptoHostPublic is a host's public E2EE identity (base64 keys).
type CryptoHostPublic struct {
	// X25519 is the HPKE receiver public key (base64, 32 bytes).
	X25519 string `json:"x25519"`
	// Ed25519 is the signing public key (base64, 32 bytes).
	Ed25519 string `json:"ed25519"`
}

// CryptoActivateResult is the ack result of host.crypto_activate: the host's
// public identity, the new epoch id, and the self-test outcome. A clean ack
// with SelfTestOK=true is what flips the network to active (plan §11.6
// step 6: the state flips ONLY after the self-test round trip succeeds).
type CryptoActivateResult struct {
	HostPub    CryptoHostPublic `json:"hostPub"`
	EpochID    string           `json:"epochId"`
	SelfTestOK bool             `json:"selfTestOk"`
}

// CryptoKeyPackageResult is the ack result of host.crypto_key_package: the
// opaque HPKE key package for the target host.
type CryptoKeyPackageResult struct {
	KeyPackage e2ee.KeyPackage `json:"keyPackage"`
}

// CryptoChallengeResult is the ack result of host.crypto_challenge: the
// opaque decryption challenge for the target host.
type CryptoChallengeResult struct {
	Challenge e2ee.Challenge `json:"challenge"`
}

// CryptoProveResult is the ack result of host.crypto_prove: the target host's
// opaque proof.
type CryptoProveResult struct {
	Proof e2ee.Proof `json:"proof"`
}

// CryptoRotateResult is the ack result of host.crypto_rotate: the id of the
// newly minted epoch.
type CryptoRotateResult struct {
	EpochID string `json:"epochId"`
}

// --- browser key-session commands (plan §13, p10) ----------------------------
//
// These are the request/response crypto operations a browser performs against
// an active private network. The control plane is an OPAQUE RELAY: it
// dispatches the command to a selected key host and relays the ack's result
// byte-for-byte. The daemon runs the customer-side cryptography (HPKE
// base-mode ephemeral-static over the network keyring); the control plane
// never sees plaintext or a CEK. Every payload carries CommandID
// (idempotency), NetworkID (the target), and TenantID (routing metadata the
// daemon binds into its local checks — the daemon does not otherwise know the
// tenant id).
//
// The "session" is an AUTHORIZATION RECORD, not a channel: the daemon holds
// an in-memory {sessionId, userId, networkId, browserPub, createdAt,
// expiresAt} (TTL 15 min, refreshed on use). A daemon restart drops it (the
// same no-durability posture as the NKA challenge store); a stale sessionId
// then fails clean with the stable code `crypto_session_gone`.

// CryptoSessionStartPayload asks the selected key host to record a browser
// session for (userId, networkId) and report its static X25519 public key.
// BrowserPub is the browser's session ephemeral-static X25519 public key
// (base64) — the unwrap target. It is public metadata, not a secret.
type CryptoSessionStartPayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	// SessionID is the server-minted session id (the daemon stores the
	// record under it; the browser reuses it on every operation).
	SessionID string `json:"sessionId"`
	// UserID is the server-attested acting user (routing metadata; the
	// daemon binds it into the session record for the single-flight
	// per-user+network replacement rule).
	UserID string `json:"userId"`
	// BrowserPub is the browser's session ephemeral-static X25519 public
	// key (base64, 32 bytes).
	BrowserPub string `json:"browserPub"`
}

// CryptoSessionStartResult is the ack result of host.crypto_session_start:
// the host's static X25519 public key (base64) — the wrap target for
// browser-originated CEK wraps — plus the network's current key epoch id.
// Public metadata only. The browser needs EpochID to build the write-path
// AAD (the AAD binds key_epoch_id, which the browser cannot know otherwise);
// it encrypts under that epoch and the daemon re-wraps the CEK under the same
// one, so the envelope's key_epoch_id matches the AAD.
type CryptoSessionStartResult struct {
	// HostX25519 is the host's static HPKE receiver public key (base64).
	HostX25519 string `json:"hostX25519"`
	// EpochID is the network's current (announced) key epoch id.
	EpochID string `json:"epochId"`
}

// CryptoHPKEWrap is one HPKE base-mode (X25519/HKDF-SHA256/AES-256-GCM)
// sealed value: the encapsulated (sender ephemeral) key + the ciphertext.
// Byte fields are base64 in JSON. It is the wire shape for a CEK wrapped to
// a static X25519 public key in either direction (daemon→browser unwrap,
// browser→daemon wrap). The control plane relays it opaquely.
type CryptoHPKEWrap struct {
	// Enc is the HPKE encapsulated (ephemeral) key (base64).
	Enc []byte `json:"enc"`
	// Ciphertext is the HPKE-sealed value (base64).
	Ciphertext []byte `json:"ciphertext"`
}

// CryptoUnwrapCekObject is one object in an unwrap batch: its id + the
// stored envelope (opaque — the daemon reads only key_epoch_id +
// wrapped_content_key to unwrap the CEK). The control plane resolves the id
// to the stored envelope and relays it byte-for-byte.
type CryptoUnwrapCekObject struct {
	ObjectID string                  `json:"objectId"`
	Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
}

// CryptoUnwrapCekPayload asks the key host to unwrap each object's CEK with
// the customer-side network epoch key and re-wrap it under the session's
// browser public key. AAD is the AAD the BROWSER will verify against (relayed
// verbatim; the daemon does not need it to unwrap — the CEK wrap carries no
// AAD — and it echoes nothing back).
type CryptoUnwrapCekPayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	SessionID string `json:"sessionId"`
	// AAD is the browser's AAD (relayed verbatim; not used by the unwrap).
	AAD e2ee.AAD `json:"aad"`
	// Objects is the batch (≤ 100), each with its stored envelope.
	Objects []CryptoUnwrapCekObject `json:"objects"`
}

// CryptoUnwrapCekResultItem is one object's unwrap outcome: either the
// HPKE-wrapped CEK (WrappedCek) or a stable per-object error code (Error).
// The error is a STABLE CODE ONLY (e.g. `epoch_unknown`) — never key
// material, keyring paths, or host internals.
type CryptoUnwrapCekResultItem struct {
	ObjectID   string          `json:"objectId"`
	WrappedCek *CryptoHPKEWrap `json:"wrappedCek,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// CryptoUnwrapCekResult is the ack result of host.crypto_unwrap_cek: one
// item per requested object (per-object errors do not fail the batch).
type CryptoUnwrapCekResult struct {
	Results []CryptoUnwrapCekResultItem `json:"results"`
}

// CryptoWrapCekPayload asks the key host to unwrap the browser's HPKE-wrapped
// CEK (sealed to the host's static X25519 public key) and re-wrap it under
// the CURRENT network epoch. ObjectType/ObjectID are routing metadata for the
// browser's AAD (the daemon does not bind them — the browser does).
type CryptoWrapCekPayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	SessionID string `json:"sessionId"`
	// AAD is the browser's AAD (relayed verbatim; not used by the wrap).
	AAD        e2ee.AAD `json:"aad"`
	ObjectType string   `json:"objectType"`
	ObjectID   string   `json:"objectId"`
	// WrappedCek is the browser's HPKE wrap of the fresh CEK (sealed to the
	// host's static public key from the session-start ack).
	WrappedCek CryptoHPKEWrap `json:"wrappedCek"`
}

// CryptoWrapCekResult is the ack result of host.crypto_wrap_cek: the current
// epoch id + the CEK wrapped under it (the p8 keyring format
// nonce||GCM(cek, epochKey), base64). The browser fills the
// EncryptedPayloadV1 envelope with these and submits it through the normal
// protected-field write path.
type CryptoWrapCekResult struct {
	KeyEpochID        string `json:"keyEpochId"`
	WrappedContentKey string `json:"wrappedContentKey"`
}

// CryptoSessionEndPayload asks the key host to drop the browser session
// (explicit teardown). Idempotent: an unknown or already-expired session is
// a clean no-op ack.
type CryptoSessionEndPayload struct {
	CommandID string `json:"commandId"`
	TenantID  string `json:"tenantId"`
	NetworkID string `json:"networkId"`
	SessionID string `json:"sessionId"`
}

// --- protocol v2: endpoint WS (SDK participants) ---------------------------
//
// These are the payloads of the endpoint connection (path /wss/endpoints,
// bearer principal credential). The control plane is a zero-knowledge relay
// for the encrypted parts: Envelope + AAD cross byte-for-byte, and the
// server never reads the ciphertext (it may read key_epoch_id for routing).

// EndpointRegisterPayload is the endpoint's registration on (re)connect.
// PublicKey is the endpoint's X25519 public key (base64) — its crypto
// identity for network enrollment (rotation-capable). Capabilities are the
// endpoint's self-declared capability descriptors (merged with the
// principal's configured descriptors for discovery).
type EndpointRegisterPayload struct {
	// EndpointName is an operator-friendly name for the endpoint ("" =
	// none; display only, not identity).
	EndpointName string              `json:"endpointName,omitempty"`
	PublicKey    string              `json:"publicKey"`
	SDKVersion   string              `json:"sdkVersion"`
	Region       string              `json:"region,omitempty"`
	Capabilities []domain.Capability `json:"capabilities"`
}

// EndpointAuthOKPayload is the server's registration acceptance.
type EndpointAuthOKPayload struct {
	PrincipalID string `json:"principalId"`
	EndpointID  string `json:"endpointId"`
	// NetworkIDs are the networks the principal is an active member of.
	NetworkIDs []string `json:"networkIds"`
	// Credential is the durable endpoint credential — returned ONLY on
	// first use with an activation credential (the one-time durable
	// secret; the client stores it and presents it on later connects).
	Credential string `json:"credential,omitempty"`
	// ProtocolVersion is the protocol version the server speaks.
	ProtocolVersion int `json:"protocolVersion"`
}

// EndpointMessageDeliverPayload is one durable message for the endpoint's
// principal. The message parts cross as the encrypted envelope (object
// type message); the plaintext fields are routing metadata only.
type EndpointMessageDeliverPayload struct {
	MessageID string `json:"messageId"`
	NetworkID string `json:"networkId"`
	ThreadID  string `json:"threadId"`
	// Kind: ASK | REPLY | NOTICE | STATUS (domain.MessageKind).
	Kind string `json:"kind"`
	// SenderPrincipalID is the message's sender principal.
	SenderPrincipalID string `json:"senderPrincipalId"`
	// Envelope is the E2EE envelope for the encrypted message parts.
	Envelope *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	// AAD is the associated-data the Envelope was bound to, relayed
	// verbatim (the AAD server obligation, PROTOCOL §3).
	AAD *e2ee.AAD `json:"aad,omitempty"`
}

// EndpointMessageAckedPayload acknowledges one delivered message.
type EndpointMessageAckedPayload struct {
	MessageID string `json:"messageId"`
}

// EndpointEventDeliverPayload is one event delivery for a subscription of
// the endpoint's principal. The event payload crosses as the encrypted
// envelope (object type event_payload); the plaintext fields are routing
// metadata only (matching is metadata-only — never the payload).
type EndpointEventDeliverPayload struct {
	EventID    string `json:"eventId"`
	DeliveryID string `json:"deliveryId"`
	NetworkID  string `json:"networkId"`
	EventType  string `json:"eventType"`
	// ProducerPrincipalID is the event's producer principal ("" when the
	// event has none, e.g. system events).
	ProducerPrincipalID string `json:"producerPrincipalId,omitempty"`
	// Envelope is the E2EE envelope for the encrypted event payload.
	Envelope *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	// AAD is the associated-data the Envelope was bound to, relayed
	// verbatim (the AAD server obligation, PROTOCOL §3).
	AAD *e2ee.AAD `json:"aad,omitempty"`
}

// EndpointEventAckPayload acknowledges one event delivery.
type EndpointEventAckPayload struct {
	DeliveryID string `json:"deliveryId"`
	EventID    string `json:"eventId"`
}

// EndpointInvocationDispatchPayload is one capability invocation for the
// endpoint's principal. The input crosses as the encrypted envelope
// (object type invocation_input); the plaintext fields are routing
// metadata only.
type EndpointInvocationDispatchPayload struct {
	InvocationID      string `json:"invocationId"`
	NetworkID         string `json:"networkId"`
	CapabilityID      string `json:"capabilityId"`
	CapabilityVersion int    `json:"capabilityVersion"`
	IdempotencyKey    string `json:"idempotencyKey"`
	CorrelationID     string `json:"correlationId,omitempty"`
	CausationID       string `json:"causationId,omitempty"`
	// Envelope is the E2EE envelope for the encrypted invocation input.
	Envelope *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	// AAD is the associated-data the Envelope was bound to, relayed
	// verbatim (the AAD server obligation, PROTOCOL §3).
	AAD *e2ee.AAD `json:"aad,omitempty"`
}

// EndpointInvocationAcceptPayload acknowledges that the endpoint accepted
// the invocation (it will produce a result).
type EndpointInvocationAcceptPayload struct {
	InvocationID string `json:"invocationId"`
}

// EndpointInvocationResultPayload is the invocation's outcome. Envelope
// carries the encrypted output (object type invocation_output) when OK, or
// the encrypted error detail (object type invocation_error) when not.
type EndpointInvocationResultPayload struct {
	InvocationID string `json:"invocationId"`
	OK           bool   `json:"ok"`
	// Envelope is the E2EE envelope for the encrypted output or error.
	Envelope *e2ee.EncryptedPayloadV1 `json:"envelope,omitempty"`
	// AAD is the associated-data the Envelope was bound to, relayed
	// verbatim (the AAD server obligation, PROTOCOL §3).
	AAD *e2ee.AAD `json:"aad,omitempty"`
	// PublicResultCode is the public-safe outcome code (stable code only —
	// never protected content).
	PublicResultCode string `json:"publicResultCode,omitempty"`
	// UsageMetadata is the public-safe usage accounting (tokens, duration,
	// ...).
	UsageMetadata map[string]any `json:"usageMetadata,omitempty"`
}

// EndpointHeartbeatPayload is the endpoint's liveness + load report.
type EndpointHeartbeatPayload struct {
	// Inflight is the number of deliveries/invocations accepted but not
	// yet finished (the control plane's load signal for selection).
	Inflight int `json:"inflight"`
}

// EndpointHeartbeatAckPayload is the server's heartbeat acknowledgement
// (no fields).
type EndpointHeartbeatAckPayload struct{}

// EndpointDisconnectPayload is the endpoint's graceful shutdown notice
// (no fields; pending work stays durable).
type EndpointDisconnectPayload struct{}

// EndpointStatusPayload is the daemon's managed-agent endpoint liveness
// report (host.endpoint_status).
type EndpointStatusPayload struct {
	// AgentPrincipalID is the managed agent's principal.
	AgentPrincipalID string `json:"agentPrincipalId"`
	// InstanceID is the managed instance behind the endpoint.
	InstanceID string `json:"instanceId"`
	Online     bool   `json:"online"`
}
