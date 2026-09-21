package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// The agent bridge socket. A managed agent never holds the host
// credential: it talks to the network only through the MCP bridge
// process (the daemon's own executable, spawned as <self> mcp worker),
// which connects to THIS socket and authenticates with the
// instance identity the daemon injected into its environment
// (PAGNET_INSTANCE_ID / PAGNET_NETWORK_ID). The daemon validates that
// identity against the instances IT launched, then relays the tool call
// over the host connection (agent.request) and answers the correlated
// agent.response to the waiting socket client (PROTOCOL §6).
//
// Wire format: newline-delimited JSON.
//   {"type":"auth","instanceId":"…","networkId":"…"}  (first message)
//   {"type":"auth_ok","instanceId":"…"}               (success)
//   {"type":"error","error":"…"}                      (auth failed; closes)
//   {"id":"…","tool":"network_ask","args":{…}}        (tool call)
//   {"id":"…","ok":true,"result":{…}} | {"id":"…","ok":false,"error":"…"}

const (
	bridgeSocketName     = "pagnetd.sock"
	bridgeAuthTimeout    = 5 * time.Second
	bridgeRequestTimeout = 60 * time.Second
	bridgeMaxLine        = 1 << 20 // 1 MiB per JSON line
	// Connection caps (external audit F-010): a managed agent opens ONE
	// bridge connection per MCP client; a misbehaving or hostile agent
	// must not be able to exhaust daemon resources by opening unbounded
	// connections. Global cap bounds the total; per-instance cap bounds
	// one agent's share.
	bridgeMaxConns        = 256
	bridgeMaxConnsPerInst = 8
	// Bounded pending relays (external audit F-010): the pending
	// agent.request map must not grow without bound (a hostile client
	// could open many in-flight requests and exhaust memory).
	bridgeMaxPending = 128
)

// bridgeConnReadTimeoutNs (external audit F-010): read deadline after
// Accept, in nanoseconds. A connection that connects but never sends its
// auth (slow-loris) must not hold a goroutine and a socket descriptor
// indefinitely. It is an atomic (not a const) so tests can shorten it
// without a data race (the handler goroutine reads it concurrently).
// Production default: 30s.
var bridgeConnReadTimeoutNs int64 = int64(30 * time.Second)

// startBridgeSocket opens the local Unix socket. Called once from Run.
func (d *Daemon) startBridgeSocket() error {
	sockPath := filepath.Join(d.StateDir, bridgeSocketName)
	// Double-start guard: a LIVE daemon already owns this socket? Refuse
	// to start. Two daemons on one host fight over the host identity —
	// each new connection supersedes the other, in an endless
	// reconnect loop that flaps the host online/offline. A stale socket
	// file (crashed daemon) is safe to replace: connect() to a socket
	// with no listener fails, so only a live daemon answers the probe.
	if probe, perr := net.Dial("unix", sockPath); perr == nil {
		_ = probe.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = probe.Write([]byte(`{"type":"auth","instanceId":"pagnet-probe","networkId":""}` + "\n"))
		buf := make([]byte, 1)
		_, rerr := probe.Read(buf)
		_ = probe.Close()
		if rerr == nil {
			return fmt.Errorf("another daemon is already running (bridge socket %s is live); stop it first", sockPath)
		}
	}
	_ = os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("bridge socket: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = l.Close()
		return err
	}
	d.bridgeMu.Lock()
	d.bridgeL = l
	d.bridgeMu.Unlock()
	d.Log.Info("agent bridge socket listening", "socket", sockPath)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			go d.handleBridgeConn(c)
		}
	}()
	return nil
}

// stopBridgeSocket closes the listener and removes the socket file.
func (d *Daemon) stopBridgeSocket() {
	d.bridgeMu.Lock()
	defer d.bridgeMu.Unlock()
	if d.bridgeL == nil {
		return
	}
	_ = d.bridgeL.Close()
	_ = os.Remove(filepath.Join(d.StateDir, bridgeSocketName))
	d.bridgeL = nil
}

// acquireBridgeConn reserves a connection slot under the global and
// per-instance caps (external audit F-010). It returns false when the
// cap is reached; the caller must close the connection. The per-instance
// count is only known after auth, so the global slot is taken up front
// and the per-instance slot is taken (and, on failure, released) after
// the instance id is known.
func (d *Daemon) acquireBridgeConn() bool {
	d.bridgeConnMu.Lock()
	defer d.bridgeConnMu.Unlock()
	if d.bridgeConns >= bridgeMaxConns {
		return false
	}
	d.bridgeConns++
	return true
}

// acquireBridgeInstSlot reserves a per-instance slot (after auth). It
// returns false when the instance's cap is reached; the caller must
// release the global slot too.
func (d *Daemon) acquireBridgeInstSlot(instanceID string) bool {
	d.bridgeConnMu.Lock()
	defer d.bridgeConnMu.Unlock()
	if d.bridgeConnsInst[instanceID] >= bridgeMaxConnsPerInst {
		return false
	}
	d.bridgeConnsInst[instanceID]++
	return true
}

// releaseBridgeConn releases a global slot and (when instanceID != "")
// the per-instance slot.
func (d *Daemon) releaseBridgeConn(instanceID string) {
	d.bridgeConnMu.Lock()
	defer d.bridgeConnMu.Unlock()
	if d.bridgeConns > 0 {
		d.bridgeConns--
	}
	if instanceID != "" {
		if d.bridgeConnsInst[instanceID] > 0 {
			d.bridgeConnsInst[instanceID]--
		}
		if d.bridgeConnsInst[instanceID] == 0 {
			delete(d.bridgeConnsInst, instanceID)
		}
	}
}

func (d *Daemon) handleBridgeConn(c net.Conn) {
	defer c.Close()
	// Read deadline after Accept (external audit F-010): a connection
	// that never sends its auth (slow-loris) is cut off instead of
	// holding a goroutine + socket descriptor indefinitely.
	_ = c.SetReadDeadline(time.Now().Add(time.Duration(atomic.LoadInt64(&bridgeConnReadTimeoutNs))))
	// Global connection cap (external audit F-010).
	if !d.acquireBridgeConn() {
		writeBridgeError(c, "bridge connection limit reached")
		return
	}
	instanceID := ""
	defer d.releaseBridgeConn(instanceID)
	r := bufio.NewReader(c)

	line, err := readLine(r)
	if err != nil {
		return
	}
	var auth struct {
		Type       string `json:"type"`
		InstanceID string `json:"instanceId"`
		NetworkID  string `json:"networkId"`
	}
	if err := json.Unmarshal(line, &auth); err != nil || auth.Type != "auth" {
		writeBridgeError(c, "first message must be auth")
		return
	}
	row, ok, err := d.state.GetInstance(auth.InstanceID)
	if err != nil || !ok {
		writeBridgeError(c, "unknown instance (identity rejected)")
		return
	}
	if row.NetworkID != "" && auth.NetworkID != row.NetworkID {
		writeBridgeError(c, "network mismatch for this instance (identity rejected)")
		return
	}
	if row.Status == "stopped" {
		writeBridgeError(c, "instance is stopped")
		return
	}
	// Per-instance connection cap (external audit F-010): a single agent
	// must not hold unbounded bridge connections. On failure the deferred
	// releaseBridgeConn("") still releases the global slot.
	if !d.acquireBridgeInstSlot(row.InstanceID) {
		writeBridgeError(c, "bridge connection limit reached for this instance")
		return
	}
	instanceID = row.InstanceID
	if _, err := writeBridge(c, map[string]any{
		"type": "auth_ok", "instanceId": row.InstanceID,
	}); err != nil {
		return
	}
	d.Log.Info("bridge authenticated", "instance", row.InstanceID)
	// The read deadline above bounds the AUTH phase only (slow-loris). A
	// managed agent keeps ONE bridge connection for the endpoint's whole
	// lifetime and is legitimately quiet on it for minutes at a time —
	// the model works on non-bridge tools between network calls. The
	// deadline is absolute since Accept, so it must be cleared here:
	// left in force, it severs the connection 30s after auth and the
	// next tool call fails with EOF, bricking the agent's network
	// surface for the rest of the endpoint's life. Resource bounds for
	// authenticated connections come from the caps above, not a timer.
	_ = c.SetReadDeadline(time.Time{})

	// Tool-call loop until the client disconnects.
	for {
		line, err := readLine(r)
		if err != nil {
			return
		}
		var req struct {
			ID   string          `json:"id"`
			Tool string          `json:"tool"`
			Args json.RawMessage `json:"args"`
		}
		// Non-empty id AND tool (external audit F-010): a request with no
		// id cannot be correlated to a response, and an empty tool is a
		// no-op that would still consume a relay slot.
		if err := json.Unmarshal(line, &req); err != nil || req.ID == "" || req.Tool == "" {
			writeBridge(c, map[string]any{"id": req.ID, "ok": false,
				"error": "bad request (need non-empty id + tool)"})
			continue
		}
		if req.Args == nil {
			req.Args = json.RawMessage("{}")
		}
		// V2: network_register_capabilities is handled LOCALLY by the daemon
		// (not relayed to the server): the agent's self-declared capability
		// set (version 1) is persisted on the instance row and reported via
		// host.endpoint_status, from which the control plane upserts
		// endpoint_capabilities. It carries no protected content (metadata),
		// so it runs on any network state.
		if req.Tool == "network_register_capabilities" {
			result, errMsg := d.registerInstanceCapabilities(row, req.Args)
			resp := map[string]any{"id": req.ID}
			if errMsg == "" {
				resp["ok"] = true
				resp["result"] = result
			} else {
				resp["ok"] = false
				resp["error"] = errMsg
			}
			if _, err := writeBridge(c, resp); err != nil {
				return
			}
			continue
		}
		// E2EE (plan §12) + D6 (always-encrypted): the daemon encrypts the
		// tool call's protected fields before they cross the cloud boundary
		// (the server stores/relays the opaque envelope + verbatim AAD and
		// routes on metadata without decrypting). A call that carries content
		// on a network whose crypto is not active is refused (no plaintext
		// path); metadata-only calls pass through unchanged.
		encArgs, encErr := d.encryptToolArgs(row, req.Tool, req.Args)
		if encErr != "" {
			resp := map[string]any{"id": req.ID, "ok": false, "error": encErr}
			if _, err := writeBridge(c, resp); err != nil {
				return
			}
			continue
		}
		result, errMsg := d.relayToServer(row.InstanceID, row.AgentPrincipalID, req.Tool, encArgs)
		// Track the rep's active network: the daemon needs it to encrypt a
		// rep's control tool with no explicit networkId (the server resolves
		// the network from the rep context, but the daemon must encrypt under
		// the same network's crypto). Any control tool that names a network
		// explicitly updates the tracking (control_use_network, control_ask
		// with networkId, ...).
		if errMsg == "" && row.NetworkID == "" {
			var nu struct {
				NetworkID string `json:"networkId"`
			}
			if json.Unmarshal(req.Args, &nu) == nil && nu.NetworkID != "" {
				d.setRepNetwork(row.InstanceID, nu.NetworkID)
			}
		}
		resp := map[string]any{"id": req.ID}
		if errMsg == "" {
			resp["ok"] = true
			resp["result"] = result
		} else {
			resp["ok"] = false
			resp["error"] = errMsg
		}
		if _, err := writeBridge(c, resp); err != nil {
			return
		}
	}
}

// toolArgsWire renames the agent-facing bridge tool arguments onto the control
// plane's agent-command field names. The bridge surface (and the MCP tools that
// mirror it) advertise the short names an agent naturally writes; the server
// validates its own contract strictly, so a tool whose advertised names differ
// from it can never be satisfied — the call fails "… required" before doing any
// work.
//
// Only the tools that actually differ are listed; every other tool already
// speaks the server's field names.
var toolArgsWire = map[string]map[string]string{
	"network_event_publish": {"type": "eventType", "target": "targetPrincipalId"},
	"network_subscribe":     {"pattern": "eventPattern", "mode": "deliveryMode"},
	// network_invoke: the agent-facing tool advertises the short "capability"
	// name (tools_generic.go); the control plane's toolInvoke decodes
	// "capabilityId" and answers "capabilityId required" when it is absent.
	// Its decode is a plain json.Unmarshal (NOT the strict decodeBody the REST
	// API uses), so the agent-facing name is silently dropped rather than
	// rejected — the call can never reach the invoke.
	"network_invoke": {"capability": "capabilityId"},
}

// wireArgs applies toolArgsWire to one relayed call.
//
// It runs AFTER encryptToolArgs on purpose: the AAD binds the tool's own
// argument (network_event_publish's recipient comes from "target"), so the
// encryption layer must see the agent-facing names, and only the bytes that
// cross the cloud boundary are renamed.
func wireArgs(tool string, args json.RawMessage) json.RawMessage {
	renames, ok := toolArgsWire[tool]
	if !ok || len(args) == 0 {
		return args
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return args // not a JSON object: relay unchanged, the server validates
	}
	changed := false
	for from, to := range renames {
		if v, ok := m[from]; ok {
			delete(m, from)
			m[to] = v
			changed = true
		}
	}
	if !changed {
		return args
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return args
	}
	return raw
}

// relayToServer forwards one tool call over the host connection and waits
// for the correlated agent.response. principalID is the instance's agent
// principal (V2): the daemon resolves EVERY network operation against it,
// so the control plane authorizes and routes on the PRINCIPAL (representative
// re-authorization, plan §17-18), not on the instance.
func (d *Daemon) relayToServer(instanceID, principalID, tool string, args json.RawMessage) (json.RawMessage, string) {
	args = wireArgs(tool, args)
	d.connMu.Lock()
	conn := d.curConn
	d.connMu.Unlock()
	if conn == nil {
		return nil, "control plane not connected; retry shortly"
	}
	env, err := transport.NewEnvelope(transport.MsgAgentRequest, transport.AgentRequestPayload{
		InstanceID:  instanceID,
		PrincipalID: principalID,
		Tool:        tool,
		Args:        args,
	})
	if err != nil {
		return nil, err.Error()
	}
	// The server echoes the request envelope's id back as the response's
	// RequestID, so the correlation key IS env.ID.
	// Bounded pending (external audit F-010): a hostile client could open
	// many in-flight requests and exhaust memory, so the pending map is
	// capped. Refuse new relays once the cap is reached (the caller
	// answers the bridge client with the error). The length check is done
	// under the same lock that guards the map (reading a map while another
	// goroutine writes it is a data race).
	d.pendingMu.Lock()
	if len(d.pending) >= bridgeMaxPending {
		d.pendingMu.Unlock()
		return nil, "too many in-flight bridge requests; retry shortly"
	}
	respCh := make(chan transport.AgentResponsePayload, 1)
	d.pending[env.ID] = respCh
	d.pendingMu.Unlock()
	defer func() {
		d.pendingMu.Lock()
		delete(d.pending, env.ID)
		d.pendingMu.Unlock()
	}()

	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err.Error()
	}
	if err := d.write(conn, raw); err != nil {
		return nil, "send to control plane failed: " + err.Error()
	}
	select {
	case resp := <-respCh:
		if !resp.OK {
			if resp.Error == "" {
				return nil, "control plane error (no detail)"
			}
			return nil, resp.Error
		}
		return resp.Result, ""
	case <-time.After(bridgeRequestTimeout):
		return nil, "control plane did not respond (timeout)"
	}
}

// deliverAgentResponse routes an agent.response envelope from the read
// loop to the waiting bridge client (if any).
func (d *Daemon) deliverAgentResponse(env transport.Envelope) {
	var p transport.AgentResponsePayload
	if err := env.DecodePayload(&p); err != nil || p.RequestID == "" {
		return
	}
	d.pendingMu.Lock()
	ch, ok := d.pending[p.RequestID]
	if ok {
		delete(d.pending, p.RequestID)
	}
	d.pendingMu.Unlock()
	if ok {
		ch <- p
	}
}

// registerInstanceCapabilities handles the agent's network_register_
// capabilities declaration (V2, version 1). It is the daemon's LOCAL
// interception of that tool: the declared set is persisted on the instance
// row (targeted single-column update, so concurrent status writes are not
// clobbered) and re-reported via host.endpoint_status, from which the
// control plane upserts endpoint_capabilities. It is NOT relayed to the
// server as an agent.request — the endpoint_status report IS the
// registration path. The declared set REPLACES the prior declaration (the
// agent re-declares its full set; the report carries the current full set).
//
// Returns the result JSON (the registered set) or an error message.
func (d *Daemon) registerInstanceCapabilities(row *InstanceRow, args json.RawMessage) (json.RawMessage, string) {
	var m struct {
		Capabilities []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(args, &m); err != nil {
		return nil, "register_capabilities: could not parse args (need {\"capabilities\":[...]})"
	}
	if len(m.Capabilities) == 0 {
		return nil, "register_capabilities: 'capabilities' must be a non-empty array"
	}
	caps := make([]domain.Capability, 0, len(m.Capabilities))
	seen := make(map[string]bool, len(m.Capabilities))
	for _, c := range m.Capabilities {
		id := strings.TrimSpace(c.ID)
		if id == "" {
			return nil, "register_capabilities: every capability needs a non-empty 'id'"
		}
		if seen[id] {
			continue // de-duplicate by id (the first declaration wins)
		}
		seen[id] = true
		name := strings.TrimSpace(c.Name)
		if name == "" {
			name = id
		}
		caps = append(caps, domain.Capability{
			ID:          id,
			Version:     1,
			Name:        name,
			Description: c.Description,
		})
	}
	if err := d.state.SetInstanceCapabilities(row.InstanceID, caps); err != nil {
		return nil, "register_capabilities: persist failed: " + err.Error()
	}
	// Re-report the endpoint status carrying the updated capability set
	// (reportEndpointStatus re-reads the row, so it picks up the new caps).
	// The conn is nil: d.send routes to the live host connection.
	d.reportEndpointStatus(nil, row.InstanceID)
	d.Log.Info("capabilities registered", "instance", row.InstanceID, "count", len(caps))
	out, err := json.Marshal(map[string]any{
		"registered": caps,
		"count":      len(caps),
	})
	if err != nil {
		return nil, "register_capabilities: encode failed: " + err.Error()
	}
	return out, ""
}

// readLine reads one newline-terminated line, bounded to bridgeMaxLine.
func readLine(r *bufio.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			return buf, nil
		}
		buf = append(buf, b)
		if len(buf) > bridgeMaxLine {
			return nil, errors.New("line too long")
		}
	}
}

func writeBridge(c net.Conn, v any) (int, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return c.Write(append(raw, '\n'))
}

func writeBridgeError(c net.Conn, msg string) {
	_, _ = writeBridge(c, map[string]any{"type": "error", "error": msg})
}
