package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"pagnet/internal/transport"
)

// The agent bridge socket. A managed agent never holds the host
// credential: it talks to the network only through the pagnet-mcp
// process, which connects to THIS socket and authenticates with the
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
)

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
		_, _ = probe.Write([]byte(`{"type":"auth","instanceId":"pagnetd-probe","networkId":""}` + "\n"))
		buf := make([]byte, 1)
		_, rerr := probe.Read(buf)
		_ = probe.Close()
		if rerr == nil {
			return fmt.Errorf("another pagnetd is already running (bridge socket %s is live); stop it first", sockPath)
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

func (d *Daemon) handleBridgeConn(c net.Conn) {
	defer c.Close()
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
	if _, err := writeBridge(c, map[string]any{
		"type": "auth_ok", "instanceId": row.InstanceID,
	}); err != nil {
		return
	}
	d.Log.Debug("bridge authenticated", "instance", row.InstanceID)

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
		if err := json.Unmarshal(line, &req); err != nil || req.Tool == "" {
			writeBridge(c, map[string]any{"id": req.ID, "ok": false,
				"error": "bad request (need id + tool)"})
			continue
		}
		if req.Args == nil {
			req.Args = json.RawMessage("{}")
		}
		result, errMsg := d.relayToServer(row.InstanceID, req.Tool, req.Args)
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

// relayToServer forwards one tool call over the host connection and waits
// for the correlated agent.response.
func (d *Daemon) relayToServer(instanceID, tool string, args json.RawMessage) (json.RawMessage, string) {
	d.connMu.Lock()
	conn := d.curConn
	d.connMu.Unlock()
	if conn == nil {
		return nil, "control plane not connected; retry shortly"
	}
	env, err := transport.NewEnvelope(transport.MsgAgentRequest, transport.AgentRequestPayload{
		InstanceID: instanceID,
		Tool:       tool,
		Args:       args,
	})
	if err != nil {
		return nil, err.Error()
	}
	// The server echoes the request envelope's id back as the response's
	// RequestID, so the correlation key IS env.ID.
	respCh := make(chan transport.AgentResponsePayload, 1)
	d.pendingMu.Lock()
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
