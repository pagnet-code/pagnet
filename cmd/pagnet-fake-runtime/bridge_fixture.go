package main

// The bridge fixtures (security wave S1 e2e). A real runtime consumes the
// daemon-rendered PAGNET_MCP_CONFIG as its MCP client config: it spawns
// the configured bridge command as its child and talks MCP stdio to it.
// The fake endpoint plays that role on script, so the daemon's bridge
// socket is exercised end-to-end (the bridge authenticates with the
// daemon-minted nonce, and — on Linux — the daemon verifies the
// connection's process tree against the endpoint's PID).
//
// Two modes (both OFF unless their flag is set):
//
//	PAGNET_FAKE_SPAWN_BRIDGE=1
//	  Spawn the MCP config's bridge command as this endpoint's child
//	  (the production bridge), speak MCP stdio to it (initialize,
//	  notifications/initialized, tools/call with the scripted tool/args),
//	  and write the observed MCP responses to PAGNET_FAKE_BRIDGE_RESULT_FILE.
//	  This is the faithful production path: real bridge binary, real
//	  per-activation nonce from the config env, real daemon auth.
//
//	PAGNET_FAKE_HOSTILE_BRIDGE=1
//	  THIS endpoint process — the supervisor's root — dials the bridge
//	  socket itself with the raw daemon bridge protocol, presenting the
//	  config's nonce. It is the in-tree raw client for dispatch-level
//	  assertions (auth_ok, per-identity tool-surface enforcement, idle
//	  survival, bad-request handling) that a legitimate MCP client could
//	  never drive (its registered surface does not include them): a
//	  compromised runtime process using its own valid credentials.
//
// The result file (PAGNET_FAKE_BRIDGE_RESULT_FILE) holds a JSON array of
// the raw response lines observed (the MCP response objects in spawn mode;
// the daemon bridge protocol responses in hostile mode), so a test polls
// the file and asserts on the protocol facts.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// bridgeMCPConfig is the daemon-rendered MCP client config shape.
type bridgeMCPConfig struct {
	MCPServers map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
}

// firstBridgeServer returns the (single) bridge server entry from the
// rendered config, plus the identity/credential values the bridge needs.
func firstBridgeServer() (serverName, command string, args []string, env map[string]string, err error) {
	raw := os.Getenv("PAGNET_MCP_CONFIG")
	if raw == "" {
		return "", "", nil, nil, fmt.Errorf("PAGNET_MCP_CONFIG is not set")
	}
	var cfg bridgeMCPConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", "", nil, nil, fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
	}
	if len(cfg.MCPServers) != 1 {
		return "", "", nil, nil, fmt.Errorf("expected exactly one mcp server entry, got %d", len(cfg.MCPServers))
	}
	for name, srv := range cfg.MCPServers {
		serverName, command, args, env = name, srv.Command, srv.Args, srv.Env
	}
	return serverName, command, args, env, nil
}

// bridgeIdentity extracts the bridge's identity + nonce from the config
// env (the daemon renders PAGNET_INSTANCE_ID / PAGNET_NETWORK_ID /
// PAGNET_BRIDGE_NONCE into the bridge server's env) and the socket path
// from the command args. kind follows the server name the daemon renders
// ("pagnet" = worker, "pagnet-control" = representative).
func bridgeIdentity(serverName string, args []string, env map[string]string) (instanceID, networkID, nonce, kind, socket string) {
	instanceID = env["PAGNET_INSTANCE_ID"]
	networkID = env["PAGNET_NETWORK_ID"]
	nonce = env["PAGNET_BRIDGE_NONCE"]
	if serverName == "pagnet-control" {
		kind = "representative"
	} else {
		kind = "worker"
	}
	for i, a := range args {
		if a == "--socket" && i+1 < len(args) {
			socket = args[i+1]
		}
	}
	return
}

// writeBridgeResultFile writes the observed response lines as a JSON
// array to the result file (the test's synchronization point).
func writeBridgeResultFile(lines [][]byte) {
	path := os.Getenv("PAGNET_FAKE_BRIDGE_RESULT_FILE")
	if path == "" {
		return
	}
	out := bytes.NewBufferString("[")
	for i, l := range lines {
		if i > 0 {
			out.WriteString(",")
		}
		out.Write(l)
	}
	out.WriteString("]")
	if err := os.WriteFile(path, append(out.Bytes(), '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: write result file:", err)
	}
}

// spawnBridgeFixture is the faithful MCP-client mode: spawn the config's
// bridge command as a child, drive one MCP tools/call, record the
// responses. It runs until the endpoint is told to stop.
func spawnBridgeFixture(stopping <-chan struct{}) {
	_, command, args, env, err := firstBridgeServer()
	if err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": err.Error()})})
		return
	}
	tool := os.Getenv("PAGNET_FAKE_BRIDGE_TOOL")
	if tool == "" {
		tool = "network_whoami"
	}
	toolArgs := map[string]any{}
	if raw := os.Getenv("PAGNET_FAKE_BRIDGE_ARGS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &toolArgs); err != nil {
			writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "bad PAGNET_FAKE_BRIDGE_ARGS: " + err.Error()})})
			return
		}
	}

	// The child inherits this endpoint's environment (PATH/HOME from the
	// daemon's allowlisted ChildEnv) plus the config's bridge env —
	// exactly what a real runtime's MCP client passes.
	childEnv := append(os.Environ(), mapToEnv(env)...)
	cmd := exec.Command(command, args...)
	cmd.Env = childEnv
	stdin, err := cmd.StdinPipe()
	if err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": err.Error()})})
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": err.Error()})})
		return
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "spawn bridge: " + err.Error()})})
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	writeLine := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = stdin.Write(append(b, '\n'))
	}
	// readLineUntil reads MCP stdio (newline-delimited JSON-RPC) until a
	// line carrying the given JSON-RPC id, or the deadline / shutdown.
	readLineUntil := func(id int) []byte {
		r := bufio.NewReader(stdout)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			line, err := r.ReadString('\n')
			if err != nil {
				return mustJSONLine(map[string]any{"fixture": "error", "error": "read bridge stdio: " + err.Error() + " stderr: " + stderr.String()})
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				continue
			}
			var probe struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal([]byte(line), &probe) == nil && string(probe.ID) == fmt.Sprint(id) {
				return []byte(line)
			}
		}
		return mustJSONLine(map[string]any{"fixture": "error", "error": "timed out waiting for the bridge response", "stderr": stderr.String()})
	}

	select {
	case <-stopping:
		return
	default:
	}
	var observed [][]byte
	// MCP handshake (newline-delimited JSON-RPC, the stdio transport).
	writeLine(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "pagnet-fake-runtime", "version": "1.0.0"},
		},
	})
	observed = append(observed, readLineUntil(1))
	writeLine(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	// The scripted tool call (relayed by the daemon over the host
	// connection; the response comes back through the same pipe).
	writeLine(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": toolArgs},
	})
	observed = append(observed, readLineUntil(2))
	writeBridgeResultFile(observed)
}

// hostileBridgeFixture is the in-tree raw-client mode: this endpoint
// process (the supervisor's root for the instance) dials the bridge
// socket with the raw daemon protocol, authenticating with the
// daemon-minted nonce.
func hostileBridgeFixture() {
	serverName, _, args, env, err := firstBridgeServer()
	if err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": err.Error()})})
		return
	}
	instanceID, networkID, nonce, kind, socket := bridgeIdentity(serverName, args, env)
	if socket == "" {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "no socket in the MCP config args"})})
		return
	}
	tool := os.Getenv("PAGNET_FAKE_HOSTILE_TOOL")
	if tool == "" {
		tool = "network_whoami"
	}
	toolArgs := map[string]any{}
	if raw := os.Getenv("PAGNET_FAKE_HOSTILE_ARGS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &toolArgs); err != nil {
			writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "bad PAGNET_FAKE_HOSTILE_ARGS: " + err.Error()})})
			return
		}
	}
	var idle time.Duration
	if s := os.Getenv("PAGNET_FAKE_HOSTILE_IDLE"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			idle = d
		}
	}
	badReq := os.Getenv("PAGNET_FAKE_HOSTILE_BADREQ") == "1"

	conn, err := net.Dial("unix", socket)
	if err != nil {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "dial: " + err.Error()})})
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	exchange := func(req any) []byte {
		b, _ := json.Marshal(req)
		if _, err := conn.Write(append(b, '\n')); err != nil {
			return mustJSONLine(map[string]any{"fixture": "error", "error": "write: " + err.Error()})
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return mustJSONLine(map[string]any{"fixture": "error", "error": "read: " + err.Error()})
		}
		return []byte(strings.TrimRight(line, "\r\n"))
	}

	var observed [][]byte
	observed = append(observed, exchange(map[string]any{
		"type": "auth", "instanceId": instanceID, "networkId": networkID,
		"nonce": nonce, "kind": kind,
	}))
	if idle > 0 {
		time.Sleep(idle)
	}
	if badReq {
		observed = append(observed, exchange(map[string]any{"id": "", "tool": "network_whoami"}))
		observed = append(observed, exchange(map[string]any{"id": "7", "tool": ""}))
	}
	observed = append(observed, exchange(map[string]any{"id": "h1", "tool": tool, "args": toolArgs}))
	writeBridgeResultFile(observed)
}

func mapToEnv(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

func mustJSONLine(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"fixture":"error","error":"fixture encode failed"}`)
	}
	return b
}
