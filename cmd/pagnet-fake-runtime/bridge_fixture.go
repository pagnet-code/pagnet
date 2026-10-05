package main

// The bridge fixtures (security wave S1 e2e). A real runtime consumes the
// daemon-rendered PAGNET_MCP_CONFIG as its MCP client config: it spawns
// the configured bridge command as its child and talks MCP stdio to it.
// The fake endpoint plays that role on script, so the daemon's bridge
// socket is exercised end-to-end (the bridge authenticates with the
// daemon-minted nonce, and — on Linux — the daemon verifies the
// connection's process tree against the endpoint's PID).
//
// Three modes (all OFF unless their flag is set):
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
//	  PAGNET_FAKE_HOSTILE_CALLS (optional extension): a JSON array of
//	  {"id","tool","args"} objects, or PAGNET_FAKE_HOSTILE_CALLS_FILE: a
//	  path to a file holding that array. The file form exists because a
//	  host whose runtime env travels the comma-separated PAGNET_RUNTIME_
//	  ENV pair list cannot carry the array's commas inline (the e2e
//	  harness); the file is read from a sandbox-granted dir (the e2e
//	  suites put it next to PAGNET_FAKE_BRIDGE_RESULT_FILE). Setting
//	  BOTH is a fixture error (ambiguous configuration). When set, the
//	  scripted calls are executed IN ORDER on the same connection after
//	  the auth exchange (and the optional PAGNET_FAKE_HOSTILE_IDLE
//	  sleep), each under its own exchange deadline, and each response is
//	  appended to the observed lines — so one endpoint activation can
//	  script a whole daemon-bridge session (used by the DY acceptance
//	  suite, where a one-shot turn process must publish/subscribe/
//	  delegate DURING its turn). When NOT set, the single-tool behavior
//	  (PAGNET_FAKE_HOSTILE_TOOL/ARGS, the optional BADREQ probes) is
//	  unchanged.
//
//	  On the ONE-SHOT (process-per-turn) endpoint the hostile fixture
//	  runs SYNCHRONOUSLY during turn completion — after the turn's
//	  session bookkeeping, before the terminal event (see
//	  hostileBridgeFixtureOnce): the daemon invalidates the
//	  per-activation nonce the moment it observes turn.completed, so
//	  the exchange must finish while the turn is still in flight. It
//	  is first-run-only per instance (marker file in the session dir),
//	  so a wake re-running a turn does not re-run the scripted calls.
//
//	PAGNET_FAKE_BRIDGE_CONTROL=1
//	  The INTERACTIVE hostile mode: like hostile mode, this endpoint
//	  process dials the bridge socket itself — but it then serves an
//	  interactive session over a control unix socket, so the black-box
//	  e2e harness can drive daemon-bridge exchanges from the test side.
//	  Newline-JSON commands ({"id","op":"auth"|"call"|"close",...}) are
//	  answered with the daemon's raw response frame verbatim.
//
//	  The control socket is bc-<instanceId without dashes>.sock (0600)
//	  in the PAGNET_FAKE_BRIDGE_RESULT_FILE's directory — the dir the
//	  sandbox already grants RW for the observation file, and the only
//	  granted location that stays under the AF_UNIX 108-byte sun_path
//	  limit in the Go test environment (a session-dir path is 120+
//	  bytes under t.TempDir and cannot be bound at all). See
//	  bridgeControlFixture.
//
// The result file (PAGNET_FAKE_BRIDGE_RESULT_FILE) holds a JSON array of
// the raw response lines observed (the MCP response objects in spawn mode;
// the daemon bridge protocol responses in hostile mode), so a test polls
// the file and asserts on the protocol facts. Control mode instead holds
// a JSON array of the (command, response) pairs it served.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	// Optional: capture the tool list as well, so the test can assert what
	// a fresh MCP client actually sees after initialize (the honesty
	// contract: no tools/list_changed claim, original tools intact).
	if os.Getenv("PAGNET_FAKE_BRIDGE_LIST_TOOLS") == "1" {
		writeLine(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
		observed = append(observed, readLineUntil(3))
	}
	// Always record the child's stderr last: the bridge's explicit error
	// logs (for example a refused sideport dial) are a behavioral contract
	// and must be assertable, not silently swallowed.
	observed = append(observed, mustJSONLine(map[string]any{"fixture": "done", "stderr": stderr.String()}))
	writeBridgeResultFile(observed)
}

// hostileCall is one entry of PAGNET_FAKE_HOSTILE_CALLS — the scripted
// call list (see the file header). Args is raw JSON (an object); nil
// sends {} (the daemon normalizes nil args the same way).
type hostileCall struct {
	ID   string          `json:"id"`
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
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
	// Scripted call list (PAGNET_FAKE_HOSTILE_CALLS / PAGNET_FAKE_
	// HOSTILE_CALLS_FILE): replaces the single tool below; the BADREQ
	// probes are a single-tool diagnostic and are not combined with the
	// list. Invalid JSON / unreadable file is a fixture error, recorded
	// like bad ARGS.
	var calls []hostileCall
	inlineCalls := os.Getenv("PAGNET_FAKE_HOSTILE_CALLS")
	callsFile := os.Getenv("PAGNET_FAKE_HOSTILE_CALLS_FILE")
	if inlineCalls != "" && callsFile != "" {
		writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "PAGNET_FAKE_HOSTILE_CALLS and PAGNET_FAKE_HOSTILE_CALLS_FILE are both set (pick one)"})})
		return
	}
	if inlineCalls != "" {
		if err := json.Unmarshal([]byte(inlineCalls), &calls); err != nil {
			writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "bad PAGNET_FAKE_HOSTILE_CALLS: " + err.Error()})})
			return
		}
	} else if callsFile != "" {
		// The file form: the JSON array lives in a file because the
		// comma-separated PAGNET_RUNTIME_ENV pair list cannot carry the
		// array's commas inline (see the file header).
		b, err := os.ReadFile(callsFile)
		if err != nil {
			writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "read PAGNET_FAKE_HOSTILE_CALLS_FILE: " + err.Error()})})
			return
		}
		if err := json.Unmarshal(b, &calls); err != nil {
			writeBridgeResultFile([][]byte{mustJSONLine(map[string]any{"fixture": "error", "error": "bad PAGNET_FAKE_HOSTILE_CALLS_FILE content: " + err.Error()})})
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
	if len(calls) > 0 {
		// Scripted call list: each exchange runs under its own
		// bridgeExchangeTimeout budget (a wedged daemon cannot hang the
		// session past one exchange's deadline).
		for _, c := range calls {
			callArgs := c.Args
			if len(callArgs) == 0 {
				callArgs = json.RawMessage("{}")
			}
			_ = conn.SetDeadline(time.Now().Add(bridgeExchangeTimeout))
			observed = append(observed, exchange(map[string]any{"id": c.ID, "tool": c.Tool, "args": callArgs}))
		}
		writeBridgeResultFile(observed)
		return
	}
	if badReq {
		observed = append(observed, exchange(map[string]any{"id": "", "tool": "network_whoami"}))
		observed = append(observed, exchange(map[string]any{"id": "7", "tool": ""}))
	}
	observed = append(observed, exchange(map[string]any{"id": "h1", "tool": tool, "args": toolArgs}))
	writeBridgeResultFile(observed)
}

// hostileBridgeFixtureOnce is the one-shot (process-per-turn) home for the
// hostile fixture: the turn-mode main() calls it SYNCHRONOUSLY as part of
// turn completion — after the turn's session bookkeeping and BEFORE the
// terminal event (the daemon invalidates the per-activation nonce and
// hibernates the instance the moment it observes turn.completed, so an
// exchange after the terminal event cannot authenticate), which is also
// what makes the result file complete by the time the harness observes the
// turn.
//
// First-run only per instance: a marker file in the session dir (which
// outlives the per-turn process) records that this instance already ran
// its scripted exchange, so a wake re-running a turn does not re-run it —
// the scripted calls have side effects (an event, a task) that must not be
// duplicated. The marker is written AFTER the exchange attempt, even when
// an exchange errored: re-running a failed list on the next turn would risk
// duplicating the calls that had already landed, and the result file keeps
// the error for diagnosis.
func hostileBridgeFixtureOnce(sessionDir string) {
	if os.Getenv("PAGNET_FAKE_HOSTILE_BRIDGE") != "1" {
		return
	}
	if sessionDir != "" {
		marker := filepath.Join(sessionDir, "pagnet-hostile-done")
		if _, err := os.Stat(marker); err == nil {
			return // this instance already ran its scripted exchange
		}
		defer os.WriteFile(marker, []byte("hostile bridge fixture ran\n"), 0o600)
	}
	hostileBridgeFixture()
}

// bridgeExchangeTimeout bounds one raw bridge request/response exchange
// (the same 10s budget the hostile mode runs its whole session under).
const bridgeExchangeTimeout = 10 * time.Second

// bridgeControl is the shared state of the interactive control fixture:
// the ONE raw daemon-bridge connection, serialised under a mutex so all
// concurrent control connections (and their auth/call/close commands)
// exchange on it in turn.
type bridgeControl struct {
	mu     sync.Mutex
	socket string // the daemon's bridge socket (from the config args)
	nonce  string // the config's per-activation nonce (never overridden)
	kind   string // the config's kind ("worker" | "representative")
	conn   net.Conn
	reader *bufio.Reader
	pairs  []map[string]any
}

// record appends one (command, response) pair to the observation history
// and atomically rewrites the result file with the full history (same
// convention as the other modes: a JSON array a test polls; a temp file
// plus rename so a concurrent reader never sees a torn file).
func (c *bridgeControl) record(cmd, resp any) {
	c.mu.Lock()
	c.pairs = append(c.pairs, map[string]any{"cmd": cmd, "resp": resp})
	hist := make([]map[string]any, len(c.pairs))
	copy(hist, c.pairs)
	c.mu.Unlock()
	writeBridgeResultPairs(hist)
}

// writeBridgeResultPairs writes the (command, response) pair history as a
// JSON array to the result file (atomic: temp file in the same dir +
// rename, 0600).
func writeBridgeResultPairs(pairs []map[string]any) {
	path := os.Getenv("PAGNET_FAKE_BRIDGE_RESULT_FILE")
	if path == "" {
		return
	}
	b, err := json.Marshal(pairs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: encode result pairs:", err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bridge-result-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: result file:", err)
		return
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: write result file:", err)
		tmp.Close()
		os.Remove(tmp.Name())
		return
	}
	if err := tmp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: close result file:", err)
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		fmt.Fprintln(os.Stderr, "bridge fixture: rename result file:", err)
		os.Remove(tmp.Name())
		return
	}
	_ = os.Chmod(path, 0o600)
}

// freshBridgeConn dials the bridge socket and performs the raw auth
// exchange with the given identity, using the config's nonce and kind
// (exactly the hostile mode's exchange, parameterised by identity). On
// any failure it closes the connection and returns the error — no
// partial state. The caller holds c.mu.
func (c *bridgeControl) freshBridgeConn(instanceID, networkID string) (net.Conn, *bufio.Reader, []byte, error) {
	conn, err := net.Dial("unix", c.socket)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(bridgeExchangeTimeout))
	r := bufio.NewReader(conn)
	b, _ := json.Marshal(map[string]any{
		"type": "auth", "instanceId": instanceID, "networkId": networkID,
		"nonce": c.nonce, "kind": c.kind,
	})
	if _, err := conn.Write(append(b, '\n')); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("auth write: %w", err)
	}
	line, err := r.ReadString('\n')
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("auth read: %w", err)
	}
	return conn, r, []byte(strings.TrimRight(line, "\r\n")), nil
}

// doAuth closes the current bridge connection, dials a FRESH one, and
// authenticates with the GIVEN identity + the config's nonce/kind. It
// returns the response carrying the daemon's raw frame; an exchange
// failure returns the fixture error instead. The caller holds c.mu.
func (c *bridgeControl) doAuth(instanceID, networkID string) map[string]any {
	if c.conn != nil {
		c.conn.Close()
		c.conn, c.reader = nil, nil
	}
	conn, r, frame, err := c.freshBridgeConn(instanceID, networkID)
	if err != nil {
		return map[string]any{"error": "auth: " + err.Error()}
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(frame, &probe); err != nil || probe.Type != "auth_ok" {
		// The daemon refused the identity: it closed the connection with
		// an error frame — relay it, keep NO active connection.
		conn.Close()
	} else {
		c.conn, c.reader = conn, r
	}
	return map[string]any{"response": json.RawMessage(frame)}
}

// doCall sends one tool request on the current bridge connection and
// returns the daemon's raw response frame. A timeout or write/read error
// severs the connection fail-closed (the stale state must not be reused).
// The caller holds c.mu.
func (c *bridgeControl) doCall(id string, tool string, args json.RawMessage) map[string]any {
	if c.conn == nil {
		return map[string]any{"error": "no active bridge connection"}
	}
	req := map[string]any{"id": "r-" + id, "tool": tool, "args": args}
	b, _ := json.Marshal(req)
	_ = c.conn.SetDeadline(time.Now().Add(bridgeExchangeTimeout))
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		c.severLocked()
		return map[string]any{"error": "call write: " + err.Error()}
	}
	line, err := c.reader.ReadString('\n')
	_ = c.conn.SetDeadline(time.Time{})
	if err != nil {
		c.severLocked()
		return map[string]any{"error": "call read: " + err.Error()}
	}
	return map[string]any{"response": json.RawMessage([]byte(strings.TrimRight(line, "\r\n")))}
}

// doClose closes the current bridge connection. The caller holds c.mu.
func (c *bridgeControl) doClose() map[string]any {
	c.severLocked()
	return map[string]any{"response": map[string]any{"ok": true}}
}

// severLocked drops the active bridge connection. The caller holds c.mu.
func (c *bridgeControl) severLocked() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn, c.reader = nil, nil
}

// dispatch runs one control command. Every code path returns a response
// (never hangs the harness): fixture-internal failures are
// {"id":"...","error":"..."}; protocol outcomes carry the daemon's raw
// frame under "response".
func (c *bridgeControl) dispatch(id, op, instanceID, networkID, tool string, args json.RawMessage) map[string]any {
	switch op {
	case "auth":
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.doAuth(instanceID, networkID)
	case "call":
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.doCall(id, tool, args)
	case "close":
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.doClose()
	default:
		return map[string]any{"error": "unknown op: " + op}
	}
}

// serveConn handles ONE control connection: newline-JSON commands in,
// newline-JSON replies out, until the peer closes or the endpoint stops.
func (c *bridgeControl) serveConn(conn net.Conn, stopping <-chan struct{}) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	reply := func(id string, v map[string]any) {
		out := make(map[string]any, len(v)+1)
		for k, val := range v {
			out[k] = val
		}
		if id != "" {
			out["id"] = id
		}
		b, _ := json.Marshal(out)
		_ = conn.SetWriteDeadline(time.Now().Add(bridgeExchangeTimeout))
		_, _ = conn.Write(append(b, '\n'))
	}
	for {
		select {
		case <-stopping:
			return
		default:
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			reply("", map[string]any{"error": "bad control command: " + err.Error()})
			continue
		}
		id, _ := raw["id"].(string)
		op, _ := raw["op"].(string)
		instanceID, _ := raw["instanceId"].(string)
		networkID, _ := raw["networkId"].(string)
		tool, _ := raw["tool"].(string)
		var args json.RawMessage
		if v, ok := raw["args"]; ok {
			if b, err := json.Marshal(v); err == nil {
				args = json.RawMessage(b)
			}
		}
		resp := c.dispatch(id, op, instanceID, networkID, tool, args)
		reply(id, resp)
		c.record(raw, resp)
	}
}

// controlSocketPath is the control socket's location: bc-<instanceId
// without dashes>.sock in the PAGNET_FAKE_BRIDGE_RESULT_FILE's directory
// (kept under the AF_UNIX 108-byte sun_path limit in the Go test
// environment — see the file header). The e2e harness derives the same
// path from the same two facts (the result-file dir it set, the
// instance id it launched); keep the two derivations in sync.
func controlSocketPath(instanceID, resultFile string) string {
	return filepath.Join(filepath.Dir(resultFile),
		"bc-"+strings.ReplaceAll(instanceID, "-", "")+".sock")
}

// bridgeControlFixture is the interactive hostile-bridge mode: at
// activation it dials the bridge socket with the config's identity
// (exactly like hostile mode), binds the control unix socket in the
// result file's directory (the sandbox-granted observation dir — the
// only granted location short enough for the AF_UNIX path limit in the
// test environment), and serves control connections until the endpoint
// stops. PAGNET_FAKE_BRIDGE_RESULT_FILE is REQUIRED (control mode is a
// test fixture; the result file is its observation point and its socket
// home).
func bridgeControlFixture(stopping <-chan struct{}) {
	serverName, _, args, env, err := firstBridgeServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "bridge control fixture:", err)
		return
	}
	resultFile := os.Getenv("PAGNET_FAKE_BRIDGE_RESULT_FILE")
	if resultFile == "" {
		fmt.Fprintln(os.Stderr, "bridge control fixture: PAGNET_FAKE_BRIDGE_RESULT_FILE is required (the control socket lives in the result file's dir)")
		return
	}
	instanceID, networkID, nonce, kind, socket := bridgeIdentity(serverName, args, env)
	if socket == "" {
		writeBridgeResultPairs([]map[string]any{{
			"cmd":  map[string]any{"op": "activate"},
			"resp": map[string]any{"fixture": "error", "error": "no socket in the MCP config args"},
		}})
		return
	}
	c := &bridgeControl{socket: socket, nonce: nonce, kind: kind}

	// Activation: dial + authenticate with the config's own identity, so
	// the result file records the endpoint's credentials working and a
	// "call" op is usable without a prior "auth" op. A failure is recorded
	// (no active connection) but does not stop the fixture — the harness
	// can still drive an "auth" op.
	activate := map[string]any{"op": "auth", "instanceId": instanceID, "networkId": networkID}
	resp := c.dispatch("", "auth", instanceID, networkID, "", nil)
	c.record(activate, resp)

	// Bind the control socket (0600; a stale file from a previous endpoint
	// is removed first). The result dir is sandbox-granted RW; a refusal
	// here (Landlock or the AF_UNIX path limit) is reported and STOPS the
	// fixture — no fallback location.
	sockPath := controlSocketPath(instanceID, resultFile)
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		c.record(map[string]any{"op": "bind"},
			map[string]any{"fixture": "error", "error": "bind control socket: " + err.Error()})
		_ = os.Remove(sockPath)
		return
	}
	_ = os.Chmod(sockPath, 0o600)
	defer func() {
		ln.Close()
		_ = os.Remove(sockPath)
		c.mu.Lock()
		c.severLocked()
		c.mu.Unlock()
	}()
	go func() { <-stopping; ln.Close() }() // unblock Accept on shutdown

	for {
		select {
		case <-stopping:
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stopping:
				return
			default:
				continue // transient: keep serving
			}
		}
		go c.serveConn(conn, stopping)
	}
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
