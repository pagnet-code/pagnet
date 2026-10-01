package daemon

// End-to-end bridge tests (security wave S1).
//
// These exercise the bridge socket through a REAL fake-persistent endpoint —
// the supervisor's root process for the instance. The endpoint is scripted
// (via the driver's launch env) to run the S1 fixtures (see
// cmd/pagnet-fake-runtime/bridge_fixture.go): it dials the bridge socket
// IN-TREE (so, on Linux, SO_PEERCRED reports the endpoint's own pid — the
// tree check reaches the root at 0 hops) with the daemon-minted nonce from
// the rendered MCP config, performs the scripted tool call, and writes the
// observed daemon-bridge-protocol responses to a result file the test polls.
//
// Because the in-tree dial passes the Linux tree check, these positives and
// the per-identity tool-surface assertions are portable (both platforms); the
// Linux-specific rejections (an UNRELATED same-UID process) live in
// bridge_linux_test.go.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
)

// mustPersistentFake returns the fake-persistent session driver (debug mode).
func mustPersistentFake(t *testing.T, d *Daemon) *agentruntime.PersistentFake {
	t.Helper()
	pf, ok := d.sessions.DriverFor(domain.RuntimeFakePersistent).(*agentruntime.PersistentFake)
	if !ok {
		t.Fatal("the PersistentFake driver is not registered (debug mode)")
	}
	return pf
}

// newBridgeE2EDaemon stands up a debug daemon with the fake-persistent
// binary, an in-memory host connection, the read-loop that routes
// agent.response envelopes back to the waiting bridge relay, and the bridge
// socket. It returns the daemon and the test-side server conn.
func newBridgeE2EDaemon(t *testing.T) (*Daemon, *websocket.Conn) {
	t.Helper()
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	// The daemon-side read loop (a real control-plane connection provides
	// this; without it a relay's response is never routed back to the
	// waiting bridge client).
	go func() {
		for {
			_, raw, err := client.ReadMessage()
			if err != nil {
				return
			}
			var env transport.Envelope
			if json.Unmarshal(raw, &env) != nil {
				continue
			}
			if env.Type == transport.MsgAgentResponse {
				d.deliverAgentResponse(env)
			}
		}
	}()
	t.Cleanup(func() { d.stopBridgeSocket() })
	if err := d.startBridgeSocket(); err != nil {
		t.Fatalf("startBridgeSocket: %v", err)
	}
	return d, server
}

// startBridgeRelayResponder answers the daemon's agent.request relays on the
// in-memory host connection (standing in for the out-of-scope control
// plane): every tool is answered ok with its name echoed, so a test can
// assert the EXACT tool was relayed.
//
// It is the SOLE reader of this host connection for the test's lifetime: a
// test that must read the same conn itself (a driveDeliver→readUntilAck of a
// functional turn) must NOT run while this responder is attached — two
// readers on one websocket race, and the responder swallows every
// non-agent.request envelope (it answers the relay and discards the rest).
// Such a test swaps the daemon onto a fresh host conn (see
// TestSandboxE2E_EndpointCannotReadDaemonState) instead of sharing this one.
func startBridgeRelayResponder(t *testing.T, server *websocket.Conn) {
	t.Helper()
	go func() {
		for {
			_, raw, err := server.ReadMessage()
			if err != nil {
				return
			}
			var env transport.Envelope
			if json.Unmarshal(raw, &env) != nil {
				continue
			}
			if env.Type != transport.MsgAgentRequest {
				continue
			}
			var req transport.AgentRequestPayload
			if env.DecodePayload(&req) != nil {
				continue
			}
			result, _ := json.Marshal(map[string]any{"tool": req.Tool, "ok": true})
			resp, err := transport.NewEnvelope(transport.MsgAgentResponse, transport.AgentResponsePayload{
				RequestID: env.ID, OK: true, Result: result,
			})
			if err != nil {
				continue
			}
			b, _ := json.Marshal(resp)
			if server.WriteMessage(websocket.TextMessage, b) != nil {
				return
			}
		}
	}()
}

// launchFakeEndpoint drives a launch command for a fake-persistent instance
// of the given kind (no initial mission) and waits for the endpoint to be
// live. It returns the instance id. The caller must have the bridge socket +
// host connection set up (newBridgeE2EDaemon) and, for the fixture tests, the
// driver's launch env configured BEFORE this call.
func launchFakeEndpoint(t *testing.T, d *Daemon, kind string) string {
	t.Helper()
	instanceID := domain.NewID().String()
	env, err := transport.NewEnvelope(transport.MsgLaunchAgent, transport.LaunchAgentPayload{
		CommandID: "cmd-bridge-e2e", InstanceID: instanceID,
		Runtime: string(domain.RuntimeFakePersistent), Kind: kind,
	})
	if err != nil {
		t.Fatalf("build launch envelope: %v", err)
	}
	d.handleCommand(nil, env)
	waitForEndpointLive(t, d, instanceID)
	return instanceID
}

// readBridgeResult polls the fixture's result file until it holds a non-empty
// JSON array of observed responses, then returns them. If the fixture recorded
// its own error (first element "fixture":"error"), the test fails with it.
func readBridgeResult(t *testing.T, path string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil && len(b) > 0 {
			var lines []map[string]any
			if json.Unmarshal(b, &lines) == nil && len(lines) > 0 {
				if lines[0]["fixture"] == "error" {
					msg, _ := lines[0]["error"].(string)
					t.Fatalf("bridge fixture failed: %s", msg)
				}
				return lines
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("bridge result file %s never appeared", path)
	return nil
}

// assertAuthOK asserts the first observed response is auth_ok for the
// instance (the in-tree, nonce-valid, kind-matching authentication succeeded).
func assertAuthOK(t *testing.T, lines []map[string]any, instanceID string) {
	t.Helper()
	if len(lines) < 1 {
		t.Fatalf("no observed responses, want auth_ok first")
	}
	if lines[0]["type"] != "auth_ok" {
		t.Fatalf("auth = %v, want auth_ok", lines[0])
	}
	if id, _ := lines[0]["instanceId"].(string); id != instanceID {
		t.Fatalf("auth_ok instanceId = %q, want %q", id, instanceID)
	}
}

// hostileFixtureEnv builds the driver launch env for the in-tree hostile-
// bridge fixture: it dials the bridge socket as the endpoint (the supervisor
// root) with the daemon-minted nonce and performs the scripted tool call.
func hostileFixtureEnv(resultFile, tool string, idle string, badReq bool) []string {
	env := []string{
		"PAGNET_FAKE_HOSTILE_BRIDGE=1",
		"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + resultFile,
		"PAGNET_FAKE_HOSTILE_TOOL=" + tool,
	}
	if idle != "" {
		env = append(env, "PAGNET_FAKE_HOSTILE_IDLE="+idle)
	}
	if badReq {
		env = append(env, "PAGNET_FAKE_HOSTILE_BADREQ=1")
	}
	return env
}

// TestBridgeE2E_WorkerNetworkWorks: a live worker endpoint's in-tree bridge
// authenticates with the daemon-minted nonce (auth_ok) and its network_*
// tool call is relayed end-to-end (the result comes back from the host).
func TestBridgeE2E_WorkerNetworkWorks(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = hostileFixtureEnv(resultFile, "network_whoami", "", false)

	instanceID := launchFakeEndpoint(t, d, "worker")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	if lines[1]["id"] != "h1" || lines[1]["ok"] != true {
		t.Fatalf("network_whoami = %v, want a successful correlated relay", lines[1])
	}
	t.Logf("worker in-tree bridge: auth_ok + network_whoami relayed (instance %s)", instanceID)
}

// TestBridgeE2E_SpawnBridgeWorks: the production bridge path — the
// sandboxed endpoint EXECs the daemon-rendered bridge worker (the real
// pagnet binary, exactly like every real runtime's MCP client) as its
// child and speaks MCP stdio to it. The worker authenticates to the
// daemon bridge with the per-activation nonce, and — on Linux — the
// daemon's SO_PEERCRED process-tree check reaches the endpoint's root
// ONE HOP UP (worker → endpoint), binding the spawned bridge process to
// the instance (the hostile in-tree fixtures pass that check at 0 hops;
// this is the real descendant case).
//
// It is also the S2 proof that the sandbox spec grants the bridge
// worker's binary dir (recovered from the rendered PAGNET_MCP_CONFIG):
// without it the sandboxed runtime cannot exec its MCP server, and the
// fixture records the spawn failure in the result file.
func TestBridgeE2E_SpawnBridgeWorks(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	// The bridge command the daemon renders must be a real pagnet binary
	// (the spawned worker implements `mcp worker`), not the test binary.
	pagnetBin := buildPagnetBinary(t)
	d.selfExe = pagnetBin

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = []string{
		"PAGNET_FAKE_SPAWN_BRIDGE=1",
		"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + resultFile,
	}

	instanceID := launchFakeEndpoint(t, d, "worker")

	// Spawn mode records the MCP stdio responses (the fixture plays the
	// MCP client): the initialize handshake, then the tools/call response.
	// A daemon-side auth refusal or tree-check rejection surfaces as a
	// failed/missing relay in the tools/call result.
	lines := readBridgeResult(t, resultFile)
	if len(lines) < 2 {
		t.Fatalf("expected initialize + tools/call responses, got %v", lines)
	}
	for _, l := range lines {
		if e, _ := l["error"].(string); l["fixture"] == "error" {
			t.Fatalf("spawn fixture failed: %s", e)
		}
	}
	// JSON-RPC ids unmarshal as float64 (json → any): compare as numbers.
	if id, _ := lines[0]["id"].(float64); id != 1 || lines[0]["result"] == nil {
		t.Fatalf("MCP initialize = %v, want a successful handshake (the worker ran and responded)", lines[0])
	}
	if id, _ := lines[1]["id"].(float64); id != 2 {
		t.Fatalf("tools/call response id = %v, want 2: %v", lines[1]["id"], lines[1])
	}
	if text := mcpResultText(lines[1]); !strings.Contains(text, "network_whoami") || !strings.Contains(text, `"ok": true`) {
		t.Fatalf("tools/call result = %q, want the relayed network_whoami result", text)
	}
	t.Logf("spawned bridge (real pagnet worker, auth + tree check by the daemon): network_whoami relayed (instance %s)", instanceID)
}

// mcpResultText extracts the concatenated text content of an MCP
// tools/call result line ("" when the line carries none — e.g. a JSON-RPC
// error response).
func mcpResultText(line map[string]any) string {
	result, ok := line["result"].(map[string]any)
	if !ok {
		return ""
	}
	content, _ := result["content"].([]any)
	var b strings.Builder
	for _, c := range content {
		cm, _ := c.(map[string]any)
		if s, _ := cm["text"].(string); s != "" {
			b.WriteString(s)
		}
	}
	return b.String()
}

// TestBridgeE2E_RepControlWorks: a live representative endpoint's in-tree
// bridge authenticates (auth_ok) and its control_* tool call is relayed
// end-to-end — the control surface a representative is entitled to.
func TestBridgeE2E_RepControlWorks(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = hostileFixtureEnv(resultFile, "control_whoami", "", false)

	instanceID := launchFakeEndpoint(t, d, "representative")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	if lines[1]["id"] != "h1" || lines[1]["ok"] != true {
		t.Fatalf("control_whoami = %v, want a successful correlated relay", lines[1])
	}
	t.Logf("representative in-tree bridge: auth_ok + control_whoami relayed (instance %s)", instanceID)
}

// TestBridgeE2E_SurfaceWorkerRejectsControl: a worker's authenticated
// connection may relay network_* ONLY. A control_* call on a worker
// connection is refused by the daemon-side dispatch (the bridge binary
// registers only the worker surface; this is the socket-level enforcement).
func TestBridgeE2E_SurfaceWorkerRejectsControl(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = hostileFixtureEnv(resultFile, "control_whoami", "", false)

	instanceID := launchFakeEndpoint(t, d, "worker")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID) // auth succeeds (valid worker credential)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	resp := lines[1]
	if resp["ok"] == true {
		t.Fatalf("a worker calling control_whoami must be refused, got %v", resp)
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "not on this identity's surface") {
		t.Fatalf("control_whoami on a worker = %v, want the tool-surface refusal", resp)
	}
}

// TestBridgeE2E_SurfaceRepRejectsNetwork: a representative's authenticated
// connection may relay control_* ONLY. A network_* call on a representative
// connection is refused by the daemon-side dispatch.
func TestBridgeE2E_SurfaceRepRejectsNetwork(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = hostileFixtureEnv(resultFile, "network_whoami", "", false)

	instanceID := launchFakeEndpoint(t, d, "representative")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID) // auth succeeds (valid rep credential)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	resp := lines[1]
	if resp["ok"] == true {
		t.Fatalf("a representative calling network_whoami must be refused, got %v", resp)
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "not on this identity's surface") {
		t.Fatalf("network_whoami on a rep = %v, want the tool-surface refusal", resp)
	}
}

// TestBridgeE2E_PerInstanceConnCap (external audit F-010): a single instance
// must not hold more than bridgeMaxConnsPerInst bridge connections. The cap is
// enforced after the live-process check and BEFORE the platform tree check,
// so it is exercised with a live endpoint + a valid nonce + a saturated
// counter and a raw dial (portable). The (cap+1)th connection is refused with
// the per-instance error.
func TestBridgeE2E_PerInstanceConnCap(t *testing.T) {
	d, _ := newBridgeE2EDaemon(t)

	instanceID := launchFakeEndpoint(t, d, "worker")
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance not found: ok=%v err=%v", ok, err)
	}
	nonce := d.currentBridgeNonce(instanceID)
	if nonce == "" {
		t.Fatal("no nonce minted for the live endpoint")
	}

	// Saturate the per-instance counter (under the lock, as the global cap
	// test does for the global counter).
	d.bridgeConnMu.Lock()
	d.bridgeConnsInst[instanceID] = bridgeMaxConnsPerInst
	d.bridgeConnMu.Unlock()
	t.Cleanup(func() {
		d.bridgeConnMu.Lock()
		delete(d.bridgeConnsInst, instanceID)
		d.bridgeConnMu.Unlock()
	})

	c := bridgeDial(t, d.bridgePath)
	resp := c.authFull(t, instanceID, row.NetworkID, nonce, "worker")
	assertBridgeError(t, resp, "bridge connection limit reached for this instance")
}

// TestBridgeE2E_AuthenticatedConnSurvivesIdle: the read deadline bounds the
// AUTH phase only. An authenticated bridge connection must survive an idle
// gap longer than the (shortened) deadline — the managed agent keeps one
// connection for the endpoint's whole life and is legitimately quiet on it.
// With the absolute deadline left in force the next tool call hits a severed
// connection (EOF); the in-tree fixture goes quiet past the deadline and its
// tool call must still get a correlated reply.
func TestBridgeE2E_AuthenticatedConnSurvivesIdle(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	prev := atomic.LoadInt64(&bridgeConnReadTimeoutNs)
	atomic.StoreInt64(&bridgeConnReadTimeoutNs, int64(300*time.Millisecond))
	t.Cleanup(func() { atomic.StoreInt64(&bridgeConnReadTimeoutNs, prev) })

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	// Go quiet 900 ms after auth — longer than the 300 ms read deadline.
	pf.Env = hostileFixtureEnv(resultFile, "network_whoami", "900ms", false)

	instanceID := launchFakeEndpoint(t, d, "worker")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID)
	if len(lines) < 2 {
		t.Fatalf("expected auth + a tool response, got %v", lines)
	}
	if lines[1]["id"] != "h1" || lines[1]["ok"] == nil {
		t.Fatalf("tool call after idle = %v, want a correlated reply (not EOF)", lines[1])
	}
	t.Logf("authenticated bridge survived a 900 ms idle past the 300 ms deadline (instance %s)", instanceID)
}

// TestBridgeE2E_BadRequest: a request with an empty id or an empty tool is
// rejected (an id-less request cannot be correlated to a response; an empty
// tool is a no-op that would still consume a relay slot). The in-tree fixture
// sends both bad requests after auth and records the daemon's replies.
func TestBridgeE2E_BadRequest(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-result.json")
	pf.Env = hostileFixtureEnv(resultFile, "network_whoami", "", true)

	instanceID := launchFakeEndpoint(t, d, "worker")

	lines := readBridgeResult(t, resultFile)
	assertAuthOK(t, lines, instanceID)
	// [auth_ok, badRequest(empty id), badRequest(empty tool), final tool]
	if len(lines) < 4 {
		t.Fatalf("expected auth + 2 bad-request replies + final tool, got %v", lines)
	}
	// Empty id: rejected, response echoes the empty id.
	if lines[1]["ok"] == true || lines[1]["id"] != "" {
		t.Fatalf("empty-id request = %v, want ok=false + empty id", lines[1])
	}
	// Empty tool: rejected, response echoes the id.
	if lines[2]["ok"] == true || lines[2]["id"] != "7" {
		t.Fatalf("empty-tool request = %v, want ok=false + id 7", lines[2])
	}
	t.Logf("bad requests rejected with correlated errors (instance %s)", instanceID)
}
