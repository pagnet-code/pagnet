package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type bridgeClient struct {
	conn net.Conn
	r    *bufio.Reader
}

func startBridgeForTest(t *testing.T) (*Daemon, string) {
	t.Helper()
	d := newTestDaemon(t)
	if err := d.startBridgeSocket(); err != nil {
		t.Fatalf("startBridgeSocket: %v", err)
	}
	return d, filepath.Join(d.StateDir, bridgeSocketName)
}

func upsertBridgeInstance(t *testing.T, d *Daemon, id, name, network, status string) {
	t.Helper()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: id, Runtime: "fake", Status: status,
		Access: domain.AccessReadWrite, AgentName: name, NetworkID: network,
	}); err != nil {
		t.Fatal(err)
	}
}

func bridgeDial(t *testing.T, sock string) *bridgeClient {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &bridgeClient{conn: conn, r: bufio.NewReader(conn)}
}

func (c *bridgeClient) write(t *testing.T, v any) {
	t.Helper()
	raw, _ := json.Marshal(v)
	if _, err := c.conn.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func (c *bridgeClient) read(t *testing.T) map[string]any {
	t.Helper()
	line, err := readLine(c.r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	return out
}

func (c *bridgeClient) auth(t *testing.T, instanceID, networkID string) map[string]any {
	t.Helper()
	c.write(t, map[string]any{"type": "auth", "instanceId": instanceID, "networkId": networkID})
	return c.read(t)
}

func TestBridgeAuthOK(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	resp := bridgeDial(t, sock).auth(t, "inst-1", "net-1")
	if resp["type"] != "auth_ok" {
		t.Fatalf("auth = %v, want auth_ok", resp)
	}
}

func TestBridgeAuthUnknownInstance(t *testing.T) {
	_, sock := startBridgeForTest(t)
	resp := bridgeDial(t, sock).auth(t, "ghost", "net-1")
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want error", resp)
	}
}

func TestBridgeAuthNetworkMismatch(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	resp := bridgeDial(t, sock).auth(t, "inst-1", "other-net")
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want error (network mismatch)", resp)
	}
}

func TestBridgeAuthStoppedInstance(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "stopped")

	resp := bridgeDial(t, sock).auth(t, "inst-1", "net-1")
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want error (stopped)", resp)
	}
}

// With no host connection the relay must fail cleanly (not hang): the
// bridge surfaces an error so the agent's tool call gets a real error.
func TestBridgeRelayWithoutConnection(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	c := bridgeDial(t, sock)
	if resp := c.auth(t, "inst-1", "net-1"); resp["type"] != "auth_ok" {
		t.Fatalf("auth = %v, want auth_ok", resp)
	}
	c.write(t, map[string]any{"id": "1", "tool": "network_whoami", "args": map[string]any{}})
	resp := c.read(t)
	if resp["ok"] == true {
		t.Fatalf("relay without connection must fail, got %v", resp)
	}
	if resp["id"] != "1" {
		t.Fatalf("response id = %v, want 1", resp["id"])
	}
}

// Unknown tools are rejected by the server-side dispatcher; without a
// connection the local failure comes first. Either way the client gets a
// correlated error, never a hang.
func TestBridgeUnknownToolLocal(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	c := bridgeDial(t, sock)
	if resp := c.auth(t, "inst-1", "net-1"); resp["type"] != "auth_ok" {
		t.Fatalf("auth = %v, want auth_ok", resp)
	}
	c.write(t, map[string]any{"id": "2", "tool": "network_bogus"})
	resp := c.read(t)
	if resp["ok"] == true {
		t.Fatalf("bogus tool must fail, got %v", resp)
	}
}

// TestStartBridgeSocket_RefusesLiveDoubleStart: two daemons sharing a
// state dir must not both own the bridge socket — the second refuses to
// start. Without the guard they would fight over the host identity: each
// new connection supersedes the other, in an endless reconnect loop that
// flaps the host online/offline every backoff cycle.
func TestStartBridgeSocket_RefusesLiveDoubleStart(t *testing.T) {
	d, _ := startBridgeForTest(t)
	defer d.stopBridgeSocket()

	d2, err := New(Config{StateDir: d.StateDir}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d2.Close()
	if err := d2.startBridgeSocket(); err == nil {
		t.Fatal("second daemon must refuse to start while the first owns the bridge socket")
	}
}

// TestBridgePerInstanceConnCap (external audit F-010): a single instance
// must not hold more than bridgeMaxConnsPerInst bridge connections. The
// (cap+1)th connection for the same instance is refused with a
// per-instance error (the global slot is released by the deferred
// releaseBridgeConn).
func TestBridgePerInstanceConnCap(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	for i := 0; i < bridgeMaxConnsPerInst; i++ {
		c := bridgeDial(t, sock)
		if resp := c.auth(t, "inst-1", "net-1"); resp["type"] != "auth_ok" {
			t.Fatalf("conn %d: auth = %v, want auth_ok", i, resp)
		}
	}
	// The (cap+1)th connection for the same instance is refused.
	c := bridgeDial(t, sock)
	resp := c.auth(t, "inst-1", "net-1")
	if resp["type"] != "error" {
		t.Fatalf("conn %d: auth = %v, want error (per-instance cap)", bridgeMaxConnsPerInst, resp)
	}
	if !strings.Contains(resp["error"].(string), "this instance") {
		t.Fatalf("error = %v, want the per-instance cap message", resp["error"])
	}
}

// TestBridgeGlobalConnCap (external audit F-010): once the global
// connection cap is reached, new connections are refused regardless of
// instance.
func TestBridgeGlobalConnCap(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	// Saturate the global counter (under the lock, to avoid a data race
	// with the handler goroutine's locked read).
	d.bridgeConnMu.Lock()
	d.bridgeConns = bridgeMaxConns
	d.bridgeConnMu.Unlock()
	t.Cleanup(func() {
		d.bridgeConnMu.Lock()
		d.bridgeConns = 0
		d.bridgeConnMu.Unlock()
	})

	resp := bridgeDial(t, sock).auth(t, "inst-1", "net-1")
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want error (global cap)", resp)
	}
	if !strings.Contains(resp["error"].(string), "bridge connection limit reached") {
		t.Fatalf("error = %v, want the global cap message", resp["error"])
	}
}

// TestBridgeRequestRequiresIDAndTool (external audit F-010): a request
// with an empty id or an empty tool is rejected (an id-less request
// cannot be correlated to a response; an empty tool is a no-op that would
// still consume a relay slot).
func TestBridgeRequestRequiresIDAndTool(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle")

	c := bridgeDial(t, sock)
	if resp := c.auth(t, "inst-1", "net-1"); resp["type"] != "auth_ok" {
		t.Fatalf("auth = %v, want auth_ok", resp)
	}
	// Empty id: rejected, response echoes the empty id.
	c.write(t, map[string]any{"id": "", "tool": "network_whoami"})
	resp := c.read(t)
	if resp["ok"] == true || resp["id"] != "" {
		t.Fatalf("empty-id request = %v, want ok=false + empty id", resp)
	}
	// Empty tool: rejected, response echoes the id.
	c.write(t, map[string]any{"id": "7", "tool": ""})
	resp = c.read(t)
	if resp["ok"] == true || resp["id"] != "7" {
		t.Fatalf("empty-tool request = %v, want ok=false + id 7", resp)
	}
}

// TestBridgeBoundedPending (external audit F-010): the pending
// agent.request map is capped; once full, new relays are refused instead
// of growing the map without bound.
func TestBridgeBoundedPending(t *testing.T) {
	d := newTestDaemon(t)
	client, _ := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()

	// Saturate the pending map (under the lock that guards it).
	d.pendingMu.Lock()
	for i := 0; i < bridgeMaxPending; i++ {
		d.pending[fmt.Sprintf("fill-%d", i)] = make(chan transport.AgentResponsePayload, 1)
	}
	d.pendingMu.Unlock()

	_, errMsg := d.relayToServer("inst-1", "network_whoami", nil)
	if errMsg == "" || !strings.Contains(errMsg, "in-flight") {
		t.Fatalf("relayToServer = %q, want the bounded-pending error", errMsg)
	}
}

// TestBridgeReadDeadlineCutsSlowLoris (external audit F-010): a
// connection that connects but never sends its auth must be cut off by the
// read deadline instead of holding a goroutine + socket descriptor
// indefinitely. The deadline is shortened for the test.
func TestBridgeReadDeadlineCutsSlowLoris(t *testing.T) {
	_, sock := startBridgeForTest(t)

	prev := atomic.LoadInt64(&bridgeConnReadTimeoutNs)
	atomic.StoreInt64(&bridgeConnReadTimeoutNs, int64(200*time.Millisecond))
	t.Cleanup(func() { atomic.StoreInt64(&bridgeConnReadTimeoutNs, prev) })

	conn := bridgeDial(t, sock)
	// Send nothing. The daemon must close the connection after the
	// read deadline; a subsequent read returns EOF.
	start := time.Now()
	if line, err := readLine(conn.r); err == nil {
		t.Fatalf("slow-loris connection was not cut off (read %q, want EOF)", line)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("read deadline took too long: %v", elapsed)
	}
}
