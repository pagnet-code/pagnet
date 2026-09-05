package daemon

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"pagnet/internal/domain"
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
