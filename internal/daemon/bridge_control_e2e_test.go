package daemon

// End-to-end test for the INTERACTIVE bridge fixture
// (PAGNET_FAKE_BRIDGE_CONTROL=1, see
// cmd/pagnet-fake-runtime/bridge_fixture.go): a real fake-persistent
// endpoint dials the daemon's bridge socket in-tree at activation and
// serves control connections on bc-<instanceId>.sock in the result
// file's dir (the controlSocketPath derivation, mirrored below).
// The test drives the control socket exactly the way the black-box e2e
// harness does: an auth op (auth_ok with the instance's own identity),
// call ops (raw daemon frames relayed verbatim), an auth op with the
// wrong networkId (the daemon's identity rejection, relayed as an error
// frame and leaving no active connection), a call op on the severed
// connection (the fixture's own "no active bridge connection" error),
// recovery by re-auth, and a close op. The (command, response) pairs the
// fixture recorded in the result file are asserted too.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// controlFixtureClient is a raw client of the fixture's control socket:
// one command per line ({"id","op",...}), one reply per command.
type controlFixtureClient struct {
	conn net.Conn
	r    *bufio.Reader
	seq  int
}

// op sends one control command and returns the raw reply object.
func (c *controlFixtureClient) op(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	c.seq++
	v["id"] = fmt.Sprintf("c%d", c.seq)
	b, _ := json.Marshal(v)
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		t.Fatalf("control write: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	line, err := c.r.ReadString('\n')
	if err != nil {
		t.Fatalf("control read: %v", err)
	}
	var reply map[string]any
	if err := json.Unmarshal([]byte(line), &reply); err != nil {
		t.Fatalf("control reply %q is not a JSON object: %v", line, err)
	}
	return reply
}

// dialControlSocket polls the instance's control socket until it is
// dialable (the endpoint binds it during activation) and returns a client.
func dialControlSocket(t *testing.T, sock string) *controlFixtureClient {
	t.Helper()
	var conn net.Conn
	deadline := time.Now().Add(60 * time.Second)
	for {
		var err error
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial control socket %s: %v", sock, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Cleanup(func() { conn.Close() })
	return &controlFixtureClient{conn: conn, r: bufio.NewReader(conn)}
}

// readControlPairs polls the control fixture's result file until it holds
// at least minPairs (command, response) pairs and returns them. A pair
// whose resp carries the fixture's own error fails the test with it.
func readControlPairs(t *testing.T, path string, minPairs int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			var pairs []map[string]any
			if json.Unmarshal(b, &pairs) == nil && len(pairs) >= minPairs {
				for _, p := range pairs {
					if resp, ok := p["resp"].(map[string]any); ok && resp["fixture"] == "error" {
						msg, _ := resp["error"].(string)
						t.Fatalf("bridge control fixture failed: %s", msg)
					}
				}
				return pairs
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("bridge control result file %s never reached %d pairs", path, minPairs)
	return nil
}

func TestBridgeControlE2E_InteractiveFixture(t *testing.T) {
	d, server := newBridgeE2EDaemon(t)
	startBridgeRelayResponder(t, server)

	pf := mustPersistentFake(t, d)
	resultFile := filepath.Join(t.TempDir(), "bridge-control-result.json")
	pf.Env = []string{
		"PAGNET_FAKE_BRIDGE_CONTROL=1",
		"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + resultFile,
	}

	instanceID := launchFakeEndpoint(t, d, "worker")

	// The control socket lives in the result file's dir (the sandbox-
	// granted observation dir, and the only granted location short enough
	// for the AF_UNIX path limit under t.TempDir): bc-<instanceId without
	// dashes>.sock — the same derivation the fixture uses.
	sock := filepath.Join(filepath.Dir(resultFile),
		"bc-"+strings.ReplaceAll(instanceID, "-", "")+".sock")
	cc := dialControlSocket(t, sock)

	// (1) auth op with the instance's own identity: the fixture dials a
	// fresh bridge connection and relays the daemon's auth_ok verbatim.
	// The row's NetworkID is still empty (daemon-test launch), so the
	// empty networkId matches.
	reply := cc.op(t, map[string]any{"op": "auth", "instanceId": instanceID, "networkId": ""})
	resp, ok := reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("auth op reply = %v, want response", reply)
	}
	if resp["type"] != "auth_ok" {
		t.Fatalf("auth op = %v, want auth_ok", resp)
	}
	if id, _ := resp["instanceId"].(string); id != instanceID {
		t.Fatalf("auth_ok instanceId = %q, want %q", id, instanceID)
	}
	if reply["id"] != "c1" {
		t.Fatalf("auth op reply id = %v, want c1 (correlated)", reply["id"])
	}

	// (2) call op: the fixture sends the tool request on the shared
	// bridge connection and relays the daemon's correlated frame.
	reply = cc.op(t, map[string]any{"op": "call", "tool": "network_whoami", "args": map[string]any{}})
	resp, ok = reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("call op reply = %v, want response", reply)
	}
	if resp["ok"] != true {
		t.Fatalf("network_whoami call = %v, want ok=true (relayed end-to-end)", resp)
	}

	// Pin a network on the instance row (a control-plane fact the daemon
	// test launch leaves empty) so the network-mismatch check is live.
	row, found, err := d.state.GetInstance(instanceID)
	if err != nil || !found {
		t.Fatalf("instance row: found=%v err=%v", found, err)
	}
	row.NetworkID = "net-control-e2e"
	if err := d.state.UpsertInstance(*row); err != nil {
		t.Fatalf("pin network: %v", err)
	}

	// (3) auth op with the pinned networkId: fresh connection, auth_ok.
	reply = cc.op(t, map[string]any{"op": "auth", "instanceId": instanceID, "networkId": "net-control-e2e"})
	resp, ok = reply["response"].(map[string]any)
	if !ok || resp["type"] != "auth_ok" {
		t.Fatalf("auth op (pinned network) = %v, want auth_ok", reply)
	}

	// (4) auth op with the WRONG networkId: the daemon refuses the
	// identity (error frame, connection severed) and the fixture relays
	// the frame verbatim, keeping NO active connection.
	reply = cc.op(t, map[string]any{"op": "auth", "instanceId": instanceID, "networkId": "other-network"})
	resp, ok = reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("wrong-network auth op reply = %v, want response", reply)
	}
	if resp["type"] != "error" {
		t.Fatalf("wrong-network auth = %v, want an error frame", resp)
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "network mismatch") {
		t.Fatalf("wrong-network auth error = %q, want the network mismatch rejection", msg)
	}

	// (5) call op with no active bridge connection: the fixture's own
	// error (never a hang).
	reply = cc.op(t, map[string]any{"op": "call", "tool": "network_whoami", "args": map[string]any{}})
	if _, hasResp := reply["response"]; hasResp {
		t.Fatalf("call after rejected auth = %v, want the fixture error, not a response", reply)
	}
	if msg, _ := reply["error"].(string); msg != "no active bridge connection" {
		t.Fatalf("call after rejected auth error = %q, want no active bridge connection", msg)
	}

	// (6) recovery: a correct auth op restores a working connection.
	reply = cc.op(t, map[string]any{"op": "auth", "instanceId": instanceID, "networkId": "net-control-e2e"})
	resp, ok = reply["response"].(map[string]any)
	if !ok || resp["type"] != "auth_ok" {
		t.Fatalf("recovery auth op = %v, want auth_ok", reply)
	}

	// (7) close op: the fixture drops the connection.
	reply = cc.op(t, map[string]any{"op": "close"})
	resp, ok = reply["response"].(map[string]any)
	if !ok || resp["ok"] != true {
		t.Fatalf("close op = %v, want {ok:true}", reply)
	}

	// (8) observation point: the result file holds every (command,
	// response) pair the fixture served (the activation auth + the seven
	// control ops).
	pairs := readControlPairs(t, resultFile, 8)
	var sawAuthOK, sawCallOK, sawMismatch, sawNoConn, sawClose bool
	for _, p := range pairs {
		cmd, _ := p["cmd"].(map[string]any)
		r, _ := p["resp"].(map[string]any)
		op, _ := cmd["op"].(string)
		// A fixture-internal failure is recorded as {"error": "..."} (no
		// "response"); the expected one is the severed-connection call.
		if e, ok := r["error"].(string); ok {
			if op == "call" && e == "no active bridge connection" {
				sawNoConn = true
			}
			continue
		}
		rr, _ := r["response"].(map[string]any) // the daemon's raw frame
		switch {
		case op == "auth" && rr["type"] == "auth_ok":
			if id, _ := rr["instanceId"].(string); id == instanceID {
				sawAuthOK = true
			}
		case op == "call" && cmd["tool"] == "network_whoami" && rr["ok"] == true:
			sawCallOK = true
		case op == "auth" && cmd["networkId"] == "other-network" && rr["type"] == "error":
			sawMismatch = true
		case op == "close" && rr["ok"] == true:
			sawClose = true
		}
	}
	for name, saw := range map[string]bool{
		"activation/harness auth_ok": sawAuthOK,
		"network_whoami call":        sawCallOK,
		"wrong-networkId rejection":  sawMismatch,
		"severed-connection call":    sawNoConn,
		"close":                      sawClose,
	} {
		if !saw {
			t.Fatalf("result file lacks the %s pair: %v", name, pairs)
		}
	}
	t.Logf("interactive bridge fixture: control-socket auth/call/reject/recover/close all observed (instance %s)", instanceID)
}
