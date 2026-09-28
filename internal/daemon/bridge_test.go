package daemon

// Bridge-socket tests.
//
// Security wave S1 made bridge auth NOT identifier-only: the first message
// now carries the per-activation nonce the daemon minted for the instance's
// current launch, the bridge surface kind, and (on Linux) the connection is
// bound to the instance's process tree via SO_PEERCRED. This file covers the
// PORTABLE layer — every check that fires BEFORE the platform-specific
// process-tree binding — by dialing the socket from the test process and
// asserting the specific rejection. Each of these rejections happens before
// the (Linux) tree check, so the tests exercise the nonce/kind/network/
// status/live-process paths on EVERY platform.
//
// The in-tree positives (a live endpoint authenticating + the per-identity
// tool surface), the connection caps that need a live root, and the Linux
// process-tree rejections live in bridge_e2e_test.go / bridge_linux_test.go.

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

// --- harness -----------------------------------------------------------

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

// upsertBridgeInstance records a local instance the bridge auths against.
// kind "" means worker (the row's default).
func upsertBridgeInstance(t *testing.T, d *Daemon, id, name, network, status, kind string) {
	t.Helper()
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: id, Runtime: "fake", Status: status,
		Access: domain.AccessReadWrite, AgentName: name, NetworkID: network,
		Kind: kind,
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

// authFull sends the full S1 auth message (nonce + kind) and returns the
// daemon's response. It is the raw primitive the harness negatives use.
func (c *bridgeClient) authFull(t *testing.T, instanceID, networkID, nonce, kind string) map[string]any {
	t.Helper()
	c.write(t, map[string]any{
		"type": "auth", "instanceId": instanceID, "networkId": networkID,
		"nonce": nonce, "kind": kind,
	})
	return c.read(t)
}

// authMinted authenticates using the nonce the DAEMON mints for the
// instance through the real production mint path (bridgeNonceForActivation)
// and the instance's own kind — no test-only backdoor. It is the "legitimate
// credential" primitive: where it is still rejected, the rejection is a
// property of the instance (status / no live process), not of the credential.
func (c *bridgeClient) authMinted(t *testing.T, d *Daemon, instanceID, networkID string) map[string]any {
	t.Helper()
	row, ok, err := d.state.GetInstance(instanceID)
	if err != nil || !ok {
		t.Fatalf("instance %s not found: ok=%v err=%v", instanceID, ok, err)
	}
	nonce := d.bridgeNonceForActivation(row)
	if nonce == "" {
		t.Fatalf("no nonce minted for %s (crypto/rand failed?)", instanceID)
	}
	kind := row.Kind
	if kind == "" {
		kind = "worker"
	}
	return c.authFull(t, instanceID, networkID, nonce, kind)
}

// assertBridgeError asserts the response is an error whose message contains
// wantSubstr (a distinct rejection reason, S1).
func assertBridgeError(t *testing.T, resp map[string]any, wantSubstr string) {
	t.Helper()
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want an error", resp)
	}
	msg, _ := resp["error"].(string)
	if !strings.Contains(msg, wantSubstr) {
		t.Fatalf("error = %q, want it to contain %q", msg, wantSubstr)
	}
}

// --- identity rejections (portable: all fire before the tree check) ----

func TestBridgeAuthUnknownInstance(t *testing.T) {
	_, sock := startBridgeForTest(t)
	resp := bridgeDial(t, sock).authFull(t, "ghost", "net-1", "", "worker")
	assertBridgeError(t, resp, "unknown instance")
}

// A missing nonce is a rejected identity on every platform (the portable
// layer that killed identifier-only auth).
func TestBridgeAuthMissingNonce(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	resp := bridgeDial(t, sock).authFull(t, "inst-1", "net-1", "", "worker")
	assertBridgeError(t, resp, "bridge nonce invalid")
}

// A nonce that was never minted for this instance is a rejected identity.
func TestBridgeAuthGarbageNonce(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	resp := bridgeDial(t, sock).authFull(t, "inst-1", "net-1", "not-a-real-nonce", "worker")
	assertBridgeError(t, resp, "bridge nonce invalid")
}

// A nonce is bound to the instance it was minted for: inst-A's valid nonce
// is useless against inst-B (cross-instance credential theft is refused).
func TestBridgeAuthCrossInstanceNonce(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-A", "coder", "net-1", "idle", "worker")
	upsertBridgeInstance(t, d, "inst-B", "other", "net-2", "idle", "worker")

	rowA, _, _ := d.state.GetInstance("inst-A")
	nonceA := d.bridgeNonceForActivation(rowA)
	if nonceA == "" {
		t.Fatal("no nonce minted for inst-A")
	}

	resp := bridgeDial(t, sock).authFull(t, "inst-B", "net-2", nonceA, "worker")
	assertBridgeError(t, resp, "bridge nonce invalid")
}

// A stale nonce (minted for a superseded activation of the SAME instance) is
// a rejected identity: a new activation re-mints and replaces the prior
// credential, so the old one no longer matches what the daemon holds.
func TestBridgeAuthStaleNonce(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	row, _, _ := d.state.GetInstance("inst-1")
	stale := d.bridgeNonceForActivation(row) // activation 1
	fresh := d.bridgeNonceForActivation(row) // activation 2 supersedes it
	if stale == "" || fresh == "" || stale == fresh {
		t.Fatalf("expected two distinct minted nonces (stale=%q fresh=%q)", stale, fresh)
	}

	resp := bridgeDial(t, sock).authFull(t, "inst-1", "net-1", stale, "worker")
	assertBridgeError(t, resp, "bridge nonce invalid")
}

// Representative impersonation: a WORKER's own valid nonce, presented against
// a REPRESENTATIVE's instance id (with the rep kind), must not open the
// control surface. The nonce is instance-bound, so it is rejected at the
// nonce check — before kind could matter.
func TestBridgeAuthRepImpersonation(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-w", "coder", "net-1", "idle", "worker")
	upsertBridgeInstance(t, d, "inst-r", "rep", "", "idle", "representative")

	rowW, _, _ := d.state.GetInstance("inst-w")
	nonceW := d.bridgeNonceForActivation(rowW)
	if nonceW == "" {
		t.Fatal("no nonce minted for the worker")
	}

	resp := bridgeDial(t, sock).authFull(t, "inst-r", "", nonceW, "representative")
	assertBridgeError(t, resp, "bridge nonce invalid")
}

// Kind binding: a valid nonce for a WORKER instance, but presented with the
// REPRESENTATIVE kind, is refused — the bridge surface must match the
// instance's kind.
func TestBridgeAuthKindMismatch(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	row, _, _ := d.state.GetInstance("inst-1")
	nonce := d.bridgeNonceForActivation(row)
	if nonce == "" {
		t.Fatal("no nonce minted")
	}

	resp := bridgeDial(t, sock).authFull(t, "inst-1", "net-1", nonce, "representative")
	assertBridgeError(t, resp, "bridge kind does not match")
}

// The network comparison is defense-in-depth only (S1): it is no longer a
// security boundary, but a mismatch is still surfaced with a distinct error.
func TestBridgeAuthNetworkMismatch(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	row, _, _ := d.state.GetInstance("inst-1")
	nonce := d.bridgeNonceForActivation(row)
	if nonce == "" {
		t.Fatal("no nonce minted")
	}

	resp := bridgeDial(t, sock).authFull(t, "inst-1", "other-net", nonce, "worker")
	assertBridgeError(t, resp, "network mismatch")
}

// A stopped instance has no live process, so no legitimate bridge exists:
// even a valid nonce is refused.
func TestBridgeAuthStoppedInstance(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "stopped", "worker")

	resp := bridgeDial(t, sock).authMinted(t, d, "inst-1", "net-1")
	assertBridgeError(t, resp, "instance is stopped")
}

// A hibernated instance is rejected too (the old stopped-only check left
// hibernated open to a surviving bridge).
func TestBridgeAuthHibernatedInstance(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "hibernated", "worker")

	resp := bridgeDial(t, sock).authMinted(t, d, "inst-1", "net-1")
	assertBridgeError(t, resp, "instance is hibernated")
}

// The portable floor: everything passes (valid nonce/kind/network/status)
// until the live-process check — a plain upserted instance has no supervisor
// process, so the bridge is refused on EVERY platform.
func TestBridgeAuthNoLiveProcess(t *testing.T) {
	d, sock := startBridgeForTest(t)
	upsertBridgeInstance(t, d, "inst-1", "coder", "net-1", "idle", "worker")

	resp := bridgeDial(t, sock).authMinted(t, d, "inst-1", "net-1")
	assertBridgeError(t, resp, "instance has no live process")
}

// --- relay / resource bounds (portable) -------------------------------

// With no host connection the relay must fail cleanly (not hang): the agent's
// tool call gets a real, correlated error. Exercised directly on relayToServer
// (the client-facing correlation is proven by the e2e bridge tests).
func TestBridgeRelayWithoutConnection(t *testing.T) {
	d := newTestDaemon(t)
	_, errMsg := d.relayToServer("inst-1", "", "network_whoami", nil)
	if errMsg == "" {
		t.Fatal("relay without a host connection must fail")
	}
	if !strings.Contains(errMsg, errConnInterrupted) {
		t.Fatalf("relay error = %q, want the connection-interrupted message", errMsg)
	}
}

// TestBridgeGlobalConnCap (external audit F-010): once the global connection
// cap is reached, new connections are refused regardless of instance. The
// cap is enforced before the auth message is read, so no instance/nonce is
// needed.
func TestBridgeGlobalConnCap(t *testing.T) {
	d, sock := startBridgeForTest(t)

	// Saturate the global counter (under the lock, to avoid a data race with
	// the handler goroutine's locked read).
	d.bridgeConnMu.Lock()
	d.bridgeConns = bridgeMaxConns
	d.bridgeConnMu.Unlock()
	t.Cleanup(func() {
		d.bridgeConnMu.Lock()
		d.bridgeConns = 0
		d.bridgeConnMu.Unlock()
	})

	// The handler enforces the global cap BEFORE reading the auth message
	// (it writes the error and closes the connection immediately). So the
	// test must NOT write the auth first: doing so races the handler's close
	// and can fail with a broken pipe under load. Just read the error the
	// handler already sent.
	c := bridgeDial(t, sock)
	resp := c.read(t)
	if resp["type"] != "error" {
		t.Fatalf("auth = %v, want error (global cap)", resp)
	}
	if !strings.Contains(resp["error"].(string), "bridge connection limit reached") {
		t.Fatalf("error = %v, want the global cap message", resp["error"])
	}
}

// TestBridgeBoundedPending (external audit F-010): the pending
// agent.request map is capped; once full, new relays are refused instead of
// growing the map without bound.
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

	_, errMsg := d.relayToServer("inst-1", "", "network_whoami", nil)
	if errMsg == "" || !strings.Contains(errMsg, "in-flight") {
		t.Fatalf("relayToServer = %q, want the bounded-pending error", errMsg)
	}
}

// TestBridgeReadDeadlineCutsSlowLoris (external audit F-010): a connection
// that connects but never sends its auth must be cut off by the read deadline
// instead of holding a goroutine + socket descriptor indefinitely. The
// deadline is shortened for the test.
func TestBridgeReadDeadlineCutsSlowLoris(t *testing.T) {
	_, sock := startBridgeForTest(t)

	prev := atomic.LoadInt64(&bridgeConnReadTimeoutNs)
	atomic.StoreInt64(&bridgeConnReadTimeoutNs, int64(200*time.Millisecond))
	t.Cleanup(func() { atomic.StoreInt64(&bridgeConnReadTimeoutNs, prev) })

	conn := bridgeDial(t, sock)
	// Send nothing. The daemon must close the connection after the read
	// deadline; a subsequent read returns EOF.
	start := time.Now()
	if line, err := readLine(conn.r); err == nil {
		t.Fatalf("slow-loris connection was not cut off (read %q, want EOF)", line)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("read deadline took too long: %v", elapsed)
	}
}

// TestStartBridgeSocket_RefusesLiveDoubleStart: two daemons sharing a state
// dir must not both own the bridge socket — the second refuses to start.
// Without the guard they would fight over the host identity: each new
// connection supersedes the other, in an endless reconnect loop that flaps
// the host online/offline every backoff cycle.
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
