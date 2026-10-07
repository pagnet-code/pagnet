//go:build linux || darwin

package sessionworker

// Phase A step 6d — the hosted Fabric sideport advertised on the native
// worker's own bridge.
//
// These tests run the REAL SessionOwner in-process (journal + driver +
// supervisor + both sockets) instead of spawning the worker binary: the
// controller client is the genuine DialOwnerController over the real
// controller.sock (mutual HMAC handshake included), and the "MCP client" is
// the fake-persistent endpoint itself — under PAGNET_FAKE_BRIDGE_CONTROL=1
// it dials the real native.sock with the worker-minted per-activation nonce
// and relays the raw bridge frames over a control unix socket. The
// native-bridge authentication (instance scope, per-activation nonce, kernel
// process ancestry) is the identical production handshake; only the worker
// process boundary is in-process, which is exactly what makes the owner
// state observable without a second binary.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
)

// sideportFakeBinary builds (when stale/missing) the pagnet-fake-runtime
// fixture binary into the SHARED scratch bin dir — the same dir and output
// name the daemon package's p0FakeBinary uses, so both packages reuse one
// build (NEVER into the repo's bin/).
func sideportFakeBinary(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PAGNET_P0_BIN_DIR")
	if dir == "" {
		abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".qwen", "tmp", "p0-bin"))
		if err != nil {
			t.Fatalf("resolve scratch bin dir: %v", err)
		}
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scratch bin dir: %v", err)
	}
	bin := filepath.Join(dir, "pagnet-fake-runtime")
	needBuild := true
	if fi, err := os.Stat(bin); err == nil {
		srcFiles, gerr := filepath.Glob(filepath.Join("..", "..", "cmd", "pagnet-fake-runtime", "*.go"))
		if gerr == nil {
			var newest time.Time
			for _, f := range srcFiles {
				if s, serr := os.Stat(f); serr == nil && s.ModTime().After(newest) {
					newest = s.ModTime()
				}
			}
			if !newest.IsZero() && fi.ModTime().After(newest) {
				needBuild = false
			}
		}
	}
	if needBuild {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "build", "-o", bin, filepath.Join("..", "..", "cmd", "pagnet-fake-runtime")).CombinedOutput()
		if err != nil {
			t.Fatalf("build fake runtime fixture: %v\n%s", err, out)
		}
	}
	return bin
}

// sideportControlClient is a raw client of the fake endpoint's control
// socket: one newline-JSON command per exchange, one reply per command
// (the bridgeControl protocol in cmd/pagnet-fake-runtime/bridge_fixture.go).
type sideportControlClient struct {
	conn net.Conn
	r    *bufio.Reader
	seq  int
}

func (c *sideportControlClient) op(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	c.seq++
	v["id"] = fmt.Sprintf("s%d", c.seq)
	b, _ := json.Marshal(v)
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		t.Fatalf("control write: %v", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
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

// sideportOwnerFixture is the in-process real owner: a fresh journal, an
// activated fake-persistent native session, a genuine owner controller
// (DialOwnerController) and the endpoint's bridge-control client.
type sideportOwnerFixture struct {
	t          *testing.T
	scope      Scope
	owner      *SessionOwner
	controller *Controller
	control    *sideportControlClient
	resultFile string
}

const sideportNetworkID = "network-1"

func newSideportOwnerFixture(t *testing.T) *sideportOwnerFixture {
	t.Helper()
	ctx := t.Context()
	scope := testScope()
	f := &sideportOwnerFixture{t: t, scope: scope}

	// t.TempDir() leaves its leaf at 0777&~umask; privateDirectory demands a
	// 0700 leaf, so open the journal in the package's proven subdir (the
	// MkdirAll inside privateDirectory creates it 0700).
	j, err := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	// Registered before the owner cleanup below: with LIFO cleanups the
	// journal closes AFTER the owner has quiesced on it.
	t.Cleanup(func() { _ = j.Close() })

	fakeBin := sideportFakeBinary(t)
	workspace := t.TempDir()
	resultDir := t.TempDir()
	f.resultFile = filepath.Join(resultDir, "bridge-result.json")
	spec := NativeSpec{
		Runtime:         domain.RuntimeFakePersistent,
		Binary:          fakeBin,
		MCPExecutable:   fakeBin,
		Workspace:       workspace,
		NetworkID:       sideportNetworkID,
		Kind:            "worker",
		TenantID:        scope.TenantID,
		NetworkTenantID: scope.TenantID,
		Env: []string{
			"PAGNET_FAKE_BRIDGE_CONTROL=1",
			"PAGNET_FAKE_BRIDGE_RESULT_FILE=" + f.resultFile,
		},
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	owner, err := NewSessionOwner(ctx, j, spec, key)
	if err != nil {
		t.Fatalf("new session owner: %v", err)
	}
	f.owner = owner
	// Registered after the journal cleanup (runs before it) and before the
	// controller cleanup (runs after it): the owner quiesces on the journal
	// while its own control connections are still open.
	t.Cleanup(func() { f.owner.Close() })

	// The production worker binds the native bridge BEFORE advertising the
	// control socket (main.go); mirror that ordering.
	ready := make(chan struct{})
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- owner.serveBridge(ctx, ready) }()
	select {
	case err := <-bridgeDone:
		t.Fatalf("native bridge listener failed: %v", err)
	case <-ready:
	}
	go ServeOwner(ctx, owner, key, "sideport-test")

	deadline := time.Now().Add(15 * time.Second)
	for {
		ctrl, err := DialOwnerController(ctx, j.dir, scope, key, "sideport-controller")
		if err == nil {
			f.controller = ctrl
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial owner controller: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { _ = f.controller.Close() })

	admission := Admission{NativeAdmissionID: uuid.NewString(), Scope: scope, TenantID: scope.TenantID, NetworkID: sideportNetworkID, Kind: "worker", RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
	if r := f.call(t, Request{Type: "admission", Admission: &admission}); r.Error != "" {
		t.Fatalf("admission: %s", r.Error)
	}
	opRaw, _ := json.Marshal(Operation{SourceCommandID: "activate-one"})
	if r := f.call(t, Request{Type: "intent", Sequence: 1, CommandID: "activate-one", Kind: "activate", Payload: opRaw}); r.Error != "" {
		t.Fatalf("activate intent: %s", r.Error)
	}
	activation := f.pollActivation(t)
	origin := json.RawMessage(fmt.Sprintf(`{"id":%q,"commandId":"activate-one","tenantId":%q,"hostId":%q,"instanceId":%q,"runtime":"fake-persistent","nativeGeneration":%q,"nativeAdmissionId":%q,"runnerId":%q,"runnerEpoch":%q,"bootId":%q,"createdAt":%q}`,
		uuid.NewString(), spec.NetworkTenantID, scope.HostID, scope.InstanceID, activation.NativeGeneration,
		admission.NativeAdmissionID, admission.RunnerID, admission.RunnerEpoch.Format(time.RFC3339Nano), admission.BootID, time.Now().UTC().Format(time.RFC3339Nano)))
	if r := f.call(t, Request{Type: "activation_origin", ActivationOrigin: &ActivationOrigin{ID: activation.ID, NativeGeneration: activation.NativeGeneration, Origin: origin}}); r.Error != "" {
		t.Fatalf("activation origin: %s", r.Error)
	}
	if out := f.waitOutcome(t, 1); out.State != "completed" {
		t.Fatalf("native activation did not complete: %+v", out)
	}

	// The endpoint's interactive control socket appears once its in-tree
	// bridge session authenticated at activation.
	controlSock := filepath.Join(resultDir, "bc-"+strings.ReplaceAll(scope.InstanceID, "-", "")+".sock")
	deadline = time.Now().Add(30 * time.Second)
	for {
		conn, err := net.Dial("unix", controlSock)
		if err == nil {
			f.control = &sideportControlClient{conn: conn, r: bufio.NewReader(conn)}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge control socket %s never became dialable: %v", controlSock, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { _ = f.control.conn.Close() })
	return f
}

// call drives one controller request, failing the test on a transport
// error (a refused frame carries its error in Response.Error).
func (f *sideportOwnerFixture) call(t *testing.T, req Request) Response {
	t.Helper()
	r, err := f.controller.Call(t.Context(), req)
	if err != nil {
		t.Fatalf("controller %q: %v", req.Type, err)
	}
	return r
}

func (f *sideportOwnerFixture) pollActivation(t *testing.T) *ActivationRequest {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r := f.call(t, Request{Type: "activation_poll"})
		if r.Error != "" {
			t.Fatalf("activation poll: %s", r.Error)
		}
		if r.Activation != nil {
			return r.Activation
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("activation request never appeared")
	return nil
}

func (f *sideportOwnerFixture) waitOutcome(t *testing.T, seq int64) Outcome {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r := f.call(t, Request{Type: "outcome", Sequence: seq})
		if r.Error != "" {
			t.Fatalf("outcome %d: %s", seq, r.Error)
		}
		if r.Outcome != nil && r.Outcome.State != "admitted" {
			return *r.Outcome
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("outcome %d never settled", seq)
	return Outcome{}
}

// bridgeAuth opens a FRESH native bridge session (the control fixture dials
// the real native.sock with the worker's nonce + kernel ancestry) and
// returns the raw auth_ok frame.
func (f *sideportOwnerFixture) bridgeAuth(t *testing.T) map[string]any {
	t.Helper()
	reply := f.control.op(t, map[string]any{"op": "auth", "instanceId": f.scope.InstanceID, "networkId": sideportNetworkID})
	resp, ok := reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("auth op reply = %v, want the raw bridge frame", reply)
	}
	if typ, _ := resp["type"].(string); typ != "auth_ok" {
		t.Fatalf("native bridge auth = %v, want auth_ok", resp)
	}
	if id, _ := resp["instanceId"].(string); id != f.scope.InstanceID {
		t.Fatalf("auth_ok instanceId = %q, want %q", id, f.scope.InstanceID)
	}
	return resp
}

// validSideport returns a well-formed triple (a real non-offer stable
// endpoint, a bounded private socket, a bounded original generation).
func (f *sideportOwnerFixture) validSideport(t *testing.T) agentbridge.HostedFabricSideport {
	t.Helper()
	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatalf("build endpoint ref: %v", err)
	}
	return agentbridge.HostedFabricSideport{
		Socket:     filepath.Join(t.TempDir(), "node.sock"),
		Endpoint:   ref,
		Generation: "original-generation",
	}
}

// assertAuthOKShape pins the wire contract: absent sideport → auth_ok is
// EXACTLY today's two keys (byte-identical for the common case); present →
// the "sideport" key parses to the exact triple in the exact
// {socket, endpoint, generation} JSON shape the shipped bridge client
// (agentbridge) consumes.
func assertAuthOKShape(t *testing.T, resp map[string]any, want *agentbridge.HostedFabricSideport) {
	t.Helper()
	if want == nil {
		if _, has := resp["sideport"]; has {
			t.Fatalf("auth_ok carries a sideport: %v", resp)
		}
		if len(resp) != 2 || resp["type"] != "auth_ok" {
			t.Fatalf("sideport-less auth_ok is not today's exact two-key shape: %v", resp)
		}
		return
	}
	raw, err := json.Marshal(resp["sideport"])
	if err != nil {
		t.Fatalf("encode advertised sideport: %v", err)
	}
	var got agentbridge.HostedFabricSideport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("advertised sideport does not parse as agentbridge.HostedFabricSideport: %v (%s)", err, raw)
	}
	if got != *want {
		t.Fatalf("advertised sideport = %+v, want exactly %+v", got, *want)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || len(keys) != 3 || keys["socket"] == nil || keys["endpoint"] == nil || keys["generation"] == nil {
		t.Fatalf("advertised sideport shape = %s, want exactly {socket, endpoint, generation}", raw)
	}
}

// setSideport drives the daemon's owner-administration push as the
// authenticated controller.
func (f *sideportOwnerFixture) setSideport(t *testing.T, sp *agentbridge.HostedFabricSideport) Response {
	t.Helper()
	return f.call(t, Request{Type: "hosted_sideport_set", HostedSideport: sp})
}

// completeBridgeRelay polls the worker's relay broker and completes the
// one forwarded call (the daemon side of a native bridge tool call).
func (f *sideportOwnerFixture) completeBridgeRelay(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r := f.call(t, Request{Type: "bridge_poll"})
		if r.Error != "" {
			t.Fatalf("bridge_poll: %s", r.Error)
		}
		if r.Bridge != nil {
			if done := f.call(t, Request{Type: "bridge_result", Relay: &BridgeResult{ID: r.Bridge.ID, OK: true, Result: json.RawMessage(`{"fixture":"sideport-refresh"}`)}}); done.Error != "" {
				t.Fatalf("bridge_result: %s", done.Error)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bridge call never reached the relay")
}

// bridgeCall runs one tool on a SEPARATE control connection (the fixture
// serializes every op on the one active bridge session).
func (f *sideportOwnerFixture) bridgeCall(t *testing.T, id, tool string) map[string]any {
	t.Helper()
	sock := filepath.Join(filepath.Dir(f.resultFile), "bc-"+strings.ReplaceAll(f.scope.InstanceID, "-", "")+".sock")
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial control socket: %v", err)
	}
	defer conn.Close()
	cc := &sideportControlClient{conn: conn, r: bufio.NewReader(conn)}
	reply := cc.op(t, map[string]any{"op": "call", "id": id, "tool": tool, "args": map[string]any{}})
	resp, ok := reply["response"].(map[string]any)
	if !ok {
		t.Fatalf("call op reply = %v, want the raw bridge frame", reply)
	}
	return resp
}

// readControlPairs polls the fixture's recorded (command, response) history.
func readControlPairs(t *testing.T, path string, minPairs int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			var pairs []map[string]any
			if json.Unmarshal(b, &pairs) == nil && len(pairs) >= minPairs {
				return pairs
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("control result file %s never reached %d pairs", path, minPairs)
	return nil
}

// Test 1: a valid hosted_sideport_set is stored and the NEXT authenticated
// native bridge handshake carries the exact triple in the exact JSON shape
// the shipped bridge client parses.
func TestHostedSideportSetAdvertisedInNativeAuth(t *testing.T) {
	f := newSideportOwnerFixture(t)

	// Baseline: no association — auth_ok is today's exact two keys.
	assertAuthOKShape(t, f.bridgeAuth(t), nil)

	sp := f.validSideport(t)
	if r := f.setSideport(t, &sp); r.Error != "" {
		t.Fatalf("valid sideport set refused: %s", r.Error)
	}
	assertAuthOKShape(t, f.bridgeAuth(t), &sp)
}

// Test 2: invalid payloads are refused fail-closed and nothing is stored —
// the next auth_ok stays byte-identical to today's two-key shape.
func TestHostedSideportSetInvalidPayloadsRefused(t *testing.T) {
	f := newSideportOwnerFixture(t)

	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	offer, err := ref.WithOfferID(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "node.sock")
	cases := []struct {
		name string
		sp   *agentbridge.HostedFabricSideport
	}{
		{"nil payload", nil},
		{"oversized socket", &agentbridge.HostedFabricSideport{Socket: strings.Repeat("x", 108), Endpoint: ref, Generation: "g1"}},
		{"offer endpoint", &agentbridge.HostedFabricSideport{Socket: socket, Endpoint: offer, Generation: "g1"}},
		{"empty generation", &agentbridge.HostedFabricSideport{Socket: socket, Endpoint: ref, Generation: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := f.setSideport(t, tc.sp)
			if r.Error == "" {
				t.Fatalf("invalid sideport set was accepted: %+v", tc.sp)
			}
		})
	}
	// The worker is a pure advertisement carrier: every refusal left the
	// stored value absent, so the handshake is unchanged.
	assertAuthOKShape(t, f.bridgeAuth(t), nil)
}

// Test 3: hosted_sideport_clear drops the advertised value; clearing an
// absent value is a success no-op.
func TestHostedSideportClear(t *testing.T) {
	f := newSideportOwnerFixture(t)

	if r := f.call(t, Request{Type: "hosted_sideport_clear"}); r.Error != "" {
		t.Fatalf("clear when absent must be a success no-op: %s", r.Error)
	}
	assertAuthOKShape(t, f.bridgeAuth(t), nil)

	sp := f.validSideport(t)
	if r := f.setSideport(t, &sp); r.Error != "" {
		t.Fatalf("valid sideport set refused: %s", r.Error)
	}
	assertAuthOKShape(t, f.bridgeAuth(t), &sp)

	if r := f.call(t, Request{Type: "hosted_sideport_clear"}); r.Error != "" {
		t.Fatalf("sideport clear refused: %s", r.Error)
	}
	assertAuthOKShape(t, f.bridgeAuth(t), nil)
}

// Test 4: replace semantics — a second owner set REPLACES the stored value.
func TestHostedSideportSetReplaces(t *testing.T) {
	f := newSideportOwnerFixture(t)

	a := f.validSideport(t)
	if r := f.setSideport(t, &a); r.Error != "" {
		t.Fatalf("first set refused: %s", r.Error)
	}
	// A distinct triple on every field: socket and endpoint differ per
	// validSideport call, the generation is set explicitly.
	b := f.validSideport(t)
	b.Generation = "replaced-generation"
	if b == a {
		t.Fatal("test fixtures must be distinct triples")
	}
	if r := f.setSideport(t, &b); r.Error != "" {
		t.Fatalf("replace set refused: %s", r.Error)
	}
	assertAuthOKShape(t, f.bridgeAuth(t), &b)
}

// Test 5: a non-owner journal (Serve with owner==nil) has no owner request
// surface: both sideport types fall into the existing default refusal.
func TestHostedSideportNonOwnerServeUnsupported(t *testing.T) {
	j, dir := testJournal(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ctx := t.Context()
	go Serve(ctx, j, key, func(out Outcome, payload json.RawMessage) {})

	var (
		ctrl *Controller
		err  error
	)
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctrl, err = DialController(ctx, dir, j.scope, key, "non-owner-controller")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial controller: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { _ = ctrl.Close() })

	ref, err := fabric.NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ctrl.Call(ctx, Request{Type: "hosted_sideport_set", HostedSideport: &agentbridge.HostedFabricSideport{Socket: "/tmp/node.sock", Endpoint: ref, Generation: "g1"}})
	if err != nil || r.Error != "unsupported worker request" {
		t.Fatalf("non-owner set = (%q, %v), want error %q", r.Error, err, "unsupported worker request")
	}
	r, err = ctrl.Call(ctx, Request{Type: "hosted_sideport_clear"})
	if err != nil || r.Error != "unsupported worker request" {
		t.Fatalf("non-owner clear = (%q, %v), want error %q", r.Error, err, "unsupported worker request")
	}
}

// Test 6: refresh semantics (brief §3.4). A bridge connection authenticated
// BEFORE the association keeps its original tools for its lifetime — the
// sideport is read at auth time only; a NEW bridge session picks it up.
func TestHostedSideportRefreshSemantics(t *testing.T) {
	f := newSideportOwnerFixture(t)

	// The activation-time in-tree session authenticated BEFORE anything was
	// associated: its recorded auth_ok carries no sideport.
	pairs := readControlPairs(t, f.resultFile, 1)
	activationResp, ok := pairs[0]["resp"].(map[string]any)
	if !ok {
		t.Fatalf("activation pair = %v, want a response", pairs[0])
	}
	if frame, ok := activationResp["response"].(map[string]any); !ok || frame["type"] != "auth_ok" {
		t.Fatalf("activation auth = %v, want auth_ok", activationResp)
	} else if _, has := frame["sideport"]; has {
		t.Fatalf("pre-association auth_ok carried a sideport: %v", frame)
	}

	sp := f.validSideport(t)
	if r := f.setSideport(t, &sp); r.Error != "" {
		t.Fatalf("valid sideport set refused: %s", r.Error)
	}

	// The pre-set session (the activation's active connection) still serves
	// its original tools — no retroactive injection, no breakage. The call
	// blocks until the daemon side completes the relay, so the two run in
	// parallel.
	callDone := make(chan map[string]any, 1)
	go func() { callDone <- f.bridgeCall(t, "refresh-1", "network_whoami") }()
	f.completeBridgeRelay(t)
	var callResp map[string]any
	select {
	case callResp = <-callDone:
	case <-time.After(30 * time.Second):
		t.Fatal("pre-set session tool call never answered")
	}
	if callResp["ok"] != true {
		t.Fatalf("pre-set session tool call = %v, want ok:true", callResp)
	}

	// A NEW bridge session (agent restart / MCP reconnect) picks the
	// sideport up at auth time.
	assertAuthOKShape(t, f.bridgeAuth(t), &sp)
}
