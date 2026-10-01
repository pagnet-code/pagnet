package main

// V2 contract tests for the two commands that drifted from the strict V2
// control plane (2026-09-30): `pagnet run` agent creation — which sent the
// removed V1 profile/capabilities fields and 400'd on
// DisallowUnknownFields — and `pagnet send` — which sent the removed
// recipientAgent field in plaintext, which the always-encrypted V2 server
// also rejects. These pin the EXACT request JSON the fixed commands send:
// the V2 agent-creation body (console-parity fields, concrete runtime
// resolved from the host's reported runtimes) and the V2 message body
// (recipientPrincipalId + recipientInstanceId + the client-encrypted
// envelope, no plaintext anywhere).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/transport"
)

// --- harness --------------------------------------------------------------------

// recordedRequest is one captured request (method, path, raw body).
type recordedRequest struct {
	Method string
	Path   string
	Body   string
}

// recordServer is a stub control plane keyed on "METHOD /path" (run's flow
// GETs and POSTs the SAME /agents path, which the path-only stubs cannot
// tell apart). Every request is recorded for body assertions.
type recordServer struct {
	t      *testing.T
	ts     *httptest.Server
	mu     sync.Mutex
	reqs   []recordedRequest
	routes map[string]string
}

func newRecordServer(t *testing.T, routes map[string]string) *recordServer {
	t.Helper()
	s := &recordServer{t: t, routes: routes}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		resp, ok := s.routes[r.Method+" "+r.URL.Path]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		fmt.Fprint(w, resp)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

// lastBody returns the raw body of the LAST "METHOD /path" request.
func (s *recordServer) lastBody(method, path string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.reqs) - 1; i >= 0; i-- {
		if s.reqs[i].Method == method && s.reqs[i].Path == path {
			return s.reqs[i].Body, true
		}
	}
	return "", false
}

// noCall reports whether NO request matched "METHOD /path".
func (s *recordServer) noCall(method, path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reqs {
		if r.Method == method && r.Path == path {
			return false
		}
	}
	return true
}

// seedHostConfig writes the account config of stateDir with an enrolled
// host (credential + hostId) so `pagnet run` passes its preflight without a
// real enrollment. The REST bearer for the test is separate (userToken).
func seedHostConfig(t *testing.T, stateDir, serverURL, hostID string) {
	t.Helper()
	accDir := filepath.Join(stateDir, "accounts", "default")
	if err := accounts.SetCurrent(stateDir, "default"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(accDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("serverUrl: %s\ncredential: pgn_host_test\nhostId: %s\nhostName: testhost\n",
		serverURL, hostID)
	if err := os.WriteFile(filepath.Join(accDir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cliFlags pins the package-level CLI flag vars for one test against srv
// (the same isolation cliEnv gives the golden tests) and returns a restore
// func. HOME is set LAST (after cliEnv-style setup) when the caller needs a
// controlled state dir: the last t.Setenv wins.
func cliFlags(t *testing.T, srv *httptest.Server) {
	t.Helper()
	prevServer := serverURL
	serverURL = srv.URL
	prevToken := userToken
	userToken = "test-token"
	prevNonInt := nonInteractive
	nonInteractive = true
	prevSilent := silent
	silent = true
	prevJSON := jsonOut
	jsonOut = false
	t.Cleanup(func() {
		serverURL = prevServer
		userToken = prevToken
		nonInteractive = prevNonInt
		silent = prevSilent
		jsonOut = prevJSON
	})
}

// activeCryptoHome makes HOME/.pagnet the crypto-active state dir for netID
// (the daemon's announced state + the local keyring — exactly what a
// crypto-active daemon on this host leaves behind) and returns the epoch id
// and epoch key (for decrypt assertions).
func activeCryptoHome(t *testing.T, netID, tenantID string) (epochID string, key [32]byte) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateDir := filepath.Join(home, ".pagnet")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, epochID, key = activateNetworkState(t, stateDir, netID, tenantID)
	return epochID, key
}

const (
	testNetID    = "6f0c1b3e-8d52-4c1a-9f0e-0a1b2c3d4e5f"
	testTenantID = "tenant-1"
)

// --- autoPickRuntime (console Auto parity) ---------------------------------------

func TestAutoPickRuntime(t *testing.T) {
	rt := func(names ...string) []hostRuntime {
		out := make([]hostRuntime, 0, len(names))
		for _, n := range names {
			out = append(out, hostRuntime{Runtime: n})
		}
		return out
	}
	cases := []struct {
		name     string
		reported []hostRuntime
		want     string
	}{
		{"none", rt(), ""},
		{"debug only falls back to the first reported", rt("fake-persistent", "fake"), "fake-persistent"},
		{"fake alone", rt("fake"), "fake"},
		{"preference order beats first-seen", rt("claude-code", "qwen-code"), "qwen-code"},
		{"preference across four", rt("opencode", "claude-code", "qwen-code", "codex"), "qwen-code"},
		{"other real before debug", rt("generic", "fake"), "generic"},
		{"real wins over debug regardless of order", rt("fake", "codex"), "codex"},
		{"dedupe keeps first-seen", rt("opencode", "opencode", "fake"), "opencode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoPickRuntime(tc.reported); got != tc.want {
				t.Errorf("autoPickRuntime(%v) = %q, want %q", tc.reported, got, tc.want)
			}
		})
	}
}

// TestAgentCreateBody: the V2 creation body field-for-field — the fields
// the strict server decodes, and (critically) NOT profile / capabilities.
func TestAgentCreateBody(t *testing.T) {
	b := agentCreateBody("atlas", "qwen-code", "read_write", "res-1")
	if b["name"] != "atlas" || b["runtime"] != "qwen-code" {
		t.Errorf("body = %v, want name atlas + runtime qwen-code", b)
	}
	es, _ := b["executionSettings"].(map[string]any)
	if es == nil || es["access"] != "read_write" {
		t.Errorf("executionSettings = %v, want access read_write", b["executionSettings"])
	}
	resp, _ := b["responsibilities"].([]any)
	if len(resp) != 1 {
		t.Fatalf("responsibilities = %v, want the resource binding", b["responsibilities"])
	}
	binding, _ := resp[0].(map[string]any)
	if binding["resourceId"] != "res-1" {
		t.Errorf("binding = %v, want resourceId res-1", binding)
	}
	for _, k := range []string{"profile", "capabilities", "mission", "instruction"} {
		if _, ok := b[k]; ok {
			t.Errorf("body carries %q — the V2 server rejects the whole request for it", k)
		}
	}
	// Non-git workspaces have no logical resource: no responsibilities key.
	if b2 := agentCreateBody("atlas", "fake", "read_only", ""); b2["responsibilities"] != nil {
		t.Errorf("no-resource body carries responsibilities: %v", b2)
	}
}

// --- pagnet run: the V2 agent-creation + launch contract -------------------------

// runTestEnv wires a stub control plane + an enrolled host state dir for
// one runCmd invocation, chdir'ing into workDir (the "local directory" the
// launch targets). It returns the server (for body assertions) and the
// chdir'd work dir (for the host-detail workspaces fixture).
func runTestEnv(t *testing.T, runtimesJSON string, extraRoutes map[string]string) *recordServer {
	t.Helper()
	workDir := t.TempDir()
	t.Chdir(workDir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateDir := filepath.Join(home, ".pagnet")

	hostDetail := fmt.Sprintf(
		`{"host":{"ID":"host-1","Name":"testhost","Status":"online"},`+
			`"workspaces":[{"ID":"ws-1","Path":%q}],`+
			`"runtimes":[%s]}`, workDir, runtimesJSON)
	routes := map[string]string{
		"GET /api/v1/networks":                                     `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"GET /api/v1/hosts/host-1":                                 hostDetail,
		"GET /api/v1/networks/net-1/agents":                        `[]`,
		"POST /api/v1/networks/net-1/agents":                       `{"ID":"def-1"}`,
		"POST /api/v1/networks/net-1/agents/def-1/launch":          `{"ID":"inst-1","Status":"starting"}`,
		"GET /api/v1/networks/net-1/agents/def-1/instances/inst-1": `{"instance":{"Status":"idle"}}`,
	}
	for k, v := range extraRoutes {
		routes[k] = v
	}
	srv := newRecordServer(t, routes)
	cliFlags(t, srv.ts)
	seedHostConfig(t, stateDir, srv.ts.URL, "host-1")
	return srv
}

// TestRunAgentCreateV2Body: the FULL path that used to 400 — the create
// body is the V2 contract (no profile/capabilities; the concrete runtime
// auto-resolved from the host's reported runtimes, console preference
// order) and the launch carries the same runtime.
func TestRunAgentCreateV2Body(t *testing.T) {
	srv := runTestEnv(t,
		`{"Runtime":"claude-code"},{"Runtime":"qwen-code"}`, nil)

	cmd := runCmd()
	cmd.SetArgs([]string{"--name", "e2e-agent"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "agent:        e2e-agent") {
		t.Errorf("run output missing the created agent:\n%s", out)
	}
	// The create body: field-for-field the V2 contract.
	body, ok := srv.lastBody("POST", "/api/v1/networks/net-1/agents")
	if !ok {
		t.Fatal("no agent creation POST")
	}
	var create map[string]any
	if err := json.Unmarshal([]byte(body), &create); err != nil {
		t.Fatalf("create body is not an object: %v (%s)", err, body)
	}
	if create["name"] != "e2e-agent" {
		t.Errorf("name = %v, want e2e-agent", create["name"])
	}
	// Auto-pick over [claude-code, qwen-code] = qwen-code (preference order).
	if create["runtime"] != "qwen-code" {
		t.Errorf("runtime = %v, want the auto-picked qwen-code", create["runtime"])
	}
	es, _ := create["executionSettings"].(map[string]any)
	if es == nil || es["access"] != "read_write" {
		t.Errorf("executionSettings = %v, want the default read_write access", create["executionSettings"])
	}
	// Non-git directory: no logical resource, so no responsibilities.
	if _, ok := create["responsibilities"]; ok {
		t.Errorf("non-git create body carries responsibilities: %v", create)
	}
	// The V1 drift fields are GONE — the strict server 400's on any of them.
	for _, k := range []string{"profile", "capabilities", "mission", "instruction"} {
		if _, ok := create[k]; ok {
			t.Errorf("create body carries %q — the V2 server rejects the whole request for it", k)
		}
	}
	// The launch: pinned to the host + workspace, and carries the SAME
	// concrete runtime as the definition (console parity: both sources
	// agree).
	launch, ok := srv.lastBody("POST", "/api/v1/networks/net-1/agents/def-1/launch")
	if !ok {
		t.Fatal("no launch POST")
	}
	var lb map[string]any
	if err := json.Unmarshal([]byte(launch), &lb); err != nil {
		t.Fatalf("launch body is not an object: %v (%s)", err, launch)
	}
	if lb["hostId"] != "host-1" || lb["workspaceId"] != "ws-1" {
		t.Errorf("launch hostId/workspaceId = %v/%v, want host-1/ws-1", lb["hostId"], lb["workspaceId"])
	}
	if lb["runtime"] != "qwen-code" {
		t.Errorf("launch runtime = %v, want qwen-code (the resolved concrete runtime)", lb["runtime"])
	}
}

// TestRunAgentCreateExplicitRuntime: an explicit --runtime passes through
// verbatim (including the debug-only fake, even on a host that reports no
// runtimes at all).
func TestRunAgentCreateExplicitRuntime(t *testing.T) {
	srv := runTestEnv(t, ``, nil)

	cmd := runCmd()
	cmd.SetArgs([]string{"--name", "e2e-agent", "--runtime", "fake"})
	if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
		t.Fatalf("run: %v", err)
	}
	body, _ := srv.lastBody("POST", "/api/v1/networks/net-1/agents")
	var create map[string]any
	_ = json.Unmarshal([]byte(body), &create)
	if create["runtime"] != "fake" {
		t.Errorf("runtime = %v, want the explicit fake", create["runtime"])
	}
	launch, _ := srv.lastBody("POST", "/api/v1/networks/net-1/agents/def-1/launch")
	var lb map[string]any
	_ = json.Unmarshal([]byte(launch), &lb)
	if lb["runtime"] != "fake" {
		t.Errorf("launch runtime = %v, want the explicit fake", lb["runtime"])
	}
}

// TestRunAgentCreateNoRuntimesFailsClear: a host that reports no runtimes
// cannot be auto-resolved — the run fails with the clear fix, and NOTHING
// is created or launched.
func TestRunAgentCreateNoRuntimesFailsClear(t *testing.T) {
	srv := runTestEnv(t, ``, nil)

	cmd := runCmd()
	cmd.SetArgs([]string{"--name", "e2e-agent"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "reports no runtimes") {
		t.Fatalf("err = %v, want the no-runtimes error naming the host", err)
	}
	if !srv.noCall("POST", "/api/v1/networks/net-1/agents") {
		t.Error("an agent was created on a host with no runtimes")
	}
	if !srv.noCall("POST", "/api/v1/networks/net-1/agents/def-1/launch") {
		t.Error("a launch was dispatched to a host with no runtimes")
	}
}

// --- pagnet send: the V2 message contract -----------------------------------------

// sendTestRoutes builds the four routes send resolves through; instances is
// the raw JSON array of the agent's instances.
func sendTestRoutes(t *testing.T, instances string) map[string]string {
	return map[string]string{
		"GET /api/v1/networks":                                          `[{"ID":"` + testNetID + `","Name":"default","Slug":"default"}]`,
		"GET /api/v1/networks/" + testNetID + `/agents`:                 `[{"ID":"def-1","Name":"atlas","PrincipalID":"principal-atlas"}]`,
		"GET /api/v1/networks/" + testNetID + `/agents/def-1/instances`: instances,
		"POST /api/v1/networks/" + testNetID + `/messages`:              `{"ID":"msg-1"}`,
	}
}

// TestSendV2MessageBody: the exact V2 message POST — recipientPrincipalId +
// recipientInstanceId + the client-encrypted envelope (id bound to the
// AAD), and NO plaintext / V1 fields. The ciphertext decrypts to the sent
// text under the announced epoch (the same read-back the console and the
// recipient daemon perform).
func TestSendV2MessageBody(t *testing.T) {
	epochID, key := activeCryptoHome(t, testNetID, testTenantID)
	srv := newRecordServer(t, sendTestRoutes(t,
		`[{"ID":"inst-1","Status":"idle","HostID":"host-1"}]`))
	cliFlags(t, srv.ts)

	cmd := sendCmd()
	cmd.SetArgs([]string{"atlas", "hello", "world"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("send: %v\n%s", err, out)
	}
	if !strings.Contains(out, "message msg-1 sent to atlas") {
		t.Errorf("send output = %q, want the durable-ack line", out)
	}

	body, ok := srv.lastBody("POST", "/api/v1/networks/"+testNetID+"/messages")
	if !ok {
		t.Fatal("no message POST")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("message body is not an object: %v (%s)", err, body)
	}
	if m["kind"] != "ASK" {
		t.Errorf("kind = %v, want the ASK default", m["kind"])
	}
	if m["recipientPrincipalId"] != "principal-atlas" {
		t.Errorf("recipientPrincipalId = %v, want the agent's principal", m["recipientPrincipalId"])
	}
	if m["recipientInstanceId"] != "inst-1" {
		t.Errorf("recipientInstanceId = %v, want the resolved instance inst-1", m["recipientInstanceId"])
	}
	// The removed V1 field + the refused sender claim + plaintext content
	// are ALL gone (V2 networks reject any of them).
	for _, k := range []string{"recipientAgent", "senderInstanceId", "text", "parts"} {
		if _, ok := m[k]; ok {
			t.Errorf("message body carries %q — the V2 server rejects it", k)
		}
	}
	// The E2EE fields: the client-minted id the AAD binds, the envelope,
	// and the verbatim AAD.
	id, _ := m["id"].(string)
	u, err := uuid.Parse(id)
	if err != nil || u.Version() != 7 {
		t.Fatalf("id = %q, want a client-minted UUIDv7", id)
	}
	var env e2ee.EncryptedPayloadV1
	if raw, ok := m["envelope"]; !ok || json.Unmarshal(mustJSONBytes(t, raw), &env) != nil {
		t.Fatalf("message body carries no decodable envelope: %s", body)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("envelope is not structurally valid: %v", err)
	}
	var aad e2ee.AAD
	if raw, ok := m["aad"]; !ok || json.Unmarshal(mustJSONBytes(t, raw), &aad) != nil {
		t.Fatalf("message body carries no decodable AAD: %s", body)
	}
	if aad.ObjectType != e2ee.ObjectTypeMessage {
		t.Errorf("AAD.ObjectType = %q, want %q", aad.ObjectType, e2ee.ObjectTypeMessage)
	}
	if aad.ObjectID != id {
		t.Errorf("AAD.ObjectID = %q, want the bound client id %q", aad.ObjectID, id)
	}
	if aad.Recipient != "principal-atlas" {
		t.Errorf("AAD.Recipient = %q, want the addressed principal", aad.Recipient)
	}
	if aad.Sender != "" {
		t.Errorf("AAD.Sender = %q, want \"\" (the CLI acts for the signed-in user)", aad.Sender)
	}
	if transport.ProtocolVersion != 2 {
		t.Fatalf("test assumes the V2 wire (transport.ProtocolVersion = %d)", transport.ProtocolVersion)
	}
	if aad.ProtocolVersion != transport.ProtocolVersion {
		t.Errorf("AAD.ProtocolVersion = %d, want %d (the V2 wire)", aad.ProtocolVersion, transport.ProtocolVersion)
	}
	if aad.TenantID != testTenantID || aad.NetworkID != testNetID {
		t.Errorf("AAD tenant/network = %q/%q, want %q/%q", aad.TenantID, aad.NetworkID, testTenantID, testNetID)
	}
	if aad.KeyEpochID != epochID {
		t.Errorf("AAD.KeyEpochID = %q, want the announced epoch %q", aad.KeyEpochID, epochID)
	}
	// Read-back: decrypt with the announced epoch key (exactly what the
	// recipient daemon and the console do with the server-relayed AAD).
	plain, err := e2ee.Decrypt(env, key, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	parts, decodeErr := domain.DecodeMessageContent(plain)
	if decodeErr != nil || domain.RenderMessageParts(parts) != "hello world" {
		t.Errorf("decrypted = %q, want %q", plain, "hello world")
	}
}

// TestSendMultiInstance: several instances require --instance (the error
// lists every choice); --instance picks the named one; a foreign instance
// id is refused; nothing is POSTed on the error paths.
func TestSendMultiInstance(t *testing.T) {
	const instances = `[{"ID":"inst-1","Status":"idle","HostID":"host-1"},{"ID":"inst-2","Status":"working","HostID":"host-2"}]`

	t.Run("without instance flag, lists the choices and sends nothing", func(t *testing.T) {
		_, key := activeCryptoHome(t, testNetID, testTenantID)
		_ = key
		srv := newRecordServer(t, sendTestRoutes(t, instances))
		cliFlags(t, srv.ts)
		cmd := sendCmd()
		cmd.SetArgs([]string{"atlas", "hello"})
		_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err == nil {
			t.Fatal("send succeeded without --instance on a multi-instance agent")
		}
		if !strings.Contains(err.Error(), "inst-1") || !strings.Contains(err.Error(), "inst-2") {
			t.Errorf("error %q does not list both instances", err)
		}
		if !strings.Contains(err.Error(), "--instance") {
			t.Errorf("error %q does not name the --instance flag", err)
		}
		if !srv.noCall("POST", "/api/v1/networks/"+testNetID+"/messages") {
			t.Error("a message was posted on the ambiguous-addressing error path")
		}
	})

	t.Run("with instance flag, pins that instance", func(t *testing.T) {
		_, key := activeCryptoHome(t, testNetID, testTenantID)
		_ = key
		srv := newRecordServer(t, sendTestRoutes(t, instances))
		cliFlags(t, srv.ts)
		cmd := sendCmd()
		cmd.SetArgs([]string{"atlas", "hello", "--instance", "inst-2"})
		if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
			t.Fatalf("send: %v", err)
		}
		body, _ := srv.lastBody("POST", "/api/v1/networks/"+testNetID+"/messages")
		var m map[string]any
		_ = json.Unmarshal([]byte(body), &m)
		if m["recipientInstanceId"] != "inst-2" {
			t.Errorf("recipientInstanceId = %v, want inst-2 (the --instance choice)", m["recipientInstanceId"])
		}
		if m["recipientPrincipalId"] != "principal-atlas" {
			t.Errorf("recipientPrincipalId = %v, want the agent's principal", m["recipientPrincipalId"])
		}
	})

	t.Run("a foreign instance id is refused", func(t *testing.T) {
		_, key := activeCryptoHome(t, testNetID, testTenantID)
		_ = key
		srv := newRecordServer(t, sendTestRoutes(t, instances))
		cliFlags(t, srv.ts)
		cmd := sendCmd()
		cmd.SetArgs([]string{"atlas", "hello", "--instance", "inst-9"})
		_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err == nil || !strings.Contains(err.Error(), "is not one of agent atlas's instances") {
			t.Fatalf("err = %v, want the foreign-instance refusal", err)
		}
		if !srv.noCall("POST", "/api/v1/networks/"+testNetID+"/messages") {
			t.Error("a message was posted for a foreign instance id")
		}
	})
}

// TestSendNoInstances: a defined-but-never-launched agent gets the clear
// launch-first error, no POST.
func TestSendNoInstances(t *testing.T) {
	activeCryptoHome(t, testNetID, testTenantID)
	srv := newRecordServer(t, sendTestRoutes(t, `[]`))
	cliFlags(t, srv.ts)

	cmd := sendCmd()
	cmd.SetArgs([]string{"atlas", "hello"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "has no instance in this network") {
		t.Fatalf("err = %v, want the no-instance launch-first error", err)
	}
	if !srv.noCall("POST", "/api/v1/networks/"+testNetID+"/messages") {
		t.Error("a message was posted with no delivery target")
	}
}

// TestSendUnknownAgent: an unknown agent name fails before any crypto or
// network write.
func TestSendUnknownAgent(t *testing.T) {
	activeCryptoHome(t, testNetID, testTenantID)
	srv := newRecordServer(t, map[string]string{
		"GET /api/v1/networks":                          `[{"ID":"` + testNetID + `","Name":"default","Slug":"default"}]`,
		"GET /api/v1/networks/" + testNetID + `/agents`: `[]`,
	})
	cliFlags(t, srv.ts)

	cmd := sendCmd()
	cmd.SetArgs([]string{"ghost", "hello"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), `is not an agent in this network`) {
		t.Fatalf("err = %v, want the unknown-agent error", err)
	}
	if !srv.noCall("POST", "/api/v1/networks/"+testNetID+"/messages") {
		t.Error("a message was posted for an unknown agent")
	}
}

// TestSendFailClosed: a network whose crypto is not active (no daemon state
// on this host) refuses the send with the clear not-ready error — there is
// NO plaintext fallback, and nothing is posted.
func TestSendFailClosed(t *testing.T) {
	// A fresh HOME with NO daemon state: the fail-closed precondition.
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv := newRecordServer(t, sendTestRoutes(t,
		`[{"ID":"inst-1","Status":"idle","HostID":"host-1"}]`))
	cliFlags(t, srv.ts)

	cmd := sendCmd()
	cmd.SetArgs([]string{"atlas", "hello"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if !errors.Is(err, ErrClientCryptoNotReady) {
		t.Fatalf("err = %v, want the clear not-ready error (no plaintext mode)", err)
	}
	if !strings.Contains(err.Error(), "no daemon state") {
		t.Errorf("err = %v, want the no-daemon-state reason", err)
	}
	if !srv.noCall("POST", "/api/v1/networks/"+testNetID+"/messages") {
		t.Error("an unencrypted message was posted")
	}
}

// --- helpers ----------------------------------------------------------------------

// mustJSONBytes marshals v (a decoded JSON fragment) back to compact bytes.
func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
