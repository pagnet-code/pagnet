package main

// V2 cutover CLI tests (plan D10): --json goldens against a fake V2 control
// plane, recipe parsing + non-interactive fail-fast, client-side E2EE
// (fail-closed when the network is not active; round-trip + AAD binding when
// it is), and the invoke end-to-end (encrypt → POST → decrypt the result).

import (
	"bytes"
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
	"time"

	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/transport"
)

// --- harness ------------------------------------------------------------------

// stubV2Server is a fake V2 control plane: fixed JSON responses per path,
// recorded calls (method + path + body).
type stubV2Server struct {
	mu        sync.Mutex
	ts        *httptest.Server
	responses map[string]string
	calls     []string
}

func newStubV2Server(t *testing.T, responses map[string]string) *stubV2Server {
	t.Helper()
	s := &stubV2Server{responses: responses}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path+" "+string(body))
		resp, ok := s.responses[r.URL.Path]
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

func (s *stubV2Server) hasCall(substr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// cliEnv isolates the CLI for one test: a private HOME (account state), the
// stub server as the control plane, a static user token, and non-interactive
// fail-fast by default. Package flag vars are restored on cleanup.
func cliEnv(t *testing.T, ts *httptest.Server) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PAGNET_TOKEN", "")

	prevServer := serverURL
	serverURL = ts.URL
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

// withNoPrompts traps any interactive prompt: a prompt in a
// non-interactive run is a test failure.
func withNoPrompts(t *testing.T) {
	t.Helper()
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true } // the code must rely on --non-interactive
	prevAsk := askLineFn
	askLineFn = func(prompt string) (string, error) {
		t.Errorf("prompt attempted in non-interactive run: %q", prompt)
		return "", errors.New("no prompts in non-interactive mode")
	}
	t.Cleanup(func() { hasTTYFn = prevTTY; askLineFn = prevAsk })
}

// captureStdoutErr runs fn with os.Stdout captured (the V2 commands print via
// fmt). It returns the captured output and the run error.
func captureStdoutErr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	<-done
	return buf.String(), runErr
}

// --- --json goldens -------------------------------------------------------------

// TestAgentsCmdJSONGolden: `pagnet agents --json` renders the V2 agent
// document exactly (the machine-readable contract).
func TestAgentsCmdJSONGolden(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks":                `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/networks/net-1/agents":   `[{"id":"agent-1","name":"atlas","kind":"agent","status":"idle","capabilities":[{"id":"atlas.echo","version":1,"name":"echo","description":"echoes","tags":["tool"]}],"endpoints":[{"id":"ep-1","name":"local","status":"idle","online":true}],"permissions":["communicate","invoke"],"state":"active"}]`,
		"/api/v1/networks/net-1/services": `[]`,
	})
	cliEnv(t, ts.ts)
	jsonOut = true

	cmd := agentsCmd()
	cmd.SetArgs(nil)
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("agents: %v", err)
	}
	want := `[
  {
    "id": "agent-1",
    "name": "atlas",
    "kind": "agent",
    "status": "idle",
    "capabilities": [
      {
        "id": "atlas.echo",
        "version": 1,
        "name": "echo",
        "description": "echoes",
        "tags": [
          "tool"
        ]
      }
    ],
    "endpoints": [
      {
        "id": "ep-1",
        "name": "local",
        "status": "idle",
        "online": true
      }
    ],
    "permissions": [
      "communicate",
      "invoke"
    ],
    "state": "active"
  }
]
`
	if out != want {
		t.Fatalf("agents --json golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// TestSearchCmdJSONGolden: `pagnet search --json` renders the result page
// exactly (results + cursor).
func TestSearchCmdJSONGolden(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks":              `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/networks/net-1/search": `{"results":[{"id":"cap-1","kind":"capability","name":"documents.extract","capability":"documents.extract","description":"Extract text from documents","matchReasons":["capability id exact"],"state":"active"},{"id":"svc-1","kind":"service","name":"docs-svc","capability":"documents.extract","state":"active"}],"cursor":""}`,
	})
	cliEnv(t, ts.ts)
	jsonOut = true

	cmd := searchCmd()
	cmd.SetArgs([]string{"documents"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	want := `{
  "cursor": "",
  "results": [
    {
      "id": "cap-1",
      "kind": "capability",
      "name": "documents.extract",
      "capability": "documents.extract",
      "description": "Extract text from documents",
      "matchReasons": [
        "capability id exact"
      ],
      "state": "active"
    },
    {
      "id": "svc-1",
      "kind": "service",
      "name": "docs-svc",
      "capability": "documents.extract",
      "state": "active"
    }
  ]
}
`
	if out != want {
		t.Fatalf("search --json golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// TestSubscriptionsCmdJSONGolden: `pagnet subscriptions --json` renders the
// subscription list exactly.
func TestSubscriptionsCmdJSONGolden(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks":                     `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/networks/net-1/subscriptions": `[{"id":"sub-1","eventPattern":"build.*","mode":"push"},{"id":"sub-2","eventPattern":"deploy.*"}]`,
	})
	cliEnv(t, ts.ts)
	jsonOut = true

	cmd := subscriptionsCmd()
	cmd.SetArgs(nil)
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("subscriptions: %v", err)
	}
	want := `[
  {
    "id": "sub-1",
    "eventPattern": "build.*",
    "mode": "push"
  },
  {
    "id": "sub-2",
    "eventPattern": "deploy.*"
  }
]
`
	if out != want {
		t.Fatalf("subscriptions --json golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// --- recipe parsing (D13) ----------------------------------------------------------

const recipeServiceYAML = `apiVersion: pagnet.dev/v1
kind: Service
metadata:
  name: svc-echo
  description: "echo service"
capabilities:
  - id: svc.echo
    description: echoes its input
subscriptions:
  - event: "build.*"
    mode: push
permissions:
  requested: [invoke]
`

func TestParseRecipeValidKinds(t *testing.T) {
	for _, kind := range []string{"Recipe", "Service", "AgentTemplate"} {
		t.Run(kind, func(t *testing.T) {
			raw := strings.Replace(recipeServiceYAML, "kind: Service", "kind: "+kind, 1)
			m, err := parseRecipe([]byte(raw))
			if err != nil {
				t.Fatalf("kind %s: %v", kind, err)
			}
			if m.Kind != kind {
				t.Errorf("kind = %q, want %q", m.Kind, kind)
			}
			if m.Metadata.Name != "svc-echo" {
				t.Errorf("name = %q, want svc-echo", m.Metadata.Name)
			}
			// The capability's omitted version defaults to 1.
			if v := m.Capabilities[0].Version; v != 1 {
				t.Errorf("capability version = %d, want the default 1", v)
			}
		})
	}
}

func TestParseRecipeErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string // exact error (nil = substring check via wantSub)
	}{
		{"bad apiVersion", "apiVersion: pagnet.dev/v0\nkind: Service\nmetadata:\n  name: x\n", `unsupported apiVersion "pagnet.dev/v0" (want pagnet.dev/v1)`},
		{"bad kind", "apiVersion: pagnet.dev/v1\nkind: Pod\nmetadata:\n  name: x\n", `unsupported kind "Pod" (want Recipe | Service | AgentTemplate)`},
		{"missing name", "apiVersion: pagnet.dev/v1\nkind: Service\nmetadata:\n  description: no name\n", `recipe metadata.name is required`},
		{"capability not dot-separated", "apiVersion: pagnet.dev/v1\nkind: Service\nmetadata:\n  name: x\ncapabilities:\n  - id: extract\n", `capability ids are dot-separated (e.g. documents.extract); got "extract"`},
		{"missing capability id", "apiVersion: pagnet.dev/v1\nkind: Service\nmetadata:\n  name: x\ncapabilities:\n  - description: no id\n", `capabilities[0].id is required`},
		{"missing subscription event", "apiVersion: pagnet.dev/v1\nkind: Service\nmetadata:\n  name: x\nsubscriptions:\n  - mode: push\n", `subscriptions[0].event is required`},
		{"bad permission", "apiVersion: pagnet.dev/v1\nkind: Service\nmetadata:\n  name: x\npermissions:\n  requested: [fly]\n", `unknown permission "fly" (discover|communicate|invoke|event_publish|event_subscribe|task_read|task_write|operate)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRecipe([]byte(tc.raw))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("not yaml", func(t *testing.T) {
		_, err := parseRecipe([]byte("apiVersion: [unclosed"))
		if err == nil || !strings.Contains(err.Error(), "recipe is not valid YAML") {
			t.Fatalf("error = %v, want the not-valid-YAML error", err)
		}
	})
}

// --- recipe apply: non-interactive fail-fast --------------------------------------

func recipeApplyArgs(t *testing.T) []string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "recipe.yaml")
	if err := os.WriteFile(f, []byte(recipeServiceYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return []string{"apply", f}
}

// TestRecipeApplyFailFastNoNetwork: --non-interactive + no resolvable network
// → the exact error, nothing created, no prompt.
func TestRecipeApplyFailFastNoNetwork(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks": `[]`,
	})
	cliEnv(t, ts.ts)
	withNoPrompts(t)

	cmd := recipeCmd()
	cmd.SetArgs(recipeApplyArgs(t))
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || err.Error() != "no networks exist (create one first)" {
		t.Fatalf("error = %v, want the fail-fast network error", err)
	}
	// Nothing was created.
	if ts.hasCall("POST") {
		t.Error("API writes were attempted before the network was resolved")
	}
}

// TestRecipeApplyNonInteractiveApplies: --non-interactive + a resolvable
// network → the manifest applies deterministically, no prompt, and the
// one-time activation credential is printed.
func TestRecipeApplyNonInteractiveApplies(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks": `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		// The real POST /services shape (api_services.go): the principal is
		// nested under "principal" and marshals domain.Principal's exported
		// field names, and the activation credential is an object.
		"/api/v1/services":                     `{"principal":{"ID":"svc-1","Name":"svc-echo"},"activationCredential":{"credential":"pgn_epd_v1_test","expiresAt":"2026-01-01T00:00:00Z"}}`,
		"/api/v1/networks/net-1/services":      `{}`,
		"/api/v1/networks/net-1/subscriptions": `{"id":"sub-9"}`,
	})
	cliEnv(t, ts.ts) // silent: the non-interactive path skips the summary
	withNoPrompts(t)

	cmd := recipeCmd()
	cmd.SetArgs(recipeApplyArgs(t))
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("recipe apply: %v", err)
	}
	// The D12 call sequence: create the service, join the network, subscribe.
	if !ts.hasCall(`POST /api/v1/services `) || !ts.hasCall(`"name":"svc-echo"`) {
		t.Error("the service was not created with the manifest's name")
	}
	if !ts.hasCall(`POST /api/v1/networks/net-1/services `) || !ts.hasCall(`"principalId":"svc-1"`) {
		t.Error("the service was not added to the network with its id")
	}
	if !ts.hasCall(`POST /api/v1/networks/net-1/subscriptions `) || !ts.hasCall(`"eventPattern":"build.*"`) || !ts.hasCall(`"mode":"push"`) {
		t.Error("the subscription was not created from the manifest")
	}
	want := `applied Service "svc-echo" to network default
capabilities: svc.echo
subscription: build.* (mode push)

activation credential (one-time — save it now, it is shown only once):
  pgn_epd_v1_test
`
	if out != want {
		t.Fatalf("apply output mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// --- client-side E2EE (D6) ---------------------------------------------------------

// activeCryptoHost prepares a HOME-like state dir with an ACTIVE announced
// network + the local keyring, and returns the state dir, network id, and
// active epoch id.
func activeCryptoHost(t *testing.T, networkID, tenantID string) (stateDir, epochID string) {
	t.Helper()
	stateDir = t.TempDir()
	kr, err := crypto.ActivateNetwork(stateDir, tenantID, networkID, time.Now())
	if err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatalf("ActiveEpoch: %v", err)
	}
	db, err := daemon.OpenState(filepath.Join(stateDir, "daemon.sqlite"))
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	st := daemon.NetworkCryptoState{NetworkID: networkID, TenantID: tenantID, Status: "active", EpochID: epoch.ID}
	if err := db.SaveNetworkCrypto(networkID, st); err != nil {
		t.Fatalf("SaveNetworkCrypto: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return stateDir, epoch.ID
}

func announceNetworkState(t *testing.T, stateDir, networkID, tenantID, status, epochID string) {
	t.Helper()
	db, err := daemon.OpenState(filepath.Join(stateDir, "daemon.sqlite"))
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	defer db.Close()
	st := daemon.NetworkCryptoState{NetworkID: networkID, TenantID: tenantID, Status: status, EpochID: epochID}
	if err := db.SaveNetworkCrypto(networkID, st); err != nil {
		t.Fatalf("SaveNetworkCrypto: %v", err)
	}
}

// TestClientCryptoFailClosed: every not-ready state fails with the clear
// not-ready error — there is no plaintext path.
func TestClientCryptoFailClosed(t *testing.T) {
	const netID = "6f0c1b3e-8d52-4c1a-9f0e-0a1b2c3d4e5f"

	t.Run("no daemon state", func(t *testing.T) {
		c := &cliCtx{stateDir: t.TempDir()}
		_, _, err := c.clientCrypto(netID)
		if !errors.Is(err, ErrClientCryptoNotReady) || !strings.Contains(err.Error(), "no daemon state") {
			t.Fatalf("err = %v, want the not-ready error with the no-daemon-state reason", err)
		}
	})

	t.Run("not announced", func(t *testing.T) {
		dir := t.TempDir()
		db, err := daemon.OpenState(filepath.Join(dir, "daemon.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
		c := &cliCtx{stateDir: dir}
		_, _, err = c.clientCrypto(netID)
		if !errors.Is(err, ErrClientCryptoNotReady) || !strings.Contains(err.Error(), "no announced encryption state") {
			t.Fatalf("err = %v, want the not-ready error with the not-announced reason", err)
		}
	})

	t.Run("still activating", func(t *testing.T) {
		dir := t.TempDir()
		announceNetworkState(t, dir, netID, "tenant-1", "activating", "")
		c := &cliCtx{stateDir: dir}
		_, _, err := c.clientCrypto(netID)
		if !errors.Is(err, ErrClientCryptoNotReady) || !strings.Contains(err.Error(), `network state: "activating"`) {
			t.Fatalf("err = %v, want the not-ready error naming the activating state", err)
		}
	})

	t.Run("keyring missing", func(t *testing.T) {
		dir := t.TempDir()
		announceNetworkState(t, dir, netID, "tenant-1", "active", "epoch-1")
		c := &cliCtx{stateDir: dir}
		_, _, err := c.clientCrypto(netID)
		if !errors.Is(err, ErrClientCryptoNotReady) || !strings.Contains(err.Error(), "keyring not installed") {
			t.Fatalf("err = %v, want the not-ready error with the missing-keyring reason", err)
		}
	})

	t.Run("announced epoch not in keyring", func(t *testing.T) {
		stateDir, _ := activeCryptoHost(t, netID, "tenant-1")
		// Overwrite the announcement with an epoch the keyring does not have.
		announceNetworkState(t, stateDir, netID, "tenant-1", "active", "epoch-other")
		c := &cliCtx{stateDir: stateDir}
		_, _, err := c.clientCrypto(netID)
		if !errors.Is(err, ErrClientCryptoNotReady) || !strings.Contains(err.Error(), "announced key epoch is not in this host's keyring") {
			t.Fatalf("err = %v, want the not-ready error for the unknown announced epoch", err)
		}
	})
}

// TestClientCryptoActiveRoundTrip: an active network encrypts/decrypts
// round-trip, the AAD binds the routing metadata (protocol v2, object type,
// recipient, the UUIDv7 object id as a single clock source), and a tampered
// AAD is rejected.
func TestClientCryptoActiveRoundTrip(t *testing.T) {
	const (
		netID    = "6f0c1b3e-8d52-4c1a-9f0e-0a1b2c3d4e5f"
		tenantID = "tenant-1"
	)
	stateDir, epochID := activeCryptoHost(t, netID, tenantID)
	c := &cliCtx{stateDir: stateDir}

	st, kr, err := c.clientCrypto(netID)
	if err != nil {
		t.Fatalf("clientCrypto: %v", err)
	}
	if st.Status != "active" || st.EpochID != epochID {
		t.Fatalf("state = %+v, want active + epoch %s", st, epochID)
	}

	objectID := newClientObjectID()
	plaintext := `{"text":"hello"}`
	env, aad, err := c.encryptClientContent(st, kr, e2ee.ObjectTypeInvocationInput, objectID, "agent-atlas", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// The AAD contract (V2 content protocol).
	if aad.ProtocolVersion != transport.ProtocolVersion || transport.ProtocolVersion != 2 {
		t.Errorf("AAD.ProtocolVersion = %d, want %d (V2)", aad.ProtocolVersion, transport.ProtocolVersion)
	}
	if aad.TenantID != tenantID || aad.NetworkID != netID {
		t.Errorf("AAD tenant/network = %q/%q, want %q/%q", aad.TenantID, aad.NetworkID, tenantID, netID)
	}
	if aad.ObjectType != e2ee.ObjectTypeInvocationInput {
		t.Errorf("AAD.ObjectType = %q, want %q", aad.ObjectType, e2ee.ObjectTypeInvocationInput)
	}
	if aad.ObjectID != objectID {
		t.Errorf("AAD.ObjectID = %q, want %q", aad.ObjectID, objectID)
	}
	if aad.Sender != "" {
		t.Errorf("AAD.Sender = %q, want \"\" (the CLI acts for the signed-in user)", aad.Sender)
	}
	if aad.Recipient != "agent-atlas" {
		t.Errorf("AAD.Recipient = %q, want agent-atlas", aad.Recipient)
	}
	if aad.KeyEpochID != epochID {
		t.Errorf("AAD.KeyEpochID = %q, want %q", aad.KeyEpochID, epochID)
	}
	// CreatedAt = the object id's embedded UUIDv7 timestamp (one clock).
	u, err := uuid.Parse(objectID)
	if err != nil || u.Version() != 7 {
		t.Fatalf("object id %q is not a UUIDv7", objectID)
	}
	ms := uint64(u[0])<<40 | uint64(u[1])<<32 | uint64(u[2])<<24 |
		uint64(u[3])<<16 | uint64(u[4])<<8 | uint64(u[5])
	wantTS := time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
	if aad.CreatedAt != wantTS {
		t.Errorf("AAD.CreatedAt = %q, want the UUIDv7-derived %q", aad.CreatedAt, wantTS)
	}

	// Round-trip with the announced epoch key.
	epochRec, ok := kr.EpochByID(epochID)
	if !ok {
		t.Fatalf("epoch %s not in keyring", epochID)
	}
	keyArr, err := epochRec.KeyArray()
	if err != nil {
		t.Fatalf("KeyArray: %v", err)
	}
	plain, err := e2ee.Decrypt(env, keyArr, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != plaintext {
		t.Errorf("round-trip = %q, want %q", plain, plaintext)
	}

	// The CLI's own decryptor agrees.
	got, err := c.decryptClientContent(kr, env, aad)
	if err != nil {
		t.Fatalf("decryptClientContent: %v", err)
	}
	if got != plaintext {
		t.Errorf("decryptClientContent = %q, want %q", got, plaintext)
	}

	// AAD binding: tampering with any bound field fails decryption.
	bad := aad
	bad.Recipient = "evil"
	if _, err := e2ee.Decrypt(env, keyArr, bad); err == nil {
		t.Error("decryption succeeded with a tampered AAD (recipient) — AAD binding is broken")
	}
}

// --- event publish fails closed ----------------------------------------------------

func TestEventPublishFailClosed(t *testing.T) {
	ts := newStubV2Server(t, map[string]string{
		"/api/v1/networks": `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
	})
	cliEnv(t, ts.ts)

	cmd := eventCmd()
	cmd.SetArgs([]string{"publish", "build.completed"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if !errors.Is(err, ErrClientCryptoNotReady) {
		t.Fatalf("err = %v, want the clear not-ready error (no plaintext mode)", err)
	}
	if !strings.Contains(err.Error(), "no daemon state") {
		t.Errorf("err = %v, want the no-daemon-state reason", err)
	}
	if ts.hasCall("POST /api/v1/networks/net-1/events") {
		t.Error("an unencrypted event was published")
	}
}

// --- invoke end-to-end (client-side E2EE over REST) ---------------------------------

// TestInvokeEndToEnd: the full `pagnet invoke` path — the input is encrypted
// on this host under the announced epoch (AAD bound to the target), the fake
// server decrypts it, encrypts the result, and the CLI decrypts + prints it.
func TestInvokeEndToEnd(t *testing.T) {
	const (
		netID    = "6f0c1b3e-8d52-4c1a-9f0e-0a1b2c3d4e5f"
		tenantID = "tenant-1"
	)
	// A HOME whose .pagnet dir is the daemon's state dir (the crypto path).
	home := t.TempDir()
	t.Setenv("HOME", home)
	stateDir := filepath.Join(home, ".pagnet")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.ActivateNetwork(stateDir, tenantID, netID, time.Now())
	if err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	key, err := epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	db, err := daemon.OpenState(filepath.Join(stateDir, "daemon.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	st := daemon.NetworkCryptoState{NetworkID: netID, TenantID: tenantID, Status: "active", EpochID: epoch.ID}
	if err := db.SaveNetworkCrypto(netID, st); err != nil {
		t.Fatal(err)
	}
	db.Close()

	type observed struct {
		input  string
		aad    e2ee.AAD
		target string
		capID  string
	}
	var (
		mu      sync.Mutex
		obs     observed
		settled string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/networks":
			fmt.Fprintf(w, `[{"ID":"%s","Name":"default","Slug":"default"}]`, netID)
		case "/api/v1/networks/" + netID + "/agents":
			fmt.Fprint(w, `[{"id":"agent-atlas","name":"atlas","kind":"agent"}]`)
		case "/api/v1/networks/" + netID + "/services":
			fmt.Fprint(w, `[]`)
		case "/api/v1/networks/" + netID + "/invocations":
			var body struct {
				Target   string                  `json:"targetPrincipalId"`
				CapID    string                  `json:"capabilityId"`
				ObjectID string                  `json:"inputObjectID"`
				Envelope e2ee.EncryptedPayloadV1 `json:"envelope"`
				AAD      e2ee.AAD                `json:"aad"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			// The fake network endpoint decrypts the input (it holds the
			// network key, as a service endpoint would).
			plain, err := e2ee.Decrypt(body.Envelope, key, body.AAD)
			if err != nil {
				http.Error(w, "envelope: "+err.Error(), 400)
				return
			}
			outAAD := e2ee.AAD{
				ProtocolVersion: transport.ProtocolVersion,
				TenantID:        tenantID,
				NetworkID:       netID,
				ObjectType:      e2ee.ObjectTypeInvocationOutput,
				ObjectID:        body.ObjectID,
				Sender:          "agent-atlas",
				Recipient:       body.Target,
				CreatedAt:       time.Now().UTC().Format(time.RFC3339),
				KeyEpochID:      epoch.ID,
			}
			resEnv, err := e2ee.Encrypt([]byte(`{"ok":true,"text":"hello"}`), key, outAAD)
			if err != nil {
				http.Error(w, "result: "+err.Error(), 500)
				return
			}
			settled = fmt.Sprintf(`{"id":"inv-1","state":"completed","outputEnvelope":%s,"outputAAD":%s}`,
				mustJSON(t, resEnv), mustJSON(t, outAAD))
			mu.Lock()
			obs = observed{input: string(plain), aad: body.AAD, target: body.Target, capID: body.CapID}
			mu.Unlock()
			fmt.Fprint(w, `{"id":"inv-1","state":"completed"}`)
		case "/api/v1/networks/" + netID + "/invocations/inv-1":
			mu.Lock()
			s := settled
			mu.Unlock()
			fmt.Fprint(w, s)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	prevServer := serverURL
	serverURL = srv.URL
	prevToken := userToken
	userToken = "test-token"
	prevNonInt := nonInteractive
	nonInteractive = true
	prevSilent := silent
	silent = true
	t.Cleanup(func() {
		serverURL = prevServer
		userToken = prevToken
		nonInteractive = prevNonInt
		silent = prevSilent
	})

	inPath := filepath.Join(t.TempDir(), "input.json")
	// Whitespace around the document: the CLI must compact before encrypting.
	if err := os.WriteFile(inPath, []byte("  {\"text\": \"hello there\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := invokeCmd()
	cmd.SetArgs([]string{"atlas", "svc.echo", "--input", inPath})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	mu.Lock()
	gotInput, gotAAD, gotTarget, gotCap := obs.input, obs.aad, obs.target, obs.capID
	mu.Unlock()
	if gotInput != `{"text":"hello there"}` {
		t.Errorf("server-decrypted input = %q, want the compacted input", gotInput)
	}
	if gotTarget != "agent-atlas" || gotCap != "svc.echo" {
		t.Errorf("invocation target/capability = %q/%q, want agent-atlas/svc.echo", gotTarget, gotCap)
	}
	if gotAAD.ObjectType != e2ee.ObjectTypeInvocationInput || gotAAD.Recipient != "agent-atlas" ||
		gotAAD.ProtocolVersion != transport.ProtocolVersion {
		t.Errorf("invocation AAD = %+v, want invocation_input to agent-atlas on protocol v2", gotAAD)
	}
	want := "{\n  \"ok\": true,\n  \"text\": \"hello\"\n}\n"
	if out != want {
		t.Fatalf("invoke output = %q, want the decrypted result %q", out, want)
	}
}

// --- matchPattern (event watch --type) --------------------------------------------

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"build.*", "build.completed", true},
		{"build.*", "build.test.failed", true},
		{"build.*", "other.x", false},
		{"build.completed", "build.completed", true},
		{"build.completed", "build.finished", false},
		{"build.*", "buildX", false}, // the dot is literal
		{"*", "anything", true},
		{"deploy.*", "build.deployed", false},
	}
	for _, tc := range cases {
		ok, err := matchPattern(tc.pattern, tc.s)
		if err != nil {
			t.Errorf("matchPattern(%q, %q) error = %v", tc.pattern, tc.s, err)
			continue
		}
		if ok != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.s, ok, tc.want)
		}
	}
	if _, err := matchPattern("build.[", "x"); err == nil {
		t.Error("an invalid pattern must return an error")
	}
}

// --- test helpers ------------------------------------------------------------------

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
