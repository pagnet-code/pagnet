package main

// The principal-actor invoke path (W10 G0(2)).
//
// The control plane refuses a user actor on POST /networks/{id}/invocations
// (api_invocations.go: "invocations are made by principals (use a principal
// credential)"), so the CLI must be able to present a PRINCIPAL credential
// (pgn_epd_) and act as that agent or service. These tests pin:
//
//   - the principal path presents the endpoint credential on EVERY call and
//     sends the documented body (targetPrincipalId / capabilityId /
//     invocationId / envelope / aad);
//   - the E2EE content path is UNCHANGED — the same client-side envelope +
//     AAD the CLI always built, so the target's SDK decrypts it exactly as
//     before (nothing about the actor changes the crypto);
//   - a user bearer's 400 is translated into product text (no raw JSON);
//   - a credential is proven locally BEFORE any round trip;
//   - the endpoint credential this host already stores is used, and an
//     ambiguous store is a choice the operator must make.

import (
	"encoding/json"
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

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/daemon"
	"github.com/pagnet-code/pagnet/transport"
)

const (
	principalNetID    = "6f0c1b3e-8d52-4c1a-9f0e-0a1b2c3d4e5f"
	principalTenantID = "tenant-1"
)

// testEndpointCred is a well-formed durable endpoint credential: the server's
// positional shape (16-char base64url lookup id, "_", 43-char base64url
// secret) after the pgn_epd_v1_ prefix.
var testEndpointCred = tokenPrefixEndpoint + strings.Repeat("k", 16) + "_" + strings.Repeat("s", 43)

// testActivationCred is the one-time credential of the same shape. It must be
// rejected on this surface: it is consumed by the endpoint's first connect.
var testActivationCred = tokenPrefixPrincipalActivation + strings.Repeat("a", 16) + "_" + strings.Repeat("z", 43)

// callCount counts what reached a fake control plane — the local-validation
// tests only mean something if the answer is zero.
func callCount(t *testing.T, s *stubV2Server) int {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// storeEndpointCredential writes the SDK's stored endpoint credential for one
// principal into the CLI's state dir (the store the SDK maintains itself).
func storeEndpointCredential(t *testing.T, stateDir, principalID, cred string) {
	t.Helper()
	dir := filepath.Join(stateDir, "principals", principalID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credential"), []byte(cred), 0o600); err != nil {
		t.Fatal(err)
	}
}

// principalEnv isolates the CLI for a principal-actor test: HOME owns the
// state dir, no user bearer exists at all (the endpoint credential must be the
// ONLY bearer on this path), and $PAGNET_CREDENTIAL is not implicitly set.
func principalEnv(t *testing.T, ts *httptest.Server, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("PAGNET_CREDENTIAL", "")
	t.Setenv("PAGNET_STATE_DIR", "")
	t.Setenv("PAGNET_TOKEN", "")

	prevServer := serverURL
	serverURL = ts.URL
	prevToken := userToken
	userToken = ""
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

// activePrincipalHost prepares HOME/.pagnet as a host whose network is ACTIVE
// (the daemon's announced state + the installed keyring) and returns the epoch
// key, so a test's fake endpoint can decrypt what the CLI encrypted. (The
// existing activeCryptoHost helper in v2_cli_test.go builds a bare state dir;
// these tests need HOME/.pagnet itself, because the CLI resolves its state dir
// from HOME.)
func activePrincipalHost(t *testing.T, home string) (stateDir, epochID string, key [32]byte) {
	t.Helper()
	stateDir = filepath.Join(home, ".pagnet")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.ActivateNetwork(stateDir, principalTenantID, principalNetID, time.Now())
	if err != nil {
		t.Fatalf("ActivateNetwork: %v", err)
	}
	epoch, err := kr.ActiveEpoch()
	if err != nil {
		t.Fatal(err)
	}
	key, err = epoch.KeyArray()
	if err != nil {
		t.Fatal(err)
	}
	db, err := daemon.OpenState(filepath.Join(stateDir, "daemon.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.SaveNetworkCrypto(principalNetID, daemon.NetworkCryptoState{
		NetworkID: principalNetID, TenantID: principalTenantID, Status: "active", EpochID: epoch.ID,
	}); err != nil {
		t.Fatal(err)
	}
	return stateDir, epoch.ID, key
}

// principalInvokeServer is a fake V2 control plane that behaves like the real
// invocation route: it records every bearer it saw, decrypts the submitted
// envelope with the network key (as the target's endpoint would), and answers
// with an encrypted result the CLI must decrypt.
type principalInvokeServer struct {
	mu      sync.Mutex
	bearers []string
	paths   []string
	// observed request fields (the invocation POST body)
	body    map[string]any
	input   string
	aad     e2ee.AAD
	settled string
	// onInvocation answers the POST; the default completes the invocation.
	onInvocation func(w http.ResponseWriter)
	srv          *httptest.Server
}

// hitPath reports whether one path reached the fake control plane.
func (p *principalInvokeServer) hitPath(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, q := range p.paths {
		if q == path {
			return true
		}
	}
	return false
}

func newPrincipalInvokeServer(t *testing.T, key [32]byte, epochID string) *principalInvokeServer {
	t.Helper()
	p := &principalInvokeServer{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p.mu.Lock()
		p.bearers = append(p.bearers, r.Header.Get("Authorization"))
		p.paths = append(p.paths, r.URL.Path)
		p.mu.Unlock()

		switch r.URL.Path {
		case "/api/v1/networks":
			fmt.Fprintf(w, `[{"ID":"%s","Name":"default","Slug":"default"}]`, principalNetID)
		case "/api/v1/networks/" + principalNetID + "/agents":
			fmt.Fprint(w, `[{"id":"agent-atlas","name":"atlas","kind":"agent"}]`)
		case "/api/v1/networks/" + principalNetID + "/services":
			fmt.Fprint(w, `[]`)
		case "/api/v1/networks/" + principalNetID + "/invocations":
			p.mu.Lock()
			custom := p.onInvocation
			p.mu.Unlock()
			if custom != nil {
				custom(w)
				return
			}
			p.complete(t, w, r, key, epochID)
		case "/api/v1/networks/" + principalNetID + "/invocations/inv-1":
			p.mu.Lock()
			s := p.settled
			p.mu.Unlock()
			fmt.Fprint(w, s)
		default:
			http.Error(w, `{"error":{"code":"not_found","message":"resource not found"}}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// complete is the happy path: decrypt the input, encrypt the result under the
// AAD the caller's target will be given.
func (p *principalInvokeServer) complete(t *testing.T, w http.ResponseWriter, r *http.Request, key [32]byte, epochID string) {
	t.Helper()
	raw, _ := io.ReadAll(r.Body)
	var body struct {
		Target       string                  `json:"targetPrincipalId"`
		CapID        string                  `json:"capabilityId"`
		InvocationID string                  `json:"invocationId"`
		Envelope     e2ee.EncryptedPayloadV1 `json:"envelope"`
		AAD          e2ee.AAD                `json:"aad"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)

	plain, err := e2ee.Decrypt(body.Envelope, key, body.AAD)
	if err != nil {
		// Exactly the control plane's answer for an envelope it cannot open.
		http.Error(w, `{"error":{"code":"bad_request","message":"invalid envelope: `+err.Error()+`"}}`, http.StatusBadRequest)
		return
	}
	outAAD := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        principalTenantID,
		NetworkID:       principalNetID,
		ObjectType:      e2ee.ObjectTypeInvocationOutput,
		ObjectID:        body.InvocationID,
		Sender:          body.Target,
		Recipient:       "caller-principal",
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		KeyEpochID:      epochID,
	}
	resEnv, err := e2ee.Encrypt([]byte(`{"ok":true}`), key, outAAD)
	if err != nil {
		http.Error(w, "result: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.body = generic
	p.input = string(plain)
	p.aad = body.AAD
	p.settled = fmt.Sprintf(`{"id":"inv-1","state":"completed","outputEnvelope":%s,"outputAAD":%s}`,
		mustJSON(t, resEnv), mustJSON(t, outAAD))
	p.mu.Unlock()
	fmt.Fprint(w, `{"id":"inv-1","state":"completed"}`)
}

func (p *principalInvokeServer) observed() (bearers []string, body map[string]any, input string, aad e2ee.AAD) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.bearers))
	copy(out, p.bearers)
	return out, p.body, p.input, p.aad
}

// refuseUserActor answers the invocation POST the way api_invocations.go
// answers a human caller.
func (p *principalInvokeServer) refuseUserActor() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onInvocation = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"code":"bad_request","message":"invocations are made by principals (use a principal credential)"}}`)
	}
}

// TestInvokeAsPrincipalWithCredential: `pagnet invoke --credential
// pgn_epd_...` runs the whole path AS the principal — every call carries that
// bearer (never a human's), the body carries the documented fields, and the
// input is encrypted with the existing client-side construction so the target
// decrypts it and the CLI decrypts the result.
func TestInvokeAsPrincipalWithCredential(t *testing.T) {
	home := t.TempDir()
	stateDir, epochID, key := activePrincipalHost(t, home)
	// The stored credential must NOT be what is used here: --credential wins,
	// and it is a different secret.
	storeEndpointCredential(t, stateDir, "01a0c000-0000-7000-8000-000000000001", "pgn_epd_v1_"+strings.Repeat("d", 16)+"_"+strings.Repeat("d", 43))

	srv := newPrincipalInvokeServer(t, key, epochID)
	principalEnv(t, srv.srv, home)

	inPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inPath, []byte("  {\"text\": \"hello\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := invokeCmd()
	cmd.SetArgs([]string{"atlas", "svc.echo", "--input", inPath, "--credential", testEndpointCred})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("principal invoke: %v", err)
	}
	if want := "{\n  \"ok\": true\n}\n"; out != want {
		t.Fatalf("output = %q, want the decrypted result %q", out, want)
	}

	bearers, body, input, aad := srv.observed()
	if len(bearers) == 0 {
		t.Fatal("the fake control plane saw no requests")
	}
	for i, b := range bearers {
		if b != "Bearer "+testEndpointCred {
			t.Errorf("request %d bearer = %q, want the endpoint credential passed with --credential", i, b)
		}
	}
	// The documented body contract (api_invocations.go handleCreateInvocation).
	if body["targetPrincipalId"] != "agent-atlas" {
		t.Errorf("targetPrincipalId = %v, want agent-atlas", body["targetPrincipalId"])
	}
	if body["capabilityId"] != "svc.echo" {
		t.Errorf("capabilityId = %v, want svc.echo", body["capabilityId"])
	}
	invokeID, _ := body["invocationId"].(string)
	if invokeID == "" {
		t.Error("invocationId is missing: the control plane would mint its own and the AAD would bind a different id")
	}
	if _, ok := body["envelope"]; !ok {
		t.Error("the request carries no envelope")
	}
	if _, ok := body["aad"]; !ok {
		t.Error("the request carries no aad")
	}
	// The E2EE content path is the EXISTING construction, unchanged by the
	// actor: the target decrypts with the relayed AAD, so the AAD the CLI
	// built is the one that must survive the round trip.
	if input != `{"text":"hello"}` {
		t.Errorf("server-decrypted input = %q, want the compacted input", input)
	}
	if aad.ObjectType != e2ee.ObjectTypeInvocationInput || aad.Recipient != "agent-atlas" ||
		aad.ProtocolVersion != transport.ProtocolVersion {
		t.Errorf("invocation AAD = %+v, want invocation_input to agent-atlas on protocol v2", aad)
	}
	if aad.ObjectID != invokeID {
		t.Errorf("AAD.ObjectID = %q, want the invocationId %q", aad.ObjectID, invokeID)
	}
}

// TestInvokeUserBearerGetsProductText: a signed-in user attempting invoke gets
// the server's 400 rendered as product text — no raw JSON body, and the text
// names the credential that works. The call still goes out: the server is the
// authority on who may invoke.
func TestInvokeUserBearerGetsProductText(t *testing.T) {
	home := t.TempDir()
	stateDir, epochID, key := activePrincipalHost(t, home)
	_ = stateDir // no principal credential is stored here
	srv := newPrincipalInvokeServer(t, key, epochID)
	srv.refuseUserActor()

	principalEnv(t, srv.srv, home)
	userToken = "test-token" // the signed-in human's bearer

	cmd := invokeCmd()
	cmd.SetArgs([]string{"atlas", "svc.echo"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil {
		t.Fatal("invoke with a user bearer succeeded; the control plane refuses a user actor")
	}
	msg := err.Error()
	for _, want := range []string{"does not let a signed-in user invoke", tokenPrefixEndpoint, "credential create"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to contain %q", msg, want)
		}
	}
	// No raw server JSON leaked into the human surface.
	for _, gone := range []string{"bad_request", "http 400", "{\"error\""} {
		if strings.Contains(msg, gone) {
			t.Errorf("the raw server body leaked into the product text (%s): %q", gone, msg)
		}
	}
	// The refusal is the server's decision, so the request must have been made.
	if !srv.hitPath("/api/v1/networks/" + principalNetID + "/invocations") {
		t.Error("no invocation request reached the control plane")
	}
}

// TestEndpointCredentialValidatedLocally: a wrong-class or malformed
// credential fails BEFORE any round trip, naming what was handed over and
// never echoing the secret.
func TestEndpointCredentialValidatedLocally(t *testing.T) {
	cases := []struct {
		name string
		give string
		want []string
	}{
		{"account token", testAccountToken, []string{"your Pagnet Token", tokenPrefixEndpoint, "credential create"}},
		{"access token", testAccessToken, []string{"an Access Token", tokenPrefixEndpoint}},
		{"legacy api token", testLegacyToken, []string{"a legacy API token", tokenPrefixEndpoint}},
		{"activation credential", testActivationCred, []string{"one-time activation credential", "endpoint credential"}},
		{"malformed endpoint credential", tokenPrefixEndpoint + "tooshort", []string{"malformed endpoint credential"}},
		{"not a credential at all", "hunter2", []string{"not an agent or service endpoint credential", "credential create"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newStubV2Server(t, map[string]string{})
			cliEnv(t, ts.ts)
			userToken = "test-token"
			t.Setenv("PAGNET_CREDENTIAL", "")

			cmd := invokeCmd()
			cmd.SetArgs([]string{"atlas", "svc.echo", "--credential", tc.give})
			_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
			if err == nil {
				t.Fatalf("a %s was accepted as a principal credential", tc.name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to name %q", err, want)
				}
			}
			if strings.Contains(err.Error(), tc.give) {
				t.Errorf("the error echoes the credential: %v", err)
			}
			if n := callCount(t, ts); n != 0 {
				t.Errorf("%d request(s) reached the control plane with an invalid credential", n)
			}
		})
	}
}

// TestInvokeUsesStoredEndpointCredential: a host that already holds a
// principal's endpoint credential (the SDK stored it) acts as that principal
// without being told. Two of them is a choice the operator must make, and
// --as picks one.
func TestInvokeUsesStoredEndpointCredential(t *testing.T) {
	const (
		principalA = "01a0c000-0000-7000-8000-00000000000a"
		principalB = "01a0c000-0000-7000-8000-00000000000b"
	)
	credA := tokenPrefixEndpoint + strings.Repeat("a", 16) + "_" + strings.Repeat("1", 43)
	credB := tokenPrefixEndpoint + strings.Repeat("b", 16) + "_" + strings.Repeat("2", 43)

	t.Run("the only stored credential is used", func(t *testing.T) {
		home := t.TempDir()
		stateDir, epochID, key := activePrincipalHost(t, home)
		storeEndpointCredential(t, stateDir, principalA, credA)
		srv := newPrincipalInvokeServer(t, key, epochID)
		principalEnv(t, srv.srv, home)

		cmd := invokeCmd()
		cmd.SetArgs([]string{"atlas", "svc.echo"})
		if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
			t.Fatalf("invoke with the stored endpoint credential: %v", err)
		}
		bearers, _, _, _ := srv.observed()
		if len(bearers) == 0 {
			t.Fatal("no request was made")
		}
		for i, b := range bearers {
			if b != "Bearer "+credA {
				t.Errorf("request %d bearer = %q, want the stored endpoint credential", i, b)
			}
		}
	})

	t.Run("two stored credentials are a choice", func(t *testing.T) {
		home := t.TempDir()
		stateDir, epochID, key := activePrincipalHost(t, home)
		storeEndpointCredential(t, stateDir, principalA, credA)
		storeEndpointCredential(t, stateDir, principalB, credB)
		srv := newPrincipalInvokeServer(t, key, epochID)
		principalEnv(t, srv.srv, home)

		cmd := invokeCmd()
		cmd.SetArgs([]string{"atlas", "svc.echo"})
		_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err == nil {
			t.Fatal("an ambiguous principal store was resolved silently")
		}
		for _, want := range []string{"2 agents or services", principalA, principalB, "--as"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to name %q", err, want)
			}
		}
		if srv.hitPath("/api/v1/networks/" + principalNetID + "/invocations") {
			t.Error("an ambiguous store still invoked")
		}

		// --as picks one, and the chosen principal's credential is presented.
		sel := newPrincipalInvokeServer(t, key, epochID)
		principalEnv(t, sel.srv, home)
		cmd = invokeCmd()
		cmd.SetArgs([]string{"atlas", "svc.echo", "--as", principalB})
		if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
			t.Fatalf("invoke --as %s: %v", principalB, err)
		}
		bearers, _, _, _ := sel.observed()
		for i, b := range bearers {
			if b != "Bearer "+credB {
				t.Errorf("request %d bearer = %q, want principal B's credential", i, b)
			}
		}
	})

	t.Run("--as naming an unheld principal fails locally", func(t *testing.T) {
		home := t.TempDir()
		stateDir, epochID, key := activePrincipalHost(t, home)
		storeEndpointCredential(t, stateDir, principalA, credA)
		srv := newPrincipalInvokeServer(t, key, epochID)
		principalEnv(t, srv.srv, home)

		cmd := invokeCmd()
		cmd.SetArgs([]string{"atlas", "svc.echo", "--as", "01a0c000-0000-7000-8000-0000000000ff"})
		_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err == nil || !strings.Contains(err.Error(), "no endpoint credential is stored here") {
			t.Fatalf("error = %v, want the stored-credential miss", err)
		}
		if srv.hitPath("/api/v1/networks/" + principalNetID + "/invocations") {
			t.Error("a --as that matches nothing still made a request")
		}
	})
}

// TestPrincipalCredentialRejectionText: a rejected endpoint credential is
// reported as a dead credential, not as a human who should sign in.
func TestPrincipalCredentialRejectionText(t *testing.T) {
	home := t.TempDir()
	stateDir, epochID, key := activePrincipalHost(t, home)
	storeEndpointCredential(t, stateDir, "01a0c000-0000-7000-8000-00000000000a", testEndpointCred)

	srv := newPrincipalInvokeServer(t, key, epochID)
	srv.mu.Lock()
	srv.onInvocation = func(w http.ResponseWriter) {}
	srv.mu.Unlock()
	// Every call is refused the way the auth middleware refuses a revoked
	// credential.
	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"invalid_credentials","message":"invalid credentials"}}`)
	}))
	t.Cleanup(rejected.Close)
	principalEnv(t, rejected, home)

	cmd := invokeCmd()
	cmd.SetArgs([]string{"atlas", "svc.echo", "--credential", testEndpointCred})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil {
		t.Fatal("a rejected endpoint credential was reported as success")
	}
	msg := err.Error()
	for _, want := range []string{"did not accept this endpoint credential", "revoked"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to contain %q", msg, want)
		}
	}
	// The human-bearer advice is wrong here (a user credential cannot use the
	// route), so it must not appear.
	for _, gone := range []string{"pagnet login", "PAGNET_TOKEN", "http 401"} {
		if strings.Contains(msg, gone) {
			t.Errorf("the human-bearer advice leaked into a principal-actor error (%s): %q", gone, msg)
		}
	}
}
