package main

// Principal-credential command tests (plan §9): the automation contract (no
// prompts, the exact REST body, the right path id per surface), the secret
// contract (create shows it once — including under --silent; list can never
// produce it), name/id resolution with its ambiguity failures, and the
// credential-class error translation on this user-only surface.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fixtures -----------------------------------------------------------------

const (
	// testAgentDefID is the agent DEFINITION id — what /agents/{id}/credentials
	// is addressed by. testServiceID is a service's PRINCIPAL id. The two
	// surfaces deliberately use different id spaces (server 1052f65).
	testAgentDefID = "01900000-0000-7000-8000-0000000000a1"
	testServiceID  = "01900000-0000-7000-8000-0000000000b1"
	testCredID     = "01900000-0000-7000-8000-0000000000c1"
	// testCredSecret is a well-formed durable endpoint credential (the class
	// the SDK presents).
	testCredSecret = "pgn_epd_v1_Qz9Xk2WeRt5Yu8Io_zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUT"
)

// credMembership is the network view both surfaces resolve through: one agent
// (a DEFINITION row, so its id is the definition id) and one service (a
// PRINCIPAL row).
func credMembership() map[string]string {
	return map[string]string{
		"/api/v1/networks":                `[{"ID":"net-1","Name":"default","Slug":"default"}]`,
		"/api/v1/networks/net-1/agents":   fmt.Sprintf(`[{"ID":"%s","PrincipalID":"01900000-0000-7000-8000-0000000000a2","Name":"atlas","Kind":"agent"}]`, testAgentDefID),
		"/api/v1/networks/net-1/services": fmt.Sprintf(`[{"ID":"%s","Name":"docs","Kind":"service"}]`, testServiceID),
	}
}

// credMeta is one metadata row exactly as principalCredentialView renders it.
func credMeta(name string, extra string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"kind":"endpoint","createdAt":"2026-09-20T10:00:00Z",`+
		`"lastUsedAt":"2026-09-20T11:00:00Z","networkIds":["net-1"],"permissions":["discover","invoke"],`+
		`"capabilities":["docs.extract"]%s}`, testCredID, name, extra)
}

// stubCreds is a fake principal-credential control plane keyed by
// "METHOD /path". It records every call and body so a test can assert the
// exact route and request body the CLI produced.
type stubCreds struct {
	ts      *httptest.Server
	mu      sync.Mutex
	calls   []string
	bodies  map[string]string
	respose map[string]string
	status  map[string]int
}

func newStubCreds(t *testing.T, responses map[string]string, statuses map[string]int) *stubCreds {
	t.Helper()
	s := &stubCreds{respose: responses, status: statuses, bodies: map[string]string{}}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		s.mu.Lock()
		s.calls = append(s.calls, key)
		s.bodies[key] = string(body)
		// A fixture key may be method-qualified ("POST /x") or a bare path
		// ("/x", matching any method) — the discovery endpoints answer the
		// same body however they are probed.
		resp, ok := s.respose[key]
		status := s.status[key]
		if !ok {
			resp, ok = s.respose[r.URL.Path]
			if ok {
				status = s.status[r.URL.Path]
			}
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":"not_found","message":"resource not found"}}`)
			return
		}
		switch {
		case status != 0:
			w.WriteHeader(status)
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		}
		fmt.Fprint(w, resp)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *stubCreds) called(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == key {
			return true
		}
	}
	return false
}

func (s *stubCreds) body(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[key]
}

// credResponses wires a stub that answers the whole agent credential surface.
func credResponses(t *testing.T, createBody string) (map[string]string, map[string]int) {
	t.Helper()
	return map[string]string{
		"POST /api/v1/agents/" + testAgentDefID + "/credentials": createBody,
		"GET  /api/v1/agents/" + testAgentDefID + "/credentials": "",
	}, nil
}

// --- automation contract --------------------------------------------------------

// TestCredentialCreateAutomation: every answer is a flag, nothing prompts, and
// the POST body is exactly the server's contract (name / networkIds resolved
// from names / permissions / capabilities / a future RFC3339 expiresAt).
func TestCredentialCreateAutomation(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/agents/"+testAgentDefID+"/credentials"] = credMeta("ci-runner", `,"credential":"`+testCredSecret+`"`)
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)
	jsonOut = true

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", "ci-runner", "--network", "default",
		"--allow", "discover,invoke", "--capability", "docs.extract", "--expires", "30d"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential create: %v\noutput: %s", err, out)
	}

	key := "POST /api/v1/agents/" + testAgentDefID + "/credentials"
	if !s.called(key) {
		t.Fatalf("the CLI never posted the agent credential route; calls: %v", s.calls)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(s.body(key)), &sent); err != nil {
		t.Fatalf("request body is not JSON: %v — %s", err, s.body(key))
	}
	if sent["name"] != "ci-runner" {
		t.Errorf("name = %v, want ci-runner", sent["name"])
	}
	nets, _ := sent["networkIds"].([]any)
	if len(nets) != 1 || nets[0] != "net-1" {
		t.Errorf("networkIds = %v, want the resolved id [net-1] (the flag said \"default\")", sent["networkIds"])
	}
	perms, _ := sent["permissions"].([]any)
	if len(perms) != 2 || perms[0] != "discover" || perms[1] != "invoke" {
		t.Errorf("permissions = %v, want [discover invoke]", sent["permissions"])
	}
	caps, _ := sent["capabilities"].([]any)
	if len(caps) != 1 || caps[0] != "docs.extract" {
		t.Errorf("capabilities = %v, want [docs.extract]", sent["capabilities"])
	}
	exp, _ := sent["expiresAt"].(string)
	tt, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		t.Fatalf("expiresAt = %q, want an RFC3339 timestamp", exp)
	}
	if !tt.After(time.Now()) {
		t.Errorf("expiresAt = %q, want a future time (30d from now)", exp)
	}

	// --json on a successful create carries the raw secret.
	if !strings.Contains(out, testCredSecret) {
		t.Errorf("--json output omitted the secret:\n%s", out)
	}
}

// TestCredentialCreateServiceRoute: `service credential` addresses the
// service's PRINCIPAL id, `agent credential` the DEFINITION id.
func TestCredentialCreateServiceRoute(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/services/"+testServiceID+"/credentials"] = credMeta("ci-runner", `,"credential":"`+testCredSecret+`"`)
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialCreateCmd(principalService)
	cmd.SetArgs([]string{"docs", "--name", "ci-runner"})
	if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
		t.Fatalf("service credential create: %v", err)
	}
	if !s.called("POST /api/v1/services/" + testServiceID + "/credentials") {
		t.Fatalf("wrong route; want the service PRINCIPAL id, calls: %v", s.calls)
	}
}

// --- the secret contract --------------------------------------------------------

// TestCredentialCreateSecretShownOnce: the human path prints the secret and the
// one-time warning.
func TestCredentialCreateSecretShownOnce(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/agents/"+testAgentDefID+"/credentials"] = credMeta("ci-runner", `,"credential":"`+testCredSecret+`"`)
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)
	silent = false

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", "ci-runner"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential create: %v", err)
	}
	for _, want := range []string{testCredSecret, "Shown once. Keep it private.", "ci-runner"} {
		if !strings.Contains(out, want) {
			t.Errorf("output must contain %q:\n%s", want, out)
		}
	}
}

// TestCredentialCreateSilentKeepsSecret: --silent quiets the prose but must NOT
// discard the only copy of the secret (spec §29).
func TestCredentialCreateSilentKeepsSecret(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/agents/"+testAgentDefID+"/credentials"] = credMeta("ci-runner", `,"credential":"`+testCredSecret+`"`)
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)
	silent = true

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", "ci-runner"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential create (--silent): %v", err)
	}
	if !strings.Contains(out, testCredSecret) {
		t.Errorf("--silent discarded the one-time secret:\n%s", out)
	}
	if strings.Contains(out, "capabilities:") {
		t.Errorf("--silent must still suppress the success prose:\n%s", out)
	}
}

// TestCredentialCreateWithoutSecretFails: a create response with no secret is
// an unusable credential, not an empty line to print.
func TestCredentialCreateWithoutSecretFails(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/agents/"+testAgentDefID+"/credentials"] = credMeta("ci-runner", "")
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", "ci-runner"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "returned no secret") {
		t.Fatalf("err = %v, want the 'returned no secret' failure", err)
	}
}

// TestCredentialListNeverReturnsSecret: neither the table nor --json can
// produce the secret — the server does not send it and the shape has no place
// for it.
func TestCredentialListNeverReturnsSecret(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	list := `[` + credMeta("ci-runner", "") + `]`
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] = list
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	for _, asJSON := range []bool{false, true} {
		jsonOut = asJSON
		cmd := credentialListCmd(principalAgent)
		cmd.SetArgs([]string{"atlas"})
		out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
		if err != nil {
			t.Fatalf("credential list (json=%v): %v", asJSON, err)
		}
		if strings.Contains(out, testCredSecret) || strings.Contains(out, "pgn_epd_") {
			t.Errorf("credential list (json=%v) produced a secret:\n%s", asJSON, out)
		}
		if !strings.Contains(out, "ci-runner") {
			t.Errorf("credential list (json=%v) lost the row:\n%s", asJSON, out)
		}
	}
}

// TestCredentialListRendersUnrestrictedAsAll: an empty allowlist is "everything
// the membership already allows", never "nothing".
func TestCredentialListRendersUnrestrictedAsAll(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] =
		`[{"id":"` + testCredID + `","name":"open","kind":"endpoint","createdAt":"2026-09-20T10:00:00Z",` +
			`"networkIds":[],"permissions":[],"capabilities":[]}]`
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"atlas"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential list: %v", err)
	}
	if !strings.Contains(out, "open") || strings.Count(out, "all") < 3 {
		t.Errorf("an unrestricted credential must render as \"all\":\n%s", out)
	}
}

// TestCredentialListShowsRevoked: a revoked row is not presented as active.
func TestCredentialListShowsRevoked(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] =
		`[{"id":"` + testCredID + `","name":"old","kind":"endpoint","createdAt":"2026-09-20T10:00:00Z",` +
			`"revokedAt":"2026-09-20T12:00:00Z","networkIds":[],"permissions":[],"capabilities":[]}]`
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"atlas"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential list: %v", err)
	}
	if !strings.Contains(out, "revoked") {
		t.Errorf("a revoked credential must render as revoked:\n%s", out)
	}
}

// --- revoke ----------------------------------------------------------------------

// TestCredentialRevokeResolvesName: a credential name resolves to its id, and
// the DELETE targets that id.
func TestCredentialRevokeResolvesName(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] = `[` + credMeta("ci-runner", "") + `]`
	res["DELETE /api/v1/agents/"+testAgentDefID+"/credentials/"+testCredID] = ``
	s := newStubCreds(t, res, map[string]int{
		"DELETE /api/v1/agents/" + testAgentDefID + "/credentials/" + testCredID: http.StatusNoContent,
	})
	cliEnv(t, s.ts)

	cmd := credentialRevokeCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "ci-runner"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatalf("credential revoke: %v\n%s", err, out)
	}
	if !s.called("DELETE /api/v1/agents/" + testAgentDefID + "/credentials/" + testCredID) {
		t.Fatalf("revoke did not DELETE the resolved id; calls: %v", s.calls)
	}
	if !strings.Contains(out, "immediately") {
		t.Errorf("revocation must say it is immediate:\n%s", out)
	}
}

// TestCredentialRevokeUnknownCredential: an unknown name fails without
// guessing (and never issues a DELETE).
func TestCredentialRevokeUnknownCredential(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] = `[` + credMeta("ci-runner", "") + `]`
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialRevokeCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "nope"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), `credential "nope" not found`) {
		t.Fatalf("err = %v, want the not-found failure", err)
	}
}

// --- resolution ------------------------------------------------------------------

// TestCredentialUnknownPrincipalNamesIds: an unresolvable name fails with the
// concrete alternative, never a guess.
func TestCredentialUnknownPrincipalNamesIds(t *testing.T) {
	withFileFallback(t)
	s := newStubCreds(t, credMembership(), nil)
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"ghost"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), `no agent named "ghost"`) {
		t.Fatalf("err = %v, want the named not-found failure", err)
	}
	if !strings.Contains(err.Error(), "pass the agent id") {
		t.Errorf("the failure must name the alternative:\n%v", err)
	}
}

// TestCredentialKindMismatch: an agent id never resolves through the service
// surface (and vice versa) — the CLI says so instead of calling the wrong
// route and taking the server's 404.
func TestCredentialKindMismatch(t *testing.T) {
	withFileFallback(t)
	s := newStubCreds(t, credMembership(), nil)
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalService)
	cmd.SetArgs([]string{"atlas"}) // atlas is an agent
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), `no service named "atlas"`) {
		t.Fatalf("err = %v, want the kind-filtered not-found failure", err)
	}
}

// TestCredentialAmbiguousNameFails: two same-named principals of the expected
// kind are reported with their ids, never resolved by a coin flip.
func TestCredentialAmbiguousNameFails(t *testing.T) {
	withFileFallback(t)
	res := map[string]string{
		"/api/v1/networks":                `[{"ID":"net-1","Name":"one","Slug":"one"},{"ID":"net-2","Name":"two","Slug":"two"}]`,
		"/api/v1/networks/net-1/agents":   `[{"ID":"01900000-0000-7000-8000-0000000000d1","Name":"dup","Kind":"agent"}]`,
		"/api/v1/networks/net-2/agents":   `[{"ID":"01900000-0000-7000-8000-0000000000d2","Name":"dup","Kind":"agent"}]`,
		"/api/v1/networks/net-1/services": `[]`,
		"/api/v1/networks/net-2/services": `[]`,
	}
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"dup"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "2 agents are named") {
		t.Fatalf("err = %v, want the ambiguity failure", err)
	}
	for _, want := range []string{"01900000-0000-7000-8000-0000000000d1", "01900000-0000-7000-8000-0000000000d2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the ambiguity error must list %s:\n%v", want, err)
		}
	}
}

// --- validation -------------------------------------------------------------------

func TestCredentialCreateRejectsUnknownPermission(t *testing.T) {
	withFileFallback(t)
	s := newStubCreds(t, credMembership(), nil)
	cliEnv(t, s.ts)

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", "x", "--allow", "discover,teleport"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "unknown permission") {
		t.Fatalf("err = %v, want the permission-vocabulary failure", err)
	}
}

func TestCredentialCreateRejectsLongName(t *testing.T) {
	withFileFallback(t)
	s := newStubCreds(t, credMembership(), nil)
	cliEnv(t, s.ts)

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas", "--name", strings.Repeat("x", maxCredentialNameLen+1)})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "maximum is 64") {
		t.Fatalf("err = %v, want the name-length failure", err)
	}
}

func TestParseExpiry(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
		future bool
	}{
		{"", true, false},
		{"never", true, false},
		{"30d", true, true},
		{"12h", true, true},
		{"2w", true, true},
		{"2027-01-01T00:00:00Z", true, true},
		{"01/01/2027", false, false},
		{"30", false, false},
		{"d30", false, false},
	}
	for _, tc := range cases {
		got, err := parseExpiry(tc.in)
		if tc.wantOK && err != nil {
			t.Errorf("parseExpiry(%q): %v", tc.in, err)
			continue
		}
		if !tc.wantOK {
			if err == nil {
				t.Errorf("parseExpiry(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if !tc.future {
			if got != "" {
				t.Errorf("parseExpiry(%q) = %q, want no expiry", tc.in, got)
			}
			continue
		}
		tt, err := time.Parse(time.RFC3339, got)
		if err != nil {
			t.Errorf("parseExpiry(%q) = %q, not RFC3339: %v", tc.in, got, err)
			continue
		}
		if !tt.After(time.Now()) {
			t.Errorf("parseExpiry(%q) = %q, want a future time", tc.in, got)
		}
	}
}

// --- interactive defaults ----------------------------------------------------------

// TestCredentialCreateInteractiveDefaults: blank answers take the defaults
// (a derived name, no restriction, no expiry) — the interactive path asks only
// what the flags did not answer and never demands an IAM matrix.
func TestCredentialCreateInteractiveDefaults(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	res["POST /api/v1/agents/"+testAgentDefID+"/credentials"] = credMeta("atlas-credential", `,"credential":"`+testCredSecret+`"`)
	s := newStubCreds(t, res, nil)
	cliEnv(t, s.ts)
	nonInteractive = false
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	var asked []string
	prevAsk := askLineFn
	askLineFn = func(prompt string) (string, error) {
		asked = append(asked, prompt)
		return "", nil // every answer blank → the defaults
	}
	t.Cleanup(func() { askLineFn = prevAsk })

	cmd := credentialCreateCmd(principalAgent)
	cmd.SetArgs([]string{"atlas"})
	if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
		t.Fatalf("interactive credential create: %v", err)
	}
	if len(asked) != 5 {
		t.Errorf("expected 5 questions (name/networks/access/capabilities/expires), got %d: %v", len(asked), asked)
	}
	key := "POST /api/v1/agents/" + testAgentDefID + "/credentials"
	var sent map[string]any
	if err := json.Unmarshal([]byte(s.body(key)), &sent); err != nil {
		t.Fatalf("request body not JSON: %s", s.body(key))
	}
	if sent["name"] != "atlas-credential" {
		t.Errorf("name = %v, want the derived default atlas-credential", sent["name"])
	}
	for _, k := range []string{"networkIds", "permissions", "capabilities", "expiresAt"} {
		if _, ok := sent[k]; ok {
			t.Errorf("a blank answer must send no %q (blank = unrestricted, not nothing): %s", k, s.body(key))
		}
	}
}

// --- the credential-class error surface on this route ------------------------------

// TestCredentialPrincipalBearerGetsProductText: the management surface is
// user-only, so a pgn_epd_ bearer answers 403 user_identity_required. That is
// an authorization failure on a valid credential — the human gets the
// explanation, never the JSON body (plan §7).
func TestCredentialPrincipalBearerGetsProductText(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	key := "GET /api/v1/agents/" + testAgentDefID + "/credentials"
	res[key] = `{"error":{"code":"user_identity_required","message":"principal credentials are managed by users, not by credentials"}}`
	s := newStubCreds(t, res, map[string]int{key: http.StatusForbidden})
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"atlas"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil {
		t.Fatal("want the translated authorization failure")
	}
	msg := err.Error()
	if strings.Contains(msg, "user_identity_required") || strings.Contains(msg, "{") {
		t.Errorf("the raw server body leaked to a human: %s", msg)
	}
	for _, want := range []string{"agent or service credential", "Pagnet Token", "Settings → Security → Pagnet Token"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message must contain %q: %s", want, msg)
		}
	}
}

// TestCredentialUnrelatedErrorKeepsServerMessage: a 404 not_found (a wrong-kind
// or foreign id) is information, not a credential problem — it stays as the
// server reported it rather than being rewritten into auth prose.
func TestCredentialUnrelatedErrorKeepsServerMessage(t *testing.T) {
	withFileFallback(t)
	res := credMembership()
	// The id resolves through the membership scan, but the credential route 404s.
	res["GET /api/v1/agents/"+testAgentDefID+"/credentials"] = `{"error":{"code":"not_found","message":"resource not found"}}`
	s := newStubCreds(t, res, map[string]int{"GET /api/v1/agents/" + testAgentDefID + "/credentials": http.StatusNotFound})
	cliEnv(t, s.ts)

	cmd := credentialListCmd(principalAgent)
	cmd.SetArgs([]string{"atlas"})
	_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err == nil {
		t.Fatal("want the 404")
	}
	if !strings.Contains(err.Error(), "http 404") || !strings.Contains(err.Error(), "not_found") {
		t.Errorf("an unrelated failure must keep the server's report: %v", err)
	}
}
