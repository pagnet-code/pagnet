package main

// Client-side tests for the OIDC Device Authorization Grant (p24): the DAG
// client against a stub IdP, the credential storage (0600 file fallback), and
// the no-credentials resume path (a command continues after login).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/99designs/keyring"
)

// --- stubs --------------------------------------------------------------------

// stubIdP is an in-process OIDC IdP for the device flow: it serves the
// device-authorization endpoint and the token endpoint. The token endpoint
// replays pollResponses (each "pending" | "slow_down" | "expired" | "denied" |
// "success") in order, then stays on the last one.
type stubIdP struct {
	mu            sync.Mutex
	ts            *httptest.Server
	pollResponses []string
	pollIdx       int
}

func newStubIdP(t *testing.T, pollResponses []string) *stubIdP {
	t.Helper()
	m := &stubIdP{pollResponses: pollResponses}
	m.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device/auth":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"%s/verify","verification_uri_complete":"%s/verify?user_code=ABCD-1234","expires_in":300,"interval":1}`,
				m.ts.URL, m.ts.URL)
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			// Replay the sequence in order; once exhausted, stay on the last
			// response (so a second flow against the same IdP still succeeds).
			resp := "pending"
			if len(m.pollResponses) > 0 {
				if m.pollIdx < len(m.pollResponses) {
					resp = m.pollResponses[m.pollIdx]
					m.pollIdx++
				} else {
					resp = m.pollResponses[len(m.pollResponses)-1]
				}
			}
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			switch resp {
			case "success":
				// A well-formed (unsecured) ID token: the stub control plane
				// accepts any non-empty id_token.
				fmt.Fprint(w, `{"access_token":"at","token_type":"Bearer","expires_in":300,"id_token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEifQ."}`)
			case "expired":
				http.Error(w, `{"error":"expired_token"}`, http.StatusBadRequest)
			case "denied":
				http.Error(w, `{"error":"access_denied"}`, http.StatusBadRequest)
			case "slow_down":
				http.Error(w, `{"error":"slow_down"}`, http.StatusBadRequest)
			default:
				http.Error(w, `{"error":"authorization_pending"}`, http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.ts.Close)
	return m
}

// stubPagnetServer is an in-process control plane for the device flow: it
// reports oidc mode, serves device-config (pointing at the IdP), and exchanges
// any non-empty id_token for a pagt_ token.
func stubPagnetServer(t *testing.T, idp *stubIdP) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/setup/status":
			fmt.Fprint(w, `{"mode":"oidc","setupRequired":false}`)
		case "/api/v1/auth/oidc/device-config":
			fmt.Fprintf(w, `{"issuer":"%s","deviceAuthorizationEndpoint":"%s/device/auth","tokenEndpoint":"%s/token","clientId":"pagnet-client","scope":"openid profile email"}`,
				idp.ts.URL, idp.ts.URL, idp.ts.URL)
		case "/api/v1/auth/oidc/device/token":
			var body struct {
				IDToken string `json:"idToken"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IDToken == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"code":"bad_request","message":"idToken required"}}`)
				return
			}
			fmt.Fprint(w, `{"token":"pagt_testtoken123","user":{"id":"u1","username":"user-1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// withFileFallback forces the 0600-file credential store (no system keyring in
// tests) and restores the real opener on cleanup.
func withFileFallback(t *testing.T) {
	t.Helper()
	prev := openKeyringFn
	openKeyringFn = func() (keyring.Keyring, error) {
		return nil, fmt.Errorf("no keyring in tests")
	}
	t.Cleanup(func() { openKeyringFn = prev })
}

// --- tests --------------------------------------------------------------------

func TestLoginOIDCDeviceFlow(t *testing.T) {
	idp := newStubIdP(t, []string{"pending", "slow_down", "success"})
	ts := stubPagnetServer(t, idp)
	base := ts.URL + "/"

	// Suppress the browser-open (headless test).
	prev := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	token, err := loginOIDCDeviceFlow(base, false)
	if err != nil {
		t.Fatalf("device flow: %v", err)
	}
	if token != "pagt_testtoken123" {
		t.Fatalf("token = %q, want pagt_testtoken123", token)
	}
	// The IdP saw the full pending -> slow_down -> success sequence.
	idp.mu.Lock()
	got := idp.pollIdx
	idp.mu.Unlock()
	if got != 3 {
		t.Errorf("polls = %d, want 3 (pending, slow_down, success)", got)
	}
}

func TestLoginOIDCDeviceFlowExpired(t *testing.T) {
	idp := newStubIdP(t, []string{"expired"})
	ts := stubPagnetServer(t, idp)
	base := ts.URL + "/"

	prev := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	_, err := loginOIDCDeviceFlow(base, true)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired_token error = %v, want a clean 'expired' message", err)
	}
}

func TestLoginOIDCDeviceFlowNoBrowser(t *testing.T) {
	idp := newStubIdP(t, []string{"success"})
	ts := stubPagnetServer(t, idp)
	base := ts.URL + "/"

	// PAGNET_NO_BROWSER=1 must suppress the browser-open attempt.
	t.Setenv("PAGNET_NO_BROWSER", "1")
	called := false
	prev := openBrowserFn
	openBrowserFn = func(string) error { called = true; return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	if _, err := loginOIDCDeviceFlow(base, false); err != nil {
		t.Fatalf("device flow: %v", err)
	}
	if called {
		t.Error("browser was opened despite PAGNET_NO_BROWSER=1")
	}

	// Without the env var (and no --no-browser), the browser-open is attempted.
	called = false
	os.Unsetenv("PAGNET_NO_BROWSER")
	if _, err := loginOIDCDeviceFlow(base, false); err != nil {
		t.Fatalf("device flow: %v", err)
	}
	if !called {
		t.Error("browser was not opened when PAGNET_NO_BROWSER is unset")
	}
}

func TestSaveLoadUserTokenFileFallback(t *testing.T) {
	withFileFallback(t)
	dir := t.TempDir()
	server := "https://control.example/"

	if err := saveUserToken(dir, server, "pagt_secret123"); err != nil {
		t.Fatalf("save: %v", err)
	}
	// The token round-trips through the file store.
	if got := loadUserToken(dir, server); got != "pagt_secret123" {
		t.Fatalf("load = %q, want pagt_secret123", got)
	}
	// The state file is 0600.
	info, err := os.Stat(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("stat config.yaml: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config.yaml perms = %o, want 0600", perm)
	}
	// The server URL (non-secret) is kept in the file.
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if !strings.Contains(string(b), "control.example") {
		t.Errorf("serverUrl not persisted: %s", b)
	}
}

// TestEnsureUserTokenResume covers the no-credentials resume path: an
// authenticated command with no stored token (oidc mode, interactive) runs the
// device flow once, stores the token, and continues with it.
func TestEnsureUserTokenResume(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := stubPagnetServer(t, idp)
	base := ts.URL + "/"

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })
	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })

	dir := t.TempDir()
	c := &cliCtx{base: base, stateDir: dir, token: ""}
	if err := ensureUserToken(c); err != nil {
		t.Fatalf("ensureUserToken: %v", err)
	}
	if c.token != "pagt_testtoken123" {
		t.Fatalf("c.token = %q, want the minted token", c.token)
	}
	// The token was stored for the next run (no re-login needed).
	if got := loadUserToken(dir, base); got != "pagt_testtoken123" {
		t.Fatalf("stored token = %q, want pagt_testtoken123", got)
	}
}

// TestEnsureUserTokenNoTTY: without an interactive terminal the resume path
// fails with a clear error instead of looping.
func TestEnsureUserTokenNoTTY(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := stubPagnetServer(t, idp)
	base := ts.URL + "/"

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return false }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	c := &cliCtx{base: base, stateDir: t.TempDir(), token: ""}
	err := ensureUserToken(c)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("no-TTY error = %v, want a clear 'interactive terminal' message", err)
	}
	if c.token != "" {
		t.Fatalf("token should be empty after a no-TTY failure, got %q", c.token)
	}
}

// TestEnsureUserTokenNonOIDC: in a non-oidc mode the resume path is a no-op
// (the command keeps its existing 401 behavior).
func TestEnsureUserTokenNonOIDC(t *testing.T) {
	withFileFallback(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/auth/setup/status" {
			fmt.Fprint(w, `{"mode":"token","setupRequired":false}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	c := &cliCtx{base: ts.URL + "/", stateDir: t.TempDir(), token: ""}
	if err := ensureUserToken(c); err != nil {
		t.Fatalf("ensureUserToken in token mode: %v", err)
	}
	if c.token != "" {
		t.Fatalf("token should stay empty in non-oidc mode, got %q", c.token)
	}
}
