package main

// Client-side tests for the sign-in flow (p24 device grant + PKCE), the
// credential storage (0600 file fallback), the shared ensureUserToken
// contract (stored-token validation, mode dispatch, non-interactive
// never-hang), and the first-run self-enrollment path.

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

	"github.com/99designs/keyring"

	"github.com/pagnet-code/pagnet/internal/config"
)

// testDeviceCredential is the account-session client credential the stub
// control plane mints for the OIDC device flow (pgn_pat_v1_ prefix, as the
// real server does for every normal human sign-in).
const testDeviceCredential = "pgn_pat_v1_D3v1c3L00k1d1d_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI"

// --- stubs --------------------------------------------------------------------

// stubIdP is an in-process OIDC IdP for the device flow: it serves the
// device-authorization endpoint and the token endpoint. The token endpoint
// replays pollResponses (each "pending" | "slow_down" | "expired" | "denied" |
// "success") in order, then stays on the last one. It also observes PKCE
// (RFC 9126): the challenge the device-authorization request carried, and how
// many token polls presented a code_verifier whose S256 challenge matches.
type stubIdP struct {
	mu            sync.Mutex
	ts            *httptest.Server
	pollResponses []string
	pollIdx       int

	// PKCE observation (set by the handlers, read by the tests).
	pkceChallenge  string
	pkceMethod     string
	pkcePollsOK    int
	pkcePollsTotal int
}

func newStubIdP(t *testing.T, pollResponses []string) *stubIdP {
	t.Helper()
	m := &stubIdP{pollResponses: pollResponses}
	m.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device/auth":
			_ = r.ParseForm()
			m.mu.Lock()
			m.pkceChallenge = r.PostForm.Get("code_challenge")
			m.pkceMethod = r.PostForm.Get("code_challenge_method")
			m.mu.Unlock()
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
			// PKCE: count polls whose code_verifier matches the challenge.
			m.pkcePollsTotal++
			if v := r.PostForm.Get("code_verifier"); v != "" && pkceChallenge(v) == m.pkceChallenge {
				m.pkcePollsOK++
			}
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

// stubPagnetServer is an in-process control plane for the sign-in flow: it
// reports the auth mode, serves device-config (pointing at the IdP), validates
// bearers against /auth/me and the API endpoints, exchanges any non-empty
// id_token for the account-session client credential, and (for the
// self-enroll test) mints + consumes a one-time enrollment token.
type stubPagnetServer struct {
	URL  string
	mode string

	mu                sync.Mutex
	deviceConfigCalls int
	// validTokens are the bearers /auth/me and the API endpoints accept.
	validTokens map[string]bool
	// mintedEnrollToken is what /hosts/enrollment-tokens returns.
	mintedEnrollToken string
	enrollCalls       int
}

func newStubPagnetServer(t *testing.T, idp *stubIdP, mode string, validTokens ...string) *stubPagnetServer {
	t.Helper()
	s := &stubPagnetServer{mode: mode, validTokens: map[string]bool{}, mintedEnrollToken: "paget_enroll_1"}
	for _, tok := range validTokens {
		s.validTokens[tok] = true
	}
	valid := func(r *http.Request) bool {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.validTokens[tok]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			if valid(r) {
				fmt.Fprint(w, `{"kind":"user","isAdmin":true}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"authentication required"}}`)
		case "/api/v1/auth/setup/status":
			fmt.Fprintf(w, `{"mode":"%s","setupRequired":false}`, s.mode)
		case "/api/v1/auth/oidc/device-config":
			s.mu.Lock()
			s.deviceConfigCalls++
			s.mu.Unlock()
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
			fmt.Fprintf(w, `{"credential":"%s","user":{"id":"u1","username":"user-1"},"role":"admin","networkScope":"all"}`,
				testDeviceCredential)
		case "/" + tokenExchangePath:
			// The paste-login exchange: a pasted root token is exchanged once
			// for the account-session client credential.
			fmt.Fprintf(w, `{"credential":"%s","role":"admin","networkScope":"all"}`, testDeviceCredential)
		case "/api/v1/hosts/enrollment-tokens":
			if !valid(r) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"authentication required"}}`)
				return
			}
			s.mu.Lock()
			s.enrollCalls++
			s.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":"%s","expiresIn":900}`, s.mintedEnrollToken)
		case "/api/v1/hosts/enroll":
			var body struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token != s.mintedEnrollToken {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"code":"bad_request","message":"token required"}}`)
				return
			}
			fmt.Fprint(w, `{"host":{"ID":"h1"},"credential":"hostcred123","allowedRoots":[],"rootsMode":"allow_all"}`)
		default:
			// Any other /api/v1/... endpoint: authenticated, returns [].
			if strings.HasPrefix(r.URL.Path, "/api/v1/") {
				if valid(r) {
					fmt.Fprint(w, `[]`)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"authentication required"}}`)
				return
			}
			http.NotFound(w, r)
		}
	}))
	s.URL = srv.URL
	t.Cleanup(srv.Close)
	return s
}

func (s *stubPagnetServer) deviceConfigCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceConfigCalls
}

func (s *stubPagnetServer) enrollCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrollCalls
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

// --- device flow (PKCE) -------------------------------------------------------

func TestLoginOIDCDeviceFlow(t *testing.T) {
	idp := newStubIdP(t, []string{"pending", "slow_down", "success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	// Suppress the browser-open (headless test).
	prev := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	cred, err := loginOIDCDeviceFlow(base, false)
	if err != nil {
		t.Fatalf("device flow: %v", err)
	}
	if cred.credential != testDeviceCredential {
		t.Fatalf("credential = %q, want the minted account-session credential", cred.credential)
	}
	// The server-reported restriction metadata is carried through.
	if cred.role != "admin" || cred.networkScope != "all" {
		t.Errorf("metadata = %q/%q, want admin/all", cred.role, cred.networkScope)
	}
	// The IdP saw the full pending -> slow_down -> success sequence.
	idp.mu.Lock()
	got := idp.pollIdx
	idp.mu.Unlock()
	if got != 3 {
		t.Errorf("polls = %d, want 3 (pending, slow_down, success)", got)
	}
	// PKCE (RFC 9126): the device-authorization request carried an S256
	// challenge, and every token poll carried the matching code_verifier.
	idp.mu.Lock()
	method, challenge, pollsOK, pollsTotal := idp.pkceMethod, idp.pkceChallenge, idp.pkcePollsOK, idp.pkcePollsTotal
	idp.mu.Unlock()
	if method != "S256" || challenge == "" {
		t.Errorf("device-authorization request: method=%q challenge=%q, want S256 + a non-empty challenge", method, challenge)
	}
	if pollsOK != pollsTotal || pollsTotal != 3 {
		t.Errorf("PKCE polls: %d/%d consistent with the challenge, want 3/3", pollsOK, pollsTotal)
	}
}

func TestLoginOIDCDeviceFlowExpired(t *testing.T) {
	idp := newStubIdP(t, []string{"expired"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
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
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
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

// --- local mode: password → account-session credential -------------------------

// stubLoginServer is a fake control plane for the password flow: it serves
// /auth/login (recording the request body, setting the session cookies, and
// returning the minted credential) and /auth/logout (counting hits).
type stubLoginServer struct {
	ts *httptest.Server

	mu         sync.Mutex
	loginBody  string
	logoutHits int
	loginCred  string // credential in the login response ("" = none)
}

func newStubLoginServer(t *testing.T, cred string) *stubLoginServer {
	t.Helper()
	s := &stubLoginServer{loginCred: cred}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/login":
			b, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.loginBody = string(b)
			cred := s.loginCred
			s.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "pagnet_session", Value: "sess-1"})
			http.SetCookie(w, &http.Cookie{Name: "pagnet_csrf", Value: "csrf-1"})
			fmt.Fprintf(w, `{"user":{"id":"u1","username":"user-1"},"credential":"%s"}`, cred)
		case "/api/v1/auth/logout":
			s.mu.Lock()
			s.logoutHits++
			s.mu.Unlock()
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *stubLoginServer) loginRequestBody() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginBody
}

func (s *stubLoginServer) logoutHitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logoutHits
}

// TestLoginLocalAPIToken: the password flow sends cli:true, the server mints
// the account-session credential in the login response, the CLI logs out the
// carrier session, and returns the credential.
func TestLoginLocalAPIToken(t *testing.T) {
	srv := newStubLoginServer(t, testDeviceCredential)

	cred, err := loginLocalAPIToken(srv.ts.Client(), srv.ts.URL+"/", "user-1", "hunter2")
	if err != nil {
		t.Fatalf("loginLocalAPIToken: %v", err)
	}
	if cred != testDeviceCredential {
		t.Fatalf("credential = %q, want the minted account-session credential", cred)
	}
	// The request carried username/password and the cli:true flag (the server
	// mints the credential in the login response when cli is set).
	var sent map[string]any
	if err := json.Unmarshal([]byte(srv.loginRequestBody()), &sent); err != nil {
		t.Fatalf("login body not JSON: %v", err)
	}
	if sent["username"] != "user-1" || sent["password"] != "hunter2" {
		t.Errorf("login body = %v, want username/password", sent)
	}
	if sent["cli"] != true {
		t.Errorf("login body cli = %v, want true", sent)
	}
	// The carrier session was logged out (not left alive).
	if n := srv.logoutHitCount(); n != 1 {
		t.Errorf("logout hits = %d, want 1 (the carrier session must not be left alive)", n)
	}
}

// TestLoginLocalAPITokenNoCredential: a login response without the credential
// (or with the wrong prefix) fails cleanly — nothing is returned.
func TestLoginLocalAPITokenNoCredential(t *testing.T) {
	// No credential at all.
	srv := newStubLoginServer(t, "")
	if _, err := loginLocalAPIToken(srv.ts.Client(), srv.ts.URL+"/", "user-1", "hunter2"); err == nil {
		t.Fatal("want a clean failure when the login response has no credential")
	}

	// A credential with the wrong prefix (not the account-session class).
	srv = newStubLoginServer(t, "pagt_wrongprefix123")
	if _, err := loginLocalAPIToken(srv.ts.Client(), srv.ts.URL+"/", "user-1", "hunter2"); err == nil {
		t.Fatal("want a clean failure when the credential has the wrong prefix")
	}
}

// --- credential storage -------------------------------------------------------

func TestSaveLoadUserTokenFileFallback(t *testing.T) {
	withFileFallback(t)
	dir := t.TempDir()
	server := "https://control.example/"

	if err := saveUserToken(dir, "", server, testDeviceCredential); err != nil {
		t.Fatalf("save: %v", err)
	}
	// The token round-trips through the file store.
	if got := loadUserToken(dir, "", server); got != testDeviceCredential {
		t.Fatalf("load = %q, want the stored credential", got)
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

// --- ensureUserToken contract -------------------------------------------------

// TestEnsureUserTokenNoStoredTokenOIDC: no stored token + oidc mode → the
// sign-in flow runs, the token is stored, and it is returned.
func TestEnsureUserTokenNoStoredTokenOIDC(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })

	dir := t.TempDir()
	tok, err := ensureUserToken(dir, "", base, false, true)
	if err != nil {
		t.Fatalf("ensureUserToken: %v", err)
	}
	if tok != testDeviceCredential {
		t.Fatalf("token = %q, want the minted credential", tok)
	}
	// The token was stored for the next run (no re-login needed).
	if got := loadUserToken(dir, "", base); got != testDeviceCredential {
		t.Fatalf("stored token = %q, want the minted credential", got)
	}
}

// TestEnsureUserTokenStoredValid: a stored token that validates → returned as
// is, with NO sign-in flow (the stub saw zero device-config calls).
func TestEnsureUserTokenStoredValid(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	dir := t.TempDir()
	if err := saveUserToken(dir, "", base, testDeviceCredential); err != nil {
		t.Fatalf("save: %v", err)
	}
	tok, err := ensureUserToken(dir, "", base, false, true)
	if err != nil {
		t.Fatalf("ensureUserToken: %v", err)
	}
	if tok != testDeviceCredential {
		t.Fatalf("token = %q, want the stored token", tok)
	}
	if n := ts.deviceConfigCallCount(); n != 0 {
		t.Errorf("device-config calls = %d, want 0 (the stored token is valid)", n)
	}
}

// TestEnsureUserTokenStored401Reauth: a stored token that the server rejects
// (revoked) → the sign-in flow runs once, the new token is stored, and the
// original call is retried once with it (the one-shot 401 recovery in do()).
func TestEnsureUserTokenStored401Reauth(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })

	dir := t.TempDir()
	// A stored credential the server no longer accepts.
	if err := saveUserToken(dir, "", base, "pgn_pat_v1_r3v0k3dCred1d_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI"); err != nil {
		t.Fatalf("save: %v", err)
	}
	// The cliCtx base has NO trailing slash (as newCLI builds it); the
	// reauth path must still reach the sign-in flow.
	c := &cliCtx{
		base:        ts.URL,
		stateDir:    dir,
		token:       "pgn_pat_v1_r3v0k3dCred1d_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI",
		reauth:      true,
		noBrowser:   false,
		interactive: true,
	}
	var out []string
	if err := c.get("/api/v1/hosts", &out); err != nil {
		t.Fatalf("get after reauth: %v", err)
	}
	// The sign-in flow ran exactly once (one device-config fetch).
	if n := ts.deviceConfigCallCount(); n != 1 {
		t.Errorf("device-config calls = %d, want 1 (re-login once)", n)
	}
	// The new credential replaced the revoked one in the store.
	if got := loadUserToken(dir, "", base); got != testDeviceCredential {
		t.Fatalf("stored token = %q, want the minted credential", got)
	}
}

// TestEnsureUserTokenTokenMode: token mode with no token → the exact error
// (the admin token cannot be minted by a flow), and no browser call.
func TestEnsureUserTokenTokenMode(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "token")
	base := ts.URL + "/"

	browserCalled := false
	prev := openBrowserFn
	openBrowserFn = func(string) error { browserCalled = true; return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	_, err := ensureUserToken(t.TempDir(), "", base, false, true)
	if err == nil || !strings.Contains(err.Error(), "token mode") {
		t.Fatalf("token-mode error = %v, want the exact 'token mode' message", err)
	}
	if browserCalled {
		t.Error("browser was opened in token mode")
	}
	if n := ts.deviceConfigCallCount(); n != 0 {
		t.Errorf("device-config calls = %d, want 0 in token mode", n)
	}
}

// TestEnsureUserTokenNoTTY: non-interactive (no TTY), no token, no
// --no-browser → a clean error, no hang, no flow started.
func TestEnsureUserTokenNoTTY(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	_, err := ensureUserToken(t.TempDir(), "", base, false, false)
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("no-TTY error = %v, want a clear 'interactive terminal' message", err)
	}
	// No flow was started.
	if n := ts.deviceConfigCallCount(); n != 0 {
		t.Errorf("device-config calls = %d, want 0 (non-interactive, no --no-browser)", n)
	}
}

// TestEnsureUserTokenNoBrowserHeadless: non-interactive WITH --no-browser →
// the deliberate headless case: the flow runs (prints the URL, polls) and
// returns the token.
func TestEnsureUserTokenNoBrowserHeadless(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)
	base := ts.URL + "/"

	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })

	dir := t.TempDir()
	tok, err := ensureUserToken(dir, "", base, true, false)
	if err != nil {
		t.Fatalf("ensureUserToken (headless --no-browser): %v", err)
	}
	if tok != testDeviceCredential {
		t.Fatalf("token = %q, want the minted credential", tok)
	}
}

// --- first-run self-enrollment ------------------------------------------------

// TestEnrollWithoutToken: `pagnet enroll` without --token against the stub:
// sign-in flow → mint a one-time enrollment token → host registered.
func TestEnrollWithoutToken(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)

	// The state file's serverUrl must win the config load (env wins over
	// file; an ambient PAGNET_SERVER would shadow it).
	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	// The --token short-circuit supplies the user bearer (no browser, no
	// paste); the pasted root is exchanged once and the flow still mints +
	// consumes the enrollment token.
	prevToken := userToken
	userToken = testAccountToken
	t.Cleanup(func() { userToken = prevToken })

	dir := t.TempDir()
	if err := enrollHostForeground(dir, "", "test-host", nil, ""); err != nil {
		t.Fatalf("enrollHostForeground: %v", err)
	}
	// The minted enrollment token was consumed exactly once.
	if n := ts.enrollCallCount(); n != 1 {
		t.Errorf("enroll calls = %d, want 1", n)
	}
	// The host credential + identity + server URL are stored.
	cfg, err := config.LoadDaemon(dir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Credential != "hostcred123" {
		t.Errorf("credential = %q, want hostcred123", cfg.Credential)
	}
	if cfg.HostID != "h1" {
		t.Errorf("hostId = %q, want h1", cfg.HostID)
	}
	if cfg.ServerURL != ts.URL {
		t.Errorf("serverUrl = %q, want %q", cfg.ServerURL, ts.URL)
	}
	// The user credential from the sign-in flow was stored too.
	if got := loadUserToken(dir, "", ts.URL+"/"); got != testDeviceCredential {
		t.Errorf("stored user token = %q, want the minted credential", got)
	}
}

// TestNewCLITokenShortCircuit: --token / $PAGNET_TOKEN short-circuits the
// sign-in flow with zero device-endpoint calls.
func TestNewCLITokenShortCircuit(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", testDeviceCredential)

	prevServer := serverURL
	serverURL = ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = testDeviceCredential
	t.Cleanup(func() { userToken = prevToken })

	c, err := newCLI(t.TempDir())
	if err != nil {
		t.Fatalf("newCLI: %v", err)
	}
	if c.token != testDeviceCredential {
		t.Fatalf("c.token = %q, want the --token value", c.token)
	}
	// The short-circuit: zero device-endpoint calls.
	if n := ts.deviceConfigCallCount(); n != 0 {
		t.Errorf("device-config calls = %d, want 0 (--token short-circuits the flow)", n)
	}
}

// --- first-run hardening: the "/" error must have no producer ---------------

// An empty base must produce the clean "no control plane URL" error, never
// the banned "cannot reach the control plane at /" string. The guard lives
// INSIDE ensureUserToken so a future caller passing an empty base cannot
// reintroduce it.
func TestEnsureUserTokenEmptyBase(t *testing.T) {
	_, err := ensureUserToken(t.TempDir(), "", "", false, false)
	if err == nil {
		t.Fatal("expected an error for an empty base")
	}
	if strings.Contains(err.Error(), "control plane at /") {
		t.Fatalf("the forbidden '/' error has a producer again: %v", err)
	}
	if !strings.Contains(err.Error(), "no control plane URL") {
		t.Fatalf("err = %v, want the clean missing-URL error", err)
	}
}

func TestStoredServerURL(t *testing.T) {
	// An ambient PAGNET_SERVER would shadow the state file in LoadDaemon.
	t.Setenv("PAGNET_SERVER", "")
	dir := t.TempDir()
	if got := storedServerURL(dir); got != "" {
		t.Fatalf("empty state dir: storedServerURL = %q, want \"\"", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("serverUrl: http://127.0.0.1:19999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := storedServerURL(dir); got != "http://127.0.0.1:19999" {
		t.Fatalf("storedServerURL = %q, want the state config value", got)
	}
}
