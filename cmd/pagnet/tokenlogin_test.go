package main

// Unit tests for AUTH-3 (token-first paste login + derived client
// credential): local format validation with no server round-trip, the
// one-shot exchange against a fake control plane (net/http/httptest only),
// the storage contract (derived credential stored, root token never,
// metadata overwritten on re-login, 0600), rejection of the removed legacy
// pagt_ class, generic rejection handling, and the never-hang
// non-interactive prompt.

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

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// --- fixtures -----------------------------------------------------------------

const (
	// Well-formed test credentials: <16-char base64url lookup>_<43-char
	// base64url secret (256 bits)> per governance §7-8.
	testAccountToken = "pgn_acc_v1_K4T9M7QZaB1c3d5f_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	testAccessToken  = "pgn_pat_v1_Qz9Xk2WeRt5Yu8Io_zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUT"
	testLegacyToken  = "pagt_testtoken123"
	testDerivedCred  = "pgn_cli_v1_D3r1v3dL00k1d_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI"
)

// stubTokenServer is a fake control plane for the paste-login tests: it
// serves the exchange endpoint and /auth/me, counts hits per route, and
// records the last exchange request body.
type stubTokenServer struct {
	ts *httptest.Server

	mu           sync.Mutex
	exchangeHits int
	meHits       int
	lastExBody   string

	exchangeStatus int    // 0 → 200
	exchangeBody   string // response body on 200
	validBearer    string // bearer /auth/me accepts
}

func newStubTokenServer(t *testing.T) *stubTokenServer {
	t.Helper()
	s := &stubTokenServer{}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/" + tokenExchangePath:
			buf, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.exchangeHits++
			s.lastExBody = string(buf)
			status, respBody := s.exchangeStatus, s.exchangeBody
			s.mu.Unlock()
			if status != 0 && status != http.StatusOK {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"invalid credentials"}}`)
				return
			}
			fmt.Fprint(w, respBody)
		case "/api/v1/auth/me":
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			s.mu.Lock()
			s.meHits++
			valid := s.validBearer
			s.mu.Unlock()
			if tok == valid {
				fmt.Fprint(w, `{"kind":"user","isAdmin":true}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"authentication required"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *stubTokenServer) setExchange(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchangeStatus, s.exchangeBody = status, body
}

func (s *stubTokenServer) setValidBearer(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validBearer = tok
}

func (s *stubTokenServer) hits() (exchange, me int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exchangeHits, s.meHits
}

func (s *stubTokenServer) lastExchangeBody() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastExBody
}

// stateFile reads the test state dir's config.yaml as a generic map.
func stateFile(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	var fc map[string]any
	if err := yaml.Unmarshal(b, &fc); err != nil {
		t.Fatalf("parse config.yaml: %v", err)
	}
	return fc
}

// --- local format validation ----------------------------------------------------

func TestParsePagnetTokenFormat(t *testing.T) {
	cases := []struct {
		name, in, wantKind, wantErrFragment string
	}{
		{"account", testAccountToken, credentialKindAccount, ""},
		{"access", testAccessToken, credentialKindAccess, ""},
		// The legacy pagt_ class is no longer a Pagnet Token: it is rejected
		// as an unknown format (no server round-trip).
		{"legacy prefix rejected", testLegacyToken, "", "unrecognized Pagnet Token"},
		{"wrong prefix", "pgn_api_v1_K4T9M7QZaB1c3d5f_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "", "unrecognized Pagnet Token"},
		{"no prefix", "hunter2", "", "unrecognized Pagnet Token"},
		{"empty", "", "", "unrecognized Pagnet Token"},
		{"account missing secret", "pgn_acc_v1_K4T9M7QZaB1c3d5f", "", "malformed Account Token"},
		{"account short secret", "pgn_acc_v1_K4T9M7QZaB1c3d5f_short", "", "malformed Account Token"},
		{"access no separator", "pgn_pat_v1_K4T9M7QZaB1c3d5f", "", "malformed Access Token"},
		// base64url contains "_", so a valid lookup id may carry one — the
		// positional check must accept it (first-underscore splitting
		// misparsed these).
		{"lookup id containing underscore (valid)", "pgn_acc_v1__K4T9M7QZaB1c3d5_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", credentialKindAccount, ""},
		{"separator not at the fixed position", "pgn_acc_v1_K4T9M7QZaB1c3d5fX_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "", "malformed Account Token"},
		{"tail too long", "pgn_acc_v1_K4T9M7QZaB1c3d5f_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGX", "", "malformed Account Token"},
		{"bad charset", "pgn_acc_v1_K4T9M7QZaB1c3d5f_abcdefghijklmnopqrstuvwxyz0123456789ABCD.EF", "", "base64url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, err := parsePagnetTokenFormat(tc.in)
			if tc.wantErrFragment != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrFragment) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErrFragment)
				}
				// The pasted material must never be echoed back.
				if tc.in != "" && strings.Contains(err.Error(), tc.in) {
					t.Errorf("the error echoed the pasted credential: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
		})
	}
}

// --- paste login: Account Token → derived credential ----------------------------

func TestLoginWithPastedAccountToken(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s","role":"","expiresAt":"2027-01-01T00:00:00Z","sourceId":"K4T9M7QZaB1c3d5f"}`, testDerivedCred))

	dir := t.TempDir()
	res, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), "  "+testAccountToken+"\n")
	if err != nil {
		t.Fatalf("paste login: %v", err)
	}

	// The exchange ran exactly once with the pasted token, and /auth/me
	// was not needed (the exchange response is authoritative).
	ex, me := srv.hits()
	if ex != 1 || me != 0 {
		t.Fatalf("hits: exchange=%d me=%d, want 1/0", ex, me)
	}
	var sent map[string]string
	if err := json.Unmarshal([]byte(srv.lastExchangeBody()), &sent); err != nil {
		t.Fatalf("exchange body not JSON: %v", err)
	}
	if sent["token"] != testAccountToken {
		t.Errorf("exchange sent token=%q, want the trimmed pasted token", sent["token"])
	}

	// The DERIVED credential is the stored bearer — never the root token.
	if got := loadUserTokenFile(dir); got != testDerivedCred {
		t.Fatalf("stored bearer = %q, want the derived credential", got)
	}
	fc := stateFile(t, dir)
	if fc["credentialKind"] != credentialKindAccount {
		t.Errorf("credentialKind = %v, want account", fc["credentialKind"])
	}
	if fc["credentialSourceId"] != "K4T9M7QZaB1c3d5f" {
		t.Errorf("credentialSourceId = %v, want the server-reported source id", fc["credentialSourceId"])
	}
	if fc["credentialExpiresAt"] != "2027-01-01T00:00:00Z" {
		t.Errorf("credentialExpiresAt = %v, want the server-reported expiry", fc["credentialExpiresAt"])
	}
	// The root Account Token appears nowhere in the state file.
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if strings.Contains(string(b), testAccountToken) || strings.Contains(string(b), "K4T9M7QZaB1c3d5f_abcdefghij") {
		t.Errorf("the root Account Token leaked into the state file: %s", b)
	}
	// Strict 0600 (governance §19).
	info, err := os.Stat(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config.yaml perms = %o, want 0600", perm)
	}
	// Honest UX: the success line says the root token is not stored.
	if !strings.Contains(res.Summary, "Account Token") || !strings.Contains(res.Summary, "derived") {
		t.Errorf("summary = %q, want the account-token/derived-credential wording", res.Summary)
	}
}

// --- paste login: Access Token → honest limited line -----------------------------

func TestLoginWithPastedAccessToken(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s","role":"operator","networkScope":"selected","networks":["Production","Staging"],"expiresAt":"2026-10-16T00:00:00Z","organizationId":"org-7"}`, testDerivedCred))

	dir := t.TempDir()
	res, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), testAccessToken)
	if err != nil {
		t.Fatalf("paste login: %v", err)
	}
	if res.Kind != credentialKindAccess {
		t.Errorf("kind = %q, want access", res.Kind)
	}
	// The brief's honest line shape: limited access token + role + networks
	// + expiry (governance §93: no fake capabilities).
	for _, want := range []string{"limited access token", "role: operator", "Production, Staging", "expires: 2026-10-16T00:00:00Z"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("summary = %q, want it to contain %q", res.Summary, want)
		}
	}
	fc := stateFile(t, dir)
	if fc["credentialKind"] != credentialKindAccess || fc["credentialRole"] != "operator" {
		t.Errorf("metadata = %v/%v, want access/operator", fc["credentialKind"], fc["credentialRole"])
	}
	nets, _ := fc["credentialNetworks"].([]any)
	if len(nets) != 2 || nets[0] != "Production" {
		t.Errorf("credentialNetworks = %v, want [Production Staging]", fc["credentialNetworks"])
	}
	if fc["credentialOrganizationId"] != "org-7" {
		t.Errorf("credentialOrganizationId = %v, want org-7", fc["credentialOrganizationId"])
	}
}

// --- paste login: the removed legacy pagt_ class is rejected ----------------------

// TestLoginWithPastedLegacyTokenRejected: a pasted pagt_ token is no longer a
// Pagnet Token. It is rejected as an unknown format BEFORE any round-trip
// (the same local-format discipline as any malformed paste), and nothing is
// stored.
func TestLoginWithPastedLegacyTokenRejected(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)

	dir := t.TempDir()
	_, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), testLegacyToken)
	if err == nil || !strings.Contains(err.Error(), "unrecognized Pagnet Token") {
		t.Fatalf("err = %v, want the unknown-format rejection", err)
	}
	// The expected prefixes must be named so the user knows what to paste.
	for _, want := range []string{"pgn_acc_v1_", "pgn_pat_v1_"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %s: %v", want, err)
		}
	}
	// The pasted material must never be echoed back.
	if strings.Contains(err.Error(), testLegacyToken) {
		t.Errorf("the error echoed the pasted credential: %v", err)
	}
	// No server round-trip: the rejection is local.
	ex, me := srv.hits()
	if ex != 0 || me != 0 {
		t.Fatalf("a rejected paste must not touch the server (exchange=%d me=%d)", ex, me)
	}
	if got := loadUserTokenFile(dir); got != "" {
		t.Errorf("nothing must be stored on rejection, got %q", got)
	}
}

// --- exchange rejection: generic error, nothing stored, no secret echo ----------

func TestLoginWithPastedTokenExchangeRejected(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(http.StatusUnauthorized, "")

	dir := t.TempDir()
	_, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), testAccountToken)
	if err == nil {
		t.Fatal("want the generic rejection error")
	}
	// The error must not echo the pasted secret (spec §27/§60).
	if strings.Contains(err.Error(), testAccountToken) || strings.Contains(err.Error(), "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG") {
		t.Errorf("the error echoed the pasted token: %v", err)
	}
	if got := loadUserTokenFile(dir); got != "" {
		t.Errorf("nothing must be stored on rejection, got %q", got)
	}
}

// --- malformed paste: no server round-trip at all --------------------------------

func TestLoginWithPastedTokenFormatErrorNoRoundTrip(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)

	dir := t.TempDir()
	_, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), "pgn_totallywrong_abc")
	if err == nil || !strings.Contains(err.Error(), "unrecognized Pagnet Token") {
		t.Fatalf("err = %v, want the prefix-naming format error", err)
	}
	// The expected prefixes must be named so the user knows what to paste.
	for _, want := range []string{"pgn_acc_v1_", "pgn_pat_v1_"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %s: %v", want, err)
		}
	}
	ex, me := srv.hits()
	if ex != 0 || me != 0 {
		t.Fatalf("a malformed paste must not touch the server (exchange=%d me=%d)", ex, me)
	}
}

// --- exchange response hardening -------------------------------------------------

func TestLoginWithPastedTokenNoDerivedCredential(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, `{"kind":"account"}`) // no credential at all

	dir := t.TempDir()
	_, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), testAccountToken)
	if err == nil || !strings.Contains(err.Error(), "no client credential") {
		t.Fatalf("err = %v, want the clean empty-credential error", err)
	}
	if got := loadUserTokenFile(dir); got != "" {
		t.Errorf("nothing must be stored when the exchange returns no credential, got %q", got)
	}
}

// --- storage: metadata never goes stale across re-logins --------------------------

func TestSaveCredentialClearsStaleMetadata(t *testing.T) {
	withFileFallback(t)
	dir := t.TempDir()

	// A token-first login stores kind + role + networks.
	if err := saveCredential(dir, "", "https://cp.example/", testDerivedCred, credentialMeta{
		Kind: credentialKindAccess, Role: "operator", Networks: []string{"Production"},
	}); err != nil {
		t.Fatalf("saveCredential: %v", err)
	}
	fc := stateFile(t, dir)
	if fc["credentialRole"] != "operator" {
		t.Fatalf("precondition: credentialRole = %v", fc["credentialRole"])
	}

	// A later mode-based login (saveUserToken) must CLEAR the restriction
	// metadata — it carries none, and stale metadata would misrepresent the
	// bearer.
	if err := saveUserToken(dir, "", "https://cp.example/", testDeviceCredential); err != nil {
		t.Fatalf("saveUserToken: %v", err)
	}
	fc = stateFile(t, dir)
	for _, key := range []string{"credentialRole", "credentialNetworks", "credentialExpiresAt", "credentialOrganizationId", "credentialSourceId", "credentialSourceKind", "credentialNetworkScope"} {
		if _, ok := fc[key]; ok {
			t.Errorf("stale metadata key %q survived the re-login: %v", key, fc)
		}
	}
	// credentialKind is NOT optional metadata: it is the class the newly
	// stored bearer's own prefix proves, so it is re-recorded (never left at
	// the previous login's value, never dropped).
	if fc["credentialKind"] != credentialKindAccess {
		t.Errorf("credentialKind = %v, want %q (verified from the pgn_pat_ bearer just stored)", fc["credentialKind"], credentialKindAccess)
	}
	// Unrelated keys survive the merge (enroll shares this file).
	if fc["serverUrl"] != "https://cp.example" {
		t.Errorf("serverUrl = %v, want the trimmed server URL", fc["serverUrl"])
	}
}

// --- the hidden prompt never reads a non-terminal ---------------------------------

func TestAskPagnetTokenNonTerminal(t *testing.T) {
	// Under `go test` stdin is not a terminal: the prompt must fail with a
	// clean error naming the scripted alternative — never hang, never read.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal in this environment")
	}
	_, err := askPagnetToken("Paste your Pagnet Token: ")
	if err == nil {
		t.Fatal("want the clean no-interactive-terminal error")
	}
	for _, want := range []string{"interactive terminal", "--token", "$PAGNET_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q: %v", want, err)
		}
	}
}
