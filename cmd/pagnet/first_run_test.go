package main

// Focused first-run-correctness tests (Wave UX-A §9): the shared token-first
// auth function, credential reuse, the already-enrolled short-circuit,
// non-interactive fail-fast, per-account credential scoping, and safe
// control-plane switching.

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
	"testing"

	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/internal/config"
)

// withNoPromptSeams installs fail-fast seams for the interactive prompts so a
// test that unexpectedly prompts (or opens a browser) fails loudly.
func withNoPromptSeams(t *testing.T) {
	t.Helper()
	prevAsk := askPagnetTokenFn
	askPagnetTokenFn = func(string) (string, error) {
		t.Error("the token paste prompt was invoked — it must not be")
		return "", errors.New("unexpected prompt")
	}
	t.Cleanup(func() { askPagnetTokenFn = prevAsk })
	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error {
		t.Error("the browser was opened — it must not be")
		return errors.New("unexpected browser")
	}
	t.Cleanup(func() { openBrowserFn = prevBrowser })
}

// TestAuthenticateUserTokenFirstPaste (§9.2): a fresh serve with no stored
// credential runs the SHARED token-first paste (never a browser), exchanges
// the token once, and stores the derived credential — the root token is
// never persisted.
func TestAuthenticateUserTokenFirstPaste(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s"}`, testDerivedCred))

	dir := t.TempDir()
	prevAsk := askPagnetTokenFn
	askPagnetTokenFn = func(string) (string, error) { return testAccountToken, nil }
	t.Cleanup(func() { askPagnetTokenFn = prevAsk })

	tok, err := authenticateUser(dir, "", srv.ts.URL, true)
	if err != nil {
		t.Fatalf("authenticateUser (paste): %v", err)
	}
	if tok != testDerivedCred {
		t.Fatalf("returned = %q, want the derived credential", tok)
	}
	// The DERIVED credential is stored; the root Account Token is not.
	if got := loadUserTokenFile(dir); got != testDerivedCred {
		t.Fatalf("stored = %q, want the derived credential", got)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if strings.Contains(string(b), testAccountToken) {
		t.Fatalf("the root Account Token leaked into the state file: %s", b)
	}
	// The exchange ran exactly once (the token is exchanged ONCE).
	if ex, _ := srv.hits(); ex != 1 {
		t.Errorf("exchange hits = %d, want 1", ex)
	}
}

// TestAuthenticateUserReusesStoredCredential (§9.4): a valid stored
// credential is reused on every run with NO prompt (the second run does not
// re-paste, re-exchange, or open a browser).
func TestAuthenticateUserReusesStoredCredential(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setValidBearer(testDerivedCred) // /auth/me accepts the derived credential

	dir := t.TempDir()
	if err := saveUserToken(dir, "", srv.ts.URL, testDerivedCred); err != nil {
		t.Fatal(err)
	}
	withNoPromptSeams(t)

	for i := 0; i < 2; i++ {
		tok, err := authenticateUser(dir, "", srv.ts.URL, true)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if tok != testDerivedCred {
			t.Fatalf("run %d: returned = %q, want the stored credential", i, tok)
		}
	}
	// No exchange happened (the stored credential was reused, not re-exchanged).
	if ex, _ := srv.hits(); ex != 0 {
		t.Errorf("exchange hits = %d, want 0 (reuse, no re-exchange)", ex)
	}
}

// TestNeedsEnroll (§9.5/§9.6): an already-enrolled host (credential + hostId)
// does NOT need enrollment — it starts without a user login. A fresh or
// partially-enrolled host does.
func TestNeedsEnroll(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Daemon
		want bool
	}{
		{"fresh", config.Daemon{}, true},
		{"credential only", config.Daemon{Credential: "c"}, true},
		{"hostId only", config.Daemon{HostID: "h"}, true},
		{"enrolled", config.Daemon{Credential: "c", HostID: "h"}, false},
	}
	for _, c := range cases {
		if got := needsEnroll(c.cfg); got != c.want {
			t.Errorf("needsEnroll(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAuthenticateUserNonInteractiveNoPrompt (§9.7): with --non-interactive
// (interactive=false) and no stored credential, the auth fails cleanly — it
// never prompts, never opens a browser, and never waits.
func TestAuthenticateUserNonInteractiveNoPrompt(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	dir := t.TempDir()
	withNoPromptSeams(t)

	_, err := authenticateUser(dir, "", srv.ts.URL, false)
	if err == nil {
		t.Fatal("non-interactive auth with no credential = nil, want a clean failure")
	}
	if !strings.Contains(err.Error(), "--non-interactive") {
		t.Fatalf("error = %q, want the non-interactive message", err)
	}
	// Zero server chatter: it failed before touching the exchange.
	if ex, me := srv.hits(); ex != 0 || me != 0 {
		t.Errorf("hits = exchange %d / me %d, want 0/0", ex, me)
	}
}

// TestUserCredentialForServeTokenShortCircuit (§9.2): an explicit --token /
// $PAGNET_TOKEN goes through the same paste-login path (one exchange, no
// interactive paste, no browser) and stores the derived credential.
func TestUserCredentialForServeTokenShortCircuit(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s"}`, testDerivedCred))

	dir := t.TempDir()
	withNoPromptSeams(t)
	prevToken := userToken
	userToken = testAccountToken
	t.Cleanup(func() { userToken = prevToken })

	tok, err := userCredentialForServe(dir, "", srv.ts.URL)
	if err != nil {
		t.Fatalf("userCredentialForServe (--token): %v", err)
	}
	if tok != testDerivedCred {
		t.Fatalf("returned = %q, want the derived credential", tok)
	}
	if got := loadUserTokenFile(dir); got != testDerivedCred {
		t.Fatalf("stored = %q, want the derived credential", got)
	}
}

// TestTwoAccountsSeparateCredentials (§9.9): two accounts on the SAME server
// get distinct keyring keys and config files — their credentials and host
// identity never overwrite each other.
func TestTwoAccountsSeparateCredentials(t *testing.T) {
	server := "https://cp.example"
	if credentialKey("personal", server) == credentialKey("work", server) {
		t.Fatal("personal and work share a keyring key — they must be distinct")
	}
	// The default account keeps the legacy server-scoped key (backward
	// compat: existing keyring entries survive the migration).
	if credentialKey(accounts.DefaultAccount, server) != "pagnet-token-"+server {
		t.Fatalf("default key = %q, want the legacy server-scoped key", credentialKey(accounts.DefaultAccount, server))
	}
	if credentialKey("", server) != "pagnet-token-"+server {
		t.Fatalf("worker (account=\"\") key = %q, want the legacy server-scoped key", credentialKey("", server))
	}

	// And the on-disk configs are separate files.
	root := t.TempDir()
	if accountConfigDir(root, "personal") == accountConfigDir(root, "work") {
		t.Fatal("personal and work share a config dir")
	}
}

// TestEnsureServerSwitchNonInteractive (§9.11): when the resolved server
// differs from the server the stored host credential is tied to, a
// non-interactive run FAILS CLEANLY — it never re-enrolls and never sends
// the old credential to the new server.
func TestEnsureServerSwitchNonInteractive(t *testing.T) {
	withFileFallback(t)
	root := t.TempDir()
	// An account enrolled on server A (credential + hostId + serverUrl).
	accDir := accountConfigDir(root, "default")
	if err := os.MkdirAll(accDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accDir, "config.yaml"),
		[]byte("serverUrl: https://a.example\ncredential: hostcred-A\nhostId: h-A\nhostName: lince\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The user explicitly selects server B (the --server flag).
	prevServer := serverURL
	serverURL = "https://b.example"
	t.Cleanup(func() { serverURL = prevServer })
	prevNI := nonInteractive
	nonInteractive = true
	t.Cleanup(func() { nonInteractive = prevNI })

	cfg, _, err := loadAccountConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	err = ensureServerSwitch(root, "default", &cfg)
	if err == nil {
		t.Fatal("server switch (non-interactive) = nil, want a clean failure")
	}
	if !strings.Contains(err.Error(), "will not be sent") {
		t.Fatalf("error = %q, want the 'will not be sent' message", err)
	}
	// The stored credential for A is untouched (no re-enrollment happened).
	b, _ := os.ReadFile(filepath.Join(accDir, "config.yaml"))
	if !strings.Contains(string(b), "hostcred-A") || !strings.Contains(string(b), "https://a.example") {
		t.Fatalf("the account config was mutated on a failed switch: %s", b)
	}
}

// captureStdout swaps os.Stdout for a pipe for the duration of fn and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
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
	fn()
	_ = w.Close()
	<-done
	os.Stdout = old
	return buf.String()
}

// TestSilentSuppressesSuccessProse (§9.8): --silent suppresses the success
// prose (the "host registered" lines) while a non-silent run prints it.
func TestSilentSuppressesSuccessProse(t *testing.T) {
	withFileFallback(t)
	ts := newStubPagnetServer(t, nil, "token")

	prevSilent := silent
	t.Cleanup(func() { silent = prevSilent })

	// Non-silent: the success prose is printed.
	silent = false
	out := captureStdout(t, func() {
		if err := doEnroll(ts.URL, "paget_enroll_1", "lince", nil, "", t.TempDir()); err != nil {
			t.Fatalf("doEnroll (non-silent): %v", err)
		}
	})
	if !strings.Contains(out, "registered") {
		t.Errorf("non-silent doEnroll printed %q, want the success prose", out)
	}

	// Silent: the success prose is suppressed (nothing on stdout).
	silent = true
	out = captureStdout(t, func() {
		if err := doEnroll(ts.URL, "paget_enroll_1", "lince", nil, "", t.TempDir()); err != nil {
			t.Fatalf("doEnroll (silent): %v", err)
		}
	})
	if strings.Contains(out, "registered") {
		t.Errorf("silent doEnroll printed success prose: %q", out)
	}
}

// TestSilentPreservesFailureExitStatus (§9.8): --silent only quiets the
// success prose — a failure still propagates as an error (a meaningful,
// non-zero exit) in BOTH silent and non-silent modes.
func TestSilentPreservesFailureExitStatus(t *testing.T) {
	withFileFallback(t)
	ts := newStubPagnetServer(t, nil, "token")

	prevSilent := silent
	t.Cleanup(func() { silent = prevSilent })

	// A bad enrollment token → the server rejects it. The error must
	// propagate regardless of --silent.
	for _, s := range []bool{false, true} {
		silent = s
		err := doEnroll(ts.URL, "wrong-token", "lince", nil, "", t.TempDir())
		if err == nil {
			t.Fatalf("silent=%v: doEnroll (bad token) = nil, want an error (exit status preserved)", s)
		}
	}
}

// --- first-run console handoff (BINDING 2026-09-22) ---------------------------
//
// The terminal's job is runtime; the browser's job is composition. `pagnet
// serve` completes the connection and then HANDS OFF to the console: the
// definitive first-run event (host registration) prints a next-steps block
// and opens /welcome (only when interactive); later runs print a one-line
// reminder when the account has zero networks.

// TestFirstRunHandoffPrintsBlock: the registration path prints the
// next-steps block with the correct /welcome URL and the quickstart link.
// The zero-networks reminder is ABSENT on the registration run itself (the
// full block covers it).
func TestFirstRunHandoffPrintsBlock(t *testing.T) {
	// Non-interactive (no TTY) + PAGNET_NO_BROWSER: no browser open.
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return false }
	t.Cleanup(func() { hasTTYFn = prevTTY })
	t.Setenv("PAGNET_NO_BROWSER", "1")

	out := captureStdout(t, func() {
		printFirstRunHandoff("https://cp.example/", "h1", "lince")
	})
	if !strings.Contains(out, `✓ signed in · host "lince" connected to https://cp.example`) {
		t.Errorf("handoff missing the signed-in line: %q", out)
	}
	if !strings.Contains(out, "https://cp.example/welcome") {
		t.Errorf("handoff missing the /welcome URL: %q", out)
	}
	if !strings.Contains(out, "docs.pagnet.dev/quickstart") {
		t.Errorf("handoff missing the quickstart URL: %q", out)
	}
	// The reminder is absent on the registration run (the full block covers it).
	if strings.Contains(out, "no networks yet") {
		t.Errorf("reminder printed on the registration run: %q", out)
	}
}

// TestFirstRunHandoffBrowserOpen: the browser is opened to /welcome?host=
// when interactive and PAGNET_NO_BROWSER is unset; it is suppressed when
// PAGNET_NO_BROWSER=1 (mirror TestLoginOIDCDeviceFlowNoBrowser).
func TestFirstRunHandoffBrowserOpen(t *testing.T) {
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true } // interactive
	t.Cleanup(func() { hasTTYFn = prevTTY })

	var gotURL string
	prev := openBrowserFn
	openBrowserFn = func(url string) error { gotURL = url; return nil }
	t.Cleanup(func() { openBrowserFn = prev })

	// Without PAGNET_NO_BROWSER: the browser-open is attempted with the
	// correct /welcome?host= URL.
	os.Unsetenv("PAGNET_NO_BROWSER")
	printFirstRunHandoff("https://cp.example/", "h1", "lince")
	if gotURL != "https://cp.example/welcome?host=h1" {
		t.Errorf("browser URL = %q, want https://cp.example/welcome?host=h1", gotURL)
	}

	// PAGNET_NO_BROWSER=1 must suppress the browser-open attempt.
	gotURL = ""
	t.Setenv("PAGNET_NO_BROWSER", "1")
	printFirstRunHandoff("https://cp.example/", "h1", "lince")
	if gotURL != "" {
		t.Errorf("browser was opened despite PAGNET_NO_BROWSER=1 (url %q)", gotURL)
	}
}

// stubNetworksServer is a fake control plane for the zero-networks reminder:
// it serves /api/v1/networks with a configurable list (count networks).
type stubNetworksServer struct {
	ts *httptest.Server
}

// newStubNetworksServer returns a fake control plane whose /api/v1/networks
// responds with a JSON array of `count` networks.
func newStubNetworksServer(t *testing.T, count int) *stubNetworksServer {
	t.Helper()
	nets := make([]map[string]string, 0, count)
	for i := 0; i < count; i++ {
		nets = append(nets, map[string]string{"ID": fmt.Sprintf("net-%d", i)})
	}
	s := &stubNetworksServer{}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/networks" {
			b, _ := json.Marshal(nets)
			fmt.Fprint(w, string(b))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

// newStubErrorServer returns a fake control plane that answers every request
// with 500 (to test the endpoint-error case: the reminder must be suppressed).
func newStubErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":{"code":"internal","message":"internal error"}}`)
	}))
	t.Cleanup(s.Close)
	return s
}

// TestZeroNetworksReminder: the reminder appears EXACTLY when the networks
// list is empty; it is suppressed when networks exist AND when the endpoint
// errors (the reminder must never break or delay serve startup).
func TestZeroNetworksReminder(t *testing.T) {
	withFileFallback(t)
	root := t.TempDir()
	accDir := accountConfigDir(root, "default")
	// Store a user bearer (so loadUserToken returns non-empty).
	if err := os.MkdirAll(accDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveUserToken(accDir, "default", "https://cp.example", "user-bearer"); err != nil {
		t.Fatal(err)
	}

	// Zero networks: the reminder is printed with the correct /welcome?host= URL.
	ts := newStubNetworksServer(t, 0)
	out := captureStdout(t, func() {
		printZeroNetworksReminder(ts.ts.URL, "h1", root, "default")
	})
	if want := "no networks yet — create your first: " + ts.ts.URL + "/welcome?host=h1"; !strings.Contains(out, want) {
		t.Errorf("zero-networks reminder = %q, want %q", out, want)
	}

	// Networks exist: the reminder is suppressed.
	ts2 := newStubNetworksServer(t, 1)
	out = captureStdout(t, func() {
		printZeroNetworksReminder(ts2.ts.URL, "h1", root, "default")
	})
	if strings.Contains(out, "no networks yet") {
		t.Errorf("reminder printed despite networks existing: %q", out)
	}

	// Endpoint error (non-200): the reminder is suppressed.
	ts3 := newStubErrorServer(t)
	out = captureStdout(t, func() {
		printZeroNetworksReminder(ts3.URL, "h1", root, "default")
	})
	if strings.Contains(out, "no networks yet") {
		t.Errorf("reminder printed despite endpoint error: %q", out)
	}
}

// TestZeroNetworksReminderNoBearer: with no stored user bearer, the reminder
// is suppressed (it must never break or delay serve startup).
func TestZeroNetworksReminderNoBearer(t *testing.T) {
	withFileFallback(t)
	root := t.TempDir() // no stored credential
	ts := newStubNetworksServer(t, 0)
	out := captureStdout(t, func() {
		printZeroNetworksReminder(ts.ts.URL, "h1", root, "default")
	})
	if strings.Contains(out, "no networks yet") {
		t.Errorf("reminder printed despite no bearer: %q", out)
	}
}
