package main

// Focused first-run-correctness tests (Wave UX-A §9): the shared token-first
// auth function, credential reuse, the already-enrolled short-circuit,
// non-interactive fail-fast, per-account credential scoping, and safe
// control-plane switching.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
