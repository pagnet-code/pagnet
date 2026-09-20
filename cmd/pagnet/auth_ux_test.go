package main

// Tests for the credential-UX fixes (plan §7, the 2026-09-20 `pagnet serve`
// incident): known auth failures become product text instead of a raw JSON
// body; a wrong-class credential re-prompts a human and exits only when nobody
// can answer; the stored credential always records the class its own material
// proves, so "a pgn_pat_ labelled account" cannot be represented; and the
// --token / $PAGNET_TOKEN short-circuit goes through the same exchange instead
// of persisting a root credential raw.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// --- the translator -----------------------------------------------------------

func TestTranslateAuthFailureKnownCodes(t *testing.T) {
	const why = "Settings → Security → Pagnet Token"
	cases := []struct {
		name         string
		status       int
		code         string
		class        string
		wantReprompt bool
		// wantFragments must all appear in the product text.
		wantFragments []string
	}{
		{
			name:         "access token on an account-authority operation",
			status:       http.StatusForbidden,
			code:         errCodeAccountAuthority,
			class:        credentialKindAccess,
			wantReprompt: true,
			wantFragments: []string{
				// The required copy, verbatim.
				"This is an Access Token. Use your Pagnet Token (" + why + ").",
				"Access Tokens are restricted tokens for scripts and API integrations",
			},
		},
		{
			name:         "legacy api token on an account-authority operation",
			status:       http.StatusForbidden,
			code:         errCodeAccountAuthority,
			class:        credentialKindAPI,
			wantReprompt: true,
			wantFragments: []string{
				"This is a legacy API token. Use your Pagnet Token (" + why + ").",
			},
		},
		{
			name:          "derived client credential on an account-authority operation",
			status:        http.StatusForbidden,
			code:          errCodeAccountAuthority,
			class:         credentialKindClient,
			wantReprompt:  true,
			wantFragments: []string{"does not carry account authority", why},
		},
		{
			// The management surface is user-only: the credential is fine, the
			// surface is wrong — so it is explained but NOT re-prompted.
			name:          "principal credential on a user-only surface",
			status:        http.StatusForbidden,
			code:          errCodeUserIdentityRequired,
			class:         credentialKindAccess,
			wantReprompt:  false,
			wantFragments: []string{"agent or service credential", "pagnet login", why},
		},
		{
			name:          "revoked or replaced token",
			status:        http.StatusUnauthorized,
			code:          errCodeInvalidCredentials,
			class:         credentialKindAccount,
			wantReprompt:  true,
			wantFragments: []string{"did not accept your Pagnet Token", "revoked or replaced", why},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fmt.Errorf("create enrollment token: %w",
				&httpFailure{status: tc.status, code: tc.code,
					body: `{"error":{"code":"` + tc.code + `","message":"server detail"}}`})
			f := translateAuthFailure(in, tc.class)
			if !f.Translated {
				t.Fatalf("this failure must be translated, got %v", f.Err)
			}
			if f.Reprompt != tc.wantReprompt {
				t.Errorf("Reprompt = %v, want %v", f.Reprompt, tc.wantReprompt)
			}
			msg := f.Err.Error()
			for _, want := range tc.wantFragments {
				if !strings.Contains(msg, want) {
					t.Errorf("message must contain %q:\n%s", want, msg)
				}
			}
			// No raw JSON, and no server-internal detail, reaches a human.
			if strings.Contains(msg, "{") || strings.Contains(msg, "server detail") {
				t.Errorf("raw server body leaked to a human: %s", msg)
			}
		})
	}
}

// TestTranslateAuthFailureLeavesUnrelatedErrors: an error the CLI has no
// product text for is reported as the call site produced it — never swallowed,
// never rewritten into generic prose.
func TestTranslateAuthFailureLeavesUnrelatedErrors(t *testing.T) {
	plain := fmt.Errorf("some local failure")
	f := translateAuthFailure(plain, credentialKindAccess)
	if f.Translated || f.Err != plain {
		t.Errorf("an unrelated error must pass through unchanged: %+v", f)
	}
	notFound := &httpFailure{status: http.StatusNotFound, code: "not_found", body: `{"error":{"code":"not_found"}}`}
	f = translateAuthFailure(notFound, credentialKindAccess)
	if f.Translated || f.Err != notFound {
		t.Errorf("a 404 not_found must keep the server's report: %+v", f)
	}
	if translateAuthFailure(nil, credentialKindAccess).Err != nil {
		t.Error("nil must stay nil")
	}
}

// captureStderr runs fn with os.Stderr redirected and returns everything it
// wrote plus its error. os.Stderr is a *os.File, so the redirect has to be a
// real pipe (an io.Writer swap would not be seen by the CLI's fmt.Fprintln).
func captureStderr(fn func() error) (string, error) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			b.Write(buf[:n])
			if rerr != nil {
				done <- b.String()
				return
			}
		}
	}()
	fnErr := fn()
	_ = w.Close()
	os.Stderr = old
	out := <-done
	_ = r.Close()
	return out, fnErr
}

// --- the wrong-class re-prompt loop ---------------------------------------------

// stubEnrollAuth is a control plane for the first-run serve path. It accepts
// the account-class bearer on the account-authority route and refuses the
// delegated one with the server's real gate, so the CLI's routing is exercised
// against the actual contract rather than a stand-in.
type stubEnrollAuth struct {
	ts *httptest.Server

	mu        sync.Mutex
	accepted  string // the bearer allowed to mint an enrollment token
	mints     int
	exchanges int
	enrolls   int
}

func newStubEnrollAuth(t *testing.T, accepted string) *stubEnrollAuth {
	t.Helper()
	s := &stubEnrollAuth{accepted: accepted}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			// Both the stored delegated token and the derived credential are
			// live bearers for ordinary calls — only the account-authority
			// gate separates them.
			if bearer == testAccessToken || bearer == testDerivedCred {
				fmt.Fprint(w, `{"kind":"user","isAdmin":true}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"code":"unauthorized","message":"authentication required"}}`)
		case "/" + tokenExchangePath:
			s.mu.Lock()
			s.exchanges++
			s.mu.Unlock()
			fmt.Fprintf(w, `{"credential":"%s","role":"admin","networkScope":"all"}`, testDerivedCred)
		case "/api/v1/hosts/enrollment-tokens":
			s.mu.Lock()
			s.mints++
			allow := bearer == s.accepted
			s.mu.Unlock()
			if !allow {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":{"code":"account_authority_required",`+
					`"message":"this operation requires account authority; sign in with your Account Token"}}`)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"token":"paget_enroll_1","expiresIn":900}`)
		case "/api/v1/hosts/enroll":
			s.mu.Lock()
			s.enrolls++
			s.mu.Unlock()
			fmt.Fprint(w, `{"host":{"ID":"h1"},"credential":"hostcred123","allowedRoots":[],"rootsMode":"allow_all"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *stubEnrollAuth) counts() (mints, exchanges, enrolls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mints, s.exchanges, s.enrolls
}

// seedStoredAccessToken reproduces the incident's starting state: the active
// account already holds a stored Access Token. It seeds through the same
// account resolution the CLI reads through (an account keeps its credential in
// its own config dir, and the account migration moves any legacy flat copy
// there), so the flow really does find and reuse the wrong-class bearer
// instead of falling through to a first-time login.
func seedStoredAccessToken(t *testing.T, server string) (root, account, accDir string) {
	t.Helper()
	root = t.TempDir()
	_, account, err := loadAccountConfig(root)
	if err != nil {
		t.Fatalf("loadAccountConfig: %v", err)
	}
	accDir = accountConfigDir(root, account)
	if err := saveCredential(accDir, account, server, testAccessToken,
		credentialMeta{Kind: credentialKindAccess, SourceKind: credentialKindAccess}); err != nil {
		t.Fatal(err)
	}
	// Precondition: the shared auth path finds the seeded bearer, or the test
	// would silently exercise a first login instead of the wrong-class reuse.
	if got := loadUserToken(accDir, account, server); got != testAccessToken {
		t.Fatalf("seeded bearer not visible to the auth path (got %q)", got)
	}
	return root, account, accDir
}

// TestServeWrongClassRepromptsThenSucceeds: the incident, fixed. A stored
// Access Token cannot mint the host enrollment token; the human gets product
// text (not the JSON body), is asked for a different credential, and the run
// completes with the one that works.
func TestServeWrongClassRepromptsThenSucceeds(t *testing.T) {
	withFileFallback(t)
	srv := newStubEnrollAuth(t, testDerivedCred)
	// The stored credential is the website-copied Access Token (the incident's
	// starting state), and it IS a live bearer for ordinary calls.
	dir, account, accDir := seedStoredAccessToken(t, srv.ts.URL)

	prevServer := serverURL
	serverURL = srv.ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = ""
	t.Cleanup(func() { userToken = prevToken })
	prevNI := nonInteractive
	nonInteractive = false
	t.Cleanup(func() { nonInteractive = prevNI })
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	pastes := 0
	prevAsk := askPagnetTokenFn
	askPagnetTokenFn = func(string) (string, error) {
		pastes++
		return testAccountToken, nil // the human follows the instruction
	}
	t.Cleanup(func() { askPagnetTokenFn = prevAsk })

	// The translated text goes to stderr; capture it to prove what was shown.
	shownText, runErr := captureStderr(func() error {
		return enrollHostForeground(dir, account, "test-host", nil, "")
	})

	if runErr != nil {
		t.Fatalf("enrollHostForeground: %v\nshown to the human:\n%s", runErr, shownText)
	}
	if pastes != 1 {
		t.Errorf("pastes = %d, want exactly 1 re-prompt", pastes)
	}
	for _, want := range []string{"This is an Access Token.", "Use your Pagnet Token", "Settings → Security → Pagnet Token"} {
		if !strings.Contains(shownText, want) {
			t.Errorf("the human must be told %q, saw:\n%s", want, shownText)
		}
	}
	if strings.Contains(shownText, "account_authority_required") {
		t.Errorf("the raw error code leaked to the human:\n%s", shownText)
	}
	mints, exchanges, enrolls := srv.counts()
	if mints != 2 || enrolls != 1 {
		t.Errorf("mints=%d enrolls=%d, want 2 attempts then 1 enroll (exchanges=%d)", mints, enrolls, exchanges)
	}
	if exchanges != 1 {
		t.Errorf("exchanges = %d, want 1 (the pasted root is exchanged once)", exchanges)
	}
	// The account's stored bearer is the DERIVED credential, never the root.
	if got := loadUserTokenFile(accDir); got != testDerivedCred {
		t.Errorf("stored bearer = %q, want the derived credential", got)
	}
	b, _ := os.ReadFile(filepath.Join(accDir, "config.yaml"))
	if strings.Contains(string(b), testAccountToken) {
		t.Errorf("the root Pagnet Token leaked into config.yaml: %s", b)
	}
}

// TestServeWrongClassExitsNonInteractive: with --non-interactive there is
// nobody to ask, so the run exits with the same product text — it never
// prompts and never prints the server body.
func TestServeWrongClassExitsNonInteractive(t *testing.T) {
	withFileFallback(t)
	srv := newStubEnrollAuth(t, testDerivedCred)
	dir, account, _ := seedStoredAccessToken(t, srv.ts.URL)
	prevServer := serverURL
	serverURL = srv.ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = ""
	t.Cleanup(func() { userToken = prevToken })

	withNoPromptSeams(t) // any prompt is a failure here
	prevNI := nonInteractive
	nonInteractive = true
	t.Cleanup(func() { nonInteractive = prevNI })

	err := enrollHostForeground(dir, account, "test-host", nil, "")
	if err == nil {
		t.Fatal("want the friendly failure")
	}
	msg := err.Error()
	if !strings.Contains(msg, "This is an Access Token.") || !strings.Contains(msg, "Use your Pagnet Token") {
		t.Fatalf("the failure must be the product text, got: %s", msg)
	}
	if strings.Contains(msg, "{") || strings.Contains(msg, "account_authority_required") {
		t.Errorf("raw JSON must never reach a human: %s", msg)
	}
	if mints, _, enrolls := srv.counts(); mints != 1 || enrolls != 0 {
		t.Errorf("mints=%d enrolls=%d, want one attempt and no enrollment", mints, enrolls)
	}
}

// TestRepromptLoopIsBounded: a human who keeps pasting the wrong class does not
// loop forever.
func TestRepromptLoopIsBounded(t *testing.T) {
	withFileFallback(t)
	srv := newStubEnrollAuth(t, "never-minted") // nothing may mint
	dir, account, _ := seedStoredAccessToken(t, srv.ts.URL)
	prevServer := serverURL
	serverURL = srv.ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = ""
	t.Cleanup(func() { userToken = prevToken })
	prevNI := nonInteractive
	nonInteractive = false
	t.Cleanup(func() { nonInteractive = prevNI })
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	pastes := 0
	prevAsk := askPagnetTokenFn
	askPagnetTokenFn = func(string) (string, error) {
		pastes++
		return testAccessToken, nil // the same wrong class every time
	}
	t.Cleanup(func() { askPagnetTokenFn = prevAsk })

	err := enrollHostForeground(dir, account, "test-host", nil, "")
	if err == nil {
		t.Fatal("want the bounded failure")
	}
	// attempt 0 reuses the stored bearer, so every paste here IS a re-prompt.
	if pastes != maxAuthReprompts {
		t.Fatalf("pastes = %d, want exactly maxAuthReprompts (%d)", pastes, maxAuthReprompts)
	}
	if !strings.Contains(err.Error(), "This is an Access Token.") {
		t.Errorf("the final failure must stay the product text: %s", err)
	}
}

// --- the recorded credential class ----------------------------------------------

// TestAccessTokenNeverRecordedAsAccount: the mislabel state that hid the
// incident is now unrepresentable — the class is read off the stored material.
func TestAccessTokenNeverRecordedAsAccount(t *testing.T) {
	withFileFallback(t)
	dir := t.TempDir()
	err := saveCredential(dir, "", "https://cp.example/", testAccessToken,
		credentialMeta{Kind: credentialKindAccount, SourceKind: credentialKindAccount})
	if err == nil {
		t.Fatal("storing a pgn_pat_ bearer as credentialKind=account must be impossible")
	}
	if !strings.Contains(err.Error(), "cannot be recorded as") {
		t.Fatalf("err = %v, want the mismatch failure", err)
	}
	if got := loadUserTokenFile(dir); got != "" {
		t.Errorf("nothing may be stored when the class disagrees, got %q", got)
	}
}

// TestDerivedAccessTokenRecordsAccessKind: the real control plane exchanges an
// Account Token for a DERIVED pgn_pat_ credential. The stored bearer is that
// delegated token, so its recorded class is access — the provenance stays
// visible as the source, and nothing claims account for a delegated bearer.
func TestDerivedAccessTokenRecordsAccessKind(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	derived := "pgn_pat_v1_D3r1v3dL00k1d_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHI"
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s","role":"admin","networkScope":"all"}`, derived))

	dir := t.TempDir()
	res, err := loginWithPastedToken(dir, "", srv.ts.URL+"/", srv.ts.Client(), testAccountToken)
	if err != nil {
		t.Fatalf("paste login: %v", err)
	}
	if got := loadUserTokenFile(dir); got != derived {
		t.Fatalf("stored bearer = %q, want the derived credential", got)
	}
	fc := stateFile(t, dir)
	if fc["credentialKind"] != credentialKindAccess {
		t.Errorf("credentialKind = %v, want access (the class the stored bearer's own prefix proves)", fc["credentialKind"])
	}
	if fc["credentialSourceKind"] != credentialKindAccount {
		t.Errorf("credentialSourceKind = %v, want account (what the human pasted)", fc["credentialSourceKind"])
	}
	// The human-facing summary still describes what THEY did.
	if !strings.Contains(res.Summary, "Account Token") {
		t.Errorf("summary = %q, want the account-token wording", res.Summary)
	}
}

// TestVerifiedCredentialKind: the class the CLI may assert is the one the
// material proves; an opaque derived credential proves nothing.
func TestVerifiedCredentialKind(t *testing.T) {
	cases := map[string]string{
		testAccountToken: credentialKindAccount,
		testAccessToken:  credentialKindAccess,
		testLegacyToken:  credentialKindAPI,
		testDerivedCred:  "", // pgn_cli_ — the client must not guess
		"":               "",
		"host_whatever":  "",
	}
	for bearer, want := range cases {
		if got := verifiedCredentialKind(bearer); got != want {
			t.Errorf("verifiedCredentialKind(%q) = %q, want %q", firstN(bearer, 16), got, want)
		}
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// --- the --token / $PAGNET_TOKEN path -------------------------------------------

// TestUserCredentialForServeExchangesToken: the short-circuit no longer
// persists the pasted root. It runs the same exchange and kind recording as an
// interactive paste, and the account ends up holding the derived credential.
func TestUserCredentialForServeExchangesToken(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s","role":"admin","networkScope":"all"}`, testDerivedCred))
	dir := t.TempDir()

	prevToken := userToken
	userToken = testAccountToken
	t.Cleanup(func() { userToken = prevToken })

	got, err := userCredentialForServe(dir, "", srv.ts.URL)
	if err != nil {
		t.Fatalf("userCredentialForServe: %v", err)
	}
	if got != testDerivedCred {
		t.Fatalf("bearer = %q, want the derived credential", got)
	}
	if stored := loadUserTokenFile(dir); stored != testDerivedCred {
		t.Fatalf("stored = %q, want the derived credential", stored)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if strings.Contains(string(b), testAccountToken) {
		t.Fatalf("the root Pagnet Token was persisted raw: %s", b)
	}
	if ex, _ := srv.hits(); ex != 1 {
		t.Errorf("exchange hits = %d, want 1", ex)
	}
	fc := stateFile(t, dir)
	if fc["credentialKind"] != credentialKindAccount || fc["credentialSourceKind"] != credentialKindAccount {
		t.Errorf("recorded class = %v/%v, want account/account", fc["credentialKind"], fc["credentialSourceKind"])
	}
}

// TestUserCredentialForServeRecordsDelegatedToken: a scripted Access Token is
// recorded as what it is, so a later wrong-class failure can name it.
func TestUserCredentialForServeRecordsDelegatedToken(t *testing.T) {
	withFileFallback(t)
	srv := newStubTokenServer(t)
	// The server returns the presented delegated token as-is (its documented
	// behavior for an Access Token).
	srv.setExchange(0, fmt.Sprintf(`{"credential":"%s","role":"operator","networkScope":"selected"}`, testAccessToken))
	dir := t.TempDir()

	prevToken := userToken
	userToken = testAccessToken
	t.Cleanup(func() { userToken = prevToken })

	if _, err := userCredentialForServe(dir, "", srv.ts.URL); err != nil {
		t.Fatalf("userCredentialForServe: %v", err)
	}
	fc := stateFile(t, dir)
	if fc["credentialKind"] != credentialKindAccess {
		t.Errorf("credentialKind = %v, want access", fc["credentialKind"])
	}
	if fc["credentialSourceKind"] != credentialKindAccess {
		t.Errorf("credentialSourceKind = %v, want access", fc["credentialSourceKind"])
	}
}

// TestCredentialClassOf: the class used to choose the product text prefers the
// bearer's own prefix, then the recorded class.
func TestCredentialClassOf(t *testing.T) {
	withFileFallback(t)
	dir := t.TempDir()
	if got := credentialClassOf(dir, testAccessToken); got != credentialKindAccess {
		t.Errorf("class = %q, want access (proved by the prefix)", got)
	}
	if err := saveCredential(dir, "", "https://cp.example/", testDerivedCred,
		credentialMeta{SourceKind: credentialKindAccess}); err != nil {
		t.Fatal(err)
	}
	if got := credentialClassOf(dir, testDerivedCred); got != credentialKindAccess {
		t.Errorf("class = %q, want access (the recorded class of an opaque derived credential)", got)
	}
	if got := credentialClassOf(t.TempDir(), "something-opaque"); got != credentialKindClient {
		t.Errorf("class = %q, want client (nothing proved, nothing recorded)", got)
	}
}
