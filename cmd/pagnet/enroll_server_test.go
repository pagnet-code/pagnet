package main

// Tests for the first-run control-plane URL resolution (Bug 1): the
// --server flag (or $PAGNET_SERVER) wins, then the state config's
// ServerURL, then an interactive prompt, then a clean non-interactive
// error. The full enroll flow (enrollHostForeground) is exercised against
// the stub for the flag and state cases; the resolution itself is
// exercised directly for the prompt and non-interactive cases.

import (
	"strings"
	"testing"
)

// TestEnrollServerFlagGiven: --server given (the flag value is set) → the
// full enroll flow runs against the stub.
func TestEnrollServerFlagGiven(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", "pagt_testtoken123")

	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ts.URL
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = ""
	t.Cleanup(func() { userToken = prevToken })

	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	dir := t.TempDir()
	if err := enrollHostForeground(dir, "test-host", nil, ""); err != nil {
		t.Fatalf("enrollHostForeground: %v", err)
	}
	if n := ts.enrollCallCount(); n != 1 {
		t.Errorf("enroll calls = %d, want 1", n)
	}
}

// TestEnrollServerFromState: flag empty + the state config has a
// ServerURL (partial state: URL present, credential missing) → that URL is
// used (the stub asserts it served the flow).
func TestEnrollServerFromState(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", "pagt_testtoken123")

	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ""
	t.Cleanup(func() { serverURL = prevServer })
	prevToken := userToken
	userToken = ""
	t.Cleanup(func() { userToken = prevToken })

	prevBrowser := openBrowserFn
	openBrowserFn = func(string) error { return nil }
	t.Cleanup(func() { openBrowserFn = prevBrowser })
	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	dir := t.TempDir()
	// Partial state: the server URL is stored, but no credential yet.
	if err := mergeConfigFile(dir, map[string]any{"serverUrl": ts.URL}); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := enrollHostForeground(dir, "test-host", nil, ""); err != nil {
		t.Fatalf("enrollHostForeground: %v", err)
	}
	if n := ts.enrollCallCount(); n != 1 {
		t.Errorf("enroll calls = %d, want 1", n)
	}
}

// TestResolveEnrollServerPrompt: flag empty + no state + interactive → the
// prompt path (the answer is used).
func TestResolveEnrollServerPrompt(t *testing.T) {
	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ""
	t.Cleanup(func() { serverURL = prevServer })

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	prevAsk := askLineFn
	prompts := 0
	askLineFn = func(prompt string) (string, error) {
		prompts++
		if !strings.HasPrefix(prompt, "control plane URL:") {
			t.Errorf("prompt = %q, want the 'control plane URL:' prompt", prompt)
		}
		return "https://prompted.example/", nil
	}
	t.Cleanup(func() { askLineFn = prevAsk })

	got, err := resolveEnrollServer(t.TempDir())
	if err != nil {
		t.Fatalf("resolveEnrollServer: %v", err)
	}
	if got != "https://prompted.example" {
		t.Fatalf("server = %q, want https://prompted.example (trailing slash trimmed)", got)
	}
	if prompts != 1 {
		t.Errorf("prompts = %d, want 1 (a non-empty answer ends the loop)", prompts)
	}
}

// TestResolveEnrollServerPromptEmptyThenAnswer: an empty answer re-prompts
// once; the second (non-empty) answer is used.
func TestResolveEnrollServerPromptEmptyThenAnswer(t *testing.T) {
	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ""
	t.Cleanup(func() { serverURL = prevServer })

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	prevAsk := askLineFn
	answers := []string{"", "https://second.example"}
	i := 0
	askLineFn = func(string) (string, error) {
		a := answers[i]
		i++
		return a, nil
	}
	t.Cleanup(func() { askLineFn = prevAsk })

	got, err := resolveEnrollServer(t.TempDir())
	if err != nil {
		t.Fatalf("resolveEnrollServer: %v", err)
	}
	if got != "https://second.example" {
		t.Fatalf("server = %q, want https://second.example", got)
	}
	if i != 2 {
		t.Errorf("prompts = %d, want 2 (empty answer re-prompts once)", i)
	}
}

// TestResolveEnrollServerPromptEmptyTwice: two empty answers → a clean
// error (no infinite loop).
func TestResolveEnrollServerPromptEmptyTwice(t *testing.T) {
	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ""
	t.Cleanup(func() { serverURL = prevServer })

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return true }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	prevAsk := askLineFn
	i := 0
	askLineFn = func(string) (string, error) {
		i++
		return "", nil
	}
	t.Cleanup(func() { askLineFn = prevAsk })

	_, err := resolveEnrollServer(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no control plane URL entered") {
		t.Fatalf("error = %v, want the 'no control plane URL entered' message", err)
	}
	if i != 2 {
		t.Errorf("prompts = %d, want 2 (one re-prompt, then error)", i)
	}
}

// TestResolveEnrollServerNoTTY: flag empty + no state + non-interactive →
// the exact clean error, and zero endpoint calls (the stub saw nothing).
func TestResolveEnrollServerNoTTY(t *testing.T) {
	withFileFallback(t)
	idp := newStubIdP(t, []string{"success"})
	ts := newStubPagnetServer(t, idp, "oidc", "pagt_testtoken123")

	t.Setenv("PAGNET_SERVER", "")
	prevServer := serverURL
	serverURL = ""
	t.Cleanup(func() { serverURL = prevServer })

	prevTTY := hasTTYFn
	hasTTYFn = func() bool { return false }
	t.Cleanup(func() { hasTTYFn = prevTTY })

	_, err := resolveEnrollServer(t.TempDir())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	want := "no control plane URL stored — run 'pagnet enroll --server <url>' first (or set --server / $PAGNET_SERVER)"
	if err.Error() != want {
		t.Fatalf("error = %q,\nwant    %q", err.Error(), want)
	}
	// Zero endpoint calls: the resolution failed before touching the server.
	if n := ts.deviceConfigCallCount(); n != 0 {
		t.Errorf("device-config calls = %d, want 0", n)
	}
	if n := ts.enrollCallCount(); n != 0 {
		t.Errorf("enroll calls = %d, want 0", n)
	}
}
