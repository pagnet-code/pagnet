package runtime

import (
	"fmt"
	"os"
	"strings"
)

// ChildEnv builds the environment for a spawned runtime process.
//
// The inherited environment is ALLOWLISTED before anything else is
// appended: runtime processes are untrusted (an LLM with shell access),
// and the daemon's own environment — and the user's shell environment —
// may carry secrets that must never be readable from an agent (spec
// §5/§15/§86.10; external audit F-009). A blocklist is inherently
// incomplete (it would leak GH_TOKEN, AWS_*, SSH_AUTH_SOCK, ...), so the
// filter is fail-closed: only the keys a runtime actually needs (PATH,
// HOME, locale, provider auth) pass through; everything else is dropped.
//
// Explicit pairs passed by the caller (adapter knobs, per-instance
// injection like the MCP bridge config and the identity vars) are
// appended after the filter, in order, and always win — they are
// pagnet's own, deliberately-injected values, not inherited secrets.
func ChildEnv(extra ...[]string) []string {
	out := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		// Fail closed: only allowlisted keys pass. isControlPlaneEnvKey is
		// kept as defense-in-depth (a control-plane key is never allowed,
		// even if it were ever added to the allowlist by mistake).
		if !ok || !isAllowedChildEnvKey(key) || isControlPlaneEnvKey(key) {
			continue
		}
		out = append(out, kv)
	}
	for _, pairs := range extra {
		out = append(out, pairs...)
	}
	return out
}

// allowedChildEnvExact is the exact-match allowlist of inherited keys that
// may reach an agent process: the minimal set a runtime CLI needs to run
// (PATH, HOME, identity, locale, terminal, temp dir, XDG) plus the provider
// auth keys / base-URL overrides the runtimes use to reach their LLM
// provider. Anything not listed here is dropped (external audit F-009).
var allowedChildEnvExact = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TERM": true, "COLUMNS": true, "LINES": true, "TMPDIR": true,
	"TZ": true, "LANG": true, "LANGUAGE": true,
	"XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true,
	"XDG_STATE_HOME": true, "XDG_RUNTIME_DIR": true,
	// Provider auth (the runtimes need these to reach their LLM provider).
	"ANTHROPIC_API_KEY": true, "ANTHROPIC_BASE_URL": true,
	"DASHSCOPE_API_KEY": true, "DASHSCOPE_BASE_URL": true,
	"OPENAI_API_KEY": true, "OPENAI_BASE_URL": true,
	"OPENROUTER_API_KEY": true, "OPENROUTER_BASE_URL": true,
	"GEMINI_API_KEY": true, "GROQ_API_KEY": true, "MISTRAL_API_KEY": true,
	"TOGETHER_API_KEY": true, "FIREWORKS_API_KEY": true,
	"PERPLEXITY_API_KEY": true, "DEEPSEEK_API_KEY": true,
}

// allowedChildEnvPrefix is the prefix allowlist (the LC_* locale family).
var allowedChildEnvPrefix = []string{"LC_"}

// isAllowedChildEnvKey reports whether an inherited env key may reach an
// agent process (exact match or prefix match against the allowlists).
func isAllowedChildEnvKey(key string) bool {
	if allowedChildEnvExact[key] {
		return true
	}
	for _, p := range allowedChildEnvPrefix {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// EnsureTurnMarker guarantees the ownership-marker pair
// PAGNET_TURN_ID=<turnID> is present exactly once in env (abuse addendum
// Part B §42). The marker is the process-tree ownership proof the
// supervisor stores in the ownership record for restart reconciliation
// and for diagnostics. It is appended when absent (the daemon may already
// have injected it via the turn spec's Env; a duplicate is never added).
func EnsureTurnMarker(env []string, turnID string) []string {
	if turnID == "" {
		return env
	}
	pair := "PAGNET_TURN_ID=" + turnID
	for _, kv := range env {
		if kv == pair {
			return env
		}
	}
	return append(env, pair)
}

// isControlPlaneEnvKey reports whether an inherited env key must not reach
// an agent process: pagnet's own configuration/credentials, plus
// database connection strings.
func isControlPlaneEnvKey(key string) bool {
	switch {
	case strings.HasPrefix(key, "PAGNET_"):
		return true
	case key == "DATABASE_URL" || key == "TEST_DATABASE_URL":
		return true
	case strings.HasPrefix(key, "POSTGRES_") || strings.HasPrefix(key, "PGPASS"):
		return true
	}
	return false
}

// ValidateExtraEnv applies the control-plane blocklist to the
// operator-supplied runtime env pairs (PAGNET_RUNTIME_ENV / config
// runtime_env) (SEC-410): these pairs are appended AFTER the ChildEnv
// filter, so without this check they could re-inject exactly the keys the
// filter removes (PAGNET_* credentials, DATABASE_URL, POSTGRES_*). The
// documented PAGNET_FAKE_* fake-runtime simulation namespace is the only
// PAGNET_ exception. A violation is a hard error (fail closed — the daemon
// refuses to start) rather than a silent drop.
func ValidateExtraEnv(pairs []string) error {
	var blocked []string
	for _, kv := range pairs {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			blocked = append(blocked, kv)
			continue
		}
		if strings.HasPrefix(key, "PAGNET_FAKE_") {
			continue
		}
		if isControlPlaneEnvKey(key) {
			blocked = append(blocked, key)
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("runtime env pairs are not allowed: %s — control-plane keys cannot be injected into agent processes",
			strings.Join(blocked, ", "))
	}
	return nil
}
