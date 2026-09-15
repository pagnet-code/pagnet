package runtime

// Regression tests for the section-by-section review fixes (runtime scope).

import (
	"strings"
	"testing"
)

// F1: spawned runtime processes must never inherit control-plane
// material from the daemon's environment (spec §86.10) — but explicit
// pairs (adapter knobs, per-instance injection) always pass through, and
// provider API keys keep flowing.
func TestChildEnv_FiltersControlPlaneKeys(t *testing.T) {
	t.Setenv("PAGNET_ADMIN_TOKEN", "admin-secret")
	t.Setenv("PAGNET_HOSTNAME_X", "whatever")
	t.Setenv("DATABASE_URL", "postgres://secret")
	t.Setenv("TEST_DATABASE_URL", "postgres://secret")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("ANTHROPIC_API_KEY", "provider-key")

	env := ChildEnv()
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if isControlPlaneEnvKey(key) {
			t.Fatalf("control-plane key leaked to child env: %q", key)
		}
	}
	for _, want := range []string{"ANTHROPIC_API_KEY=provider-key"} {
		found := false
		for _, kv := range env {
			if kv == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q must survive the filter", want)
		}
	}

	// Explicit extra pairs (e.g. the daemon's fake-runtime simulation
	// knobs, the per-instance PAGNET_* injection) always reach the child.
	env2 := ChildEnv([]string{"PAGNET_FAKE_RATELIMIT=0.5"},
		[]string{"PAGNET_INSTANCE_ID=inst-1"})
	for _, want := range []string{"PAGNET_FAKE_RATELIMIT=0.5", "PAGNET_INSTANCE_ID=inst-1"} {
		found := false
		for _, kv := range env2 {
			if kv == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("explicit pair %q must be appended", want)
		}
	}
}

// TestChildEnv_AllowlistDropsUserSecrets (external audit F-009): the
// inherited-environment filter is an ALLOWLIST, not a blocklist. A
// blocklist would leak the user's shell secrets (GH_TOKEN, AWS_*,
// SSH_AUTH_SOCK, ...) to an untrusted agent. Verify those are dropped
// while the keys a runtime needs (PATH, HOME, provider auth) survive.
func TestChildEnv_AllowlistDropsUserSecrets(t *testing.T) {
	t.Setenv("GH_TOKEN", "gh-secret")
	t.Setenv("GITHUB_TOKEN", "gh-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh")
	t.Setenv("SOME_RANDOM_USER_VAR", "not-needed")
	t.Setenv("ANTHROPIC_API_KEY", "provider-key")

	env := ChildEnv()
	leaked := map[string]bool{}
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		leaked[key] = true
	}
	for _, secret := range []string{"GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "SOME_RANDOM_USER_VAR"} {
		if leaked[secret] {
			t.Errorf("user secret %q leaked to child env (must be dropped by the allowlist)", secret)
		}
	}
	// Provider auth must survive (the runtime needs it).
	if !leaked["ANTHROPIC_API_KEY"] {
		t.Errorf("ANTHROPIC_API_KEY must survive the allowlist")
	}
}
