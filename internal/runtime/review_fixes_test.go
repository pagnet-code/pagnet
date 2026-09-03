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
	t.Setenv("AGENTNET_ADMIN_TOKEN", "admin-secret")
	t.Setenv("AGENTNET_HOSTNAME_X", "whatever")
	t.Setenv("DATABASE_URL", "postgres://secret")
	t.Setenv("TEST_DATABASE_URL", "postgres://secret")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("ANTHROPIC_API_KEY", "provider-key")
	t.Setenv("KEEP_ME", "yes")

	env := ChildEnv()
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if isControlPlaneEnvKey(key) {
			t.Fatalf("control-plane key leaked to child env: %q", key)
		}
	}
	for _, want := range []string{"ANTHROPIC_API_KEY=provider-key", "KEEP_ME=yes"} {
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
	// knobs, the per-instance AGENTNET_* injection) always reach the child.
	env2 := ChildEnv([]string{"AGENTNET_FAKE_RATELIMIT=0.5"},
		[]string{"AGENTNET_INSTANCE_ID=inst-1"})
	for _, want := range []string{"AGENTNET_FAKE_RATELIMIT=0.5", "AGENTNET_INSTANCE_ID=inst-1"} {
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
