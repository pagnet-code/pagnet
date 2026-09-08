package config

// §72 negative tests (config scope).

import (
	"strings"
	"testing"
)

// TestLoadDaemonRefusesControlPlaneRuntimeEnv (SEC-410): operator-supplied
// runtime env pairs can be appended AFTER the ChildEnv filter, so they must
// pass the blocklist — otherwise the daemon refuses to start (fail closed,
// not a silent drop).
func TestLoadDaemonRefusesControlPlaneRuntimeEnv(t *testing.T) {
	cases := []string{
		"DATABASE_URL=postgres://x",
		"PAGNET_ADMIN_TOKEN=supersecret",
		"POSTGRES_PASSWORD=supersecret",
		"=novalue",
	}
	for _, env := range cases {
		t.Setenv("PAGNET_RUNTIME_ENV", env)
		if _, err := LoadDaemon(t.TempDir()); err == nil {
			t.Fatalf("LoadDaemon accepted runtime env %q, want refusal", env)
		} else if !strings.Contains(err.Error(), "runtime env") {
			t.Fatalf("LoadDaemon(%q) → %v, want runtime-env refusal", env, err)
		}
	}
}

// TestLoadDaemonAllowsDocumentedRuntimeEnv: the documented PAGNET_FAKE_*
// simulation namespace and plain non-control-plane keys keep working.
func TestLoadDaemonAllowsDocumentedRuntimeEnv(t *testing.T) {
	t.Setenv("PAGNET_RUNTIME_ENV", "PAGNET_FAKE_LATENCY_MS=50,MY_CUSTOM_VAR=1")
	cfg, err := LoadDaemon(t.TempDir())
	if err != nil {
		t.Fatalf("LoadDaemon rejected allowed runtime env: %v", err)
	}
	if len(cfg.RuntimeEnv) != 2 {
		t.Fatalf("RuntimeEnv = %v, want both pairs", cfg.RuntimeEnv)
	}
}
