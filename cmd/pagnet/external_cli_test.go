package main

import (
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/sdk"
)

func saveExternalTestProfile(t *testing.T, dir, name string) {
	t.Helper()
	p := externalprofile.Profile{
		Version:    1,
		Principal:  "01900000-0000-7000-8000-000000000002",
		Network:    "01900000-0000-7000-8000-000000000001",
		Server:     "https://app.pagnet.dev",
		Credential: "pgn_act_v1_test",
		Grants:     []string{"01900000-0000-7000-8000-000000000002/hello.say"},
		Events:     []string{"task.*"},
	}
	path, err := externalprofile.Path(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := externalprofile.SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
}

func TestExternalCommandSurface(t *testing.T) {
	cmd := externalCmd()
	want := []string{"identity", "search", "invoke", "invocation-get", "ask", "ask-get", "events"}
	seen := map[string]bool{}
	for _, sub := range cmd.Commands() {
		seen[sub.Name()] = true
	}
	for _, name := range want {
		if !seen[name] {
			t.Fatalf("missing verb %q: %v", name, seen)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("unexpected verbs: %v", seen)
	}
}

func TestResolveExternalAuth(t *testing.T) {
	never := func(string) bool { return false }
	t.Setenv(sdk.EnvCredential, "")

	// No profile, no env credential: a clear setup error.
	if _, _, _, _, err := resolveExternalAuth(t.TempDir(), "", "", nil, nil, nil, never); err == nil || !strings.Contains(err.Error(), "no external profile") {
		t.Fatalf("no auth source: %v", err)
	}

	// $PAGNET_CREDENTIAL mode requires --network and carries the flag policy.
	t.Setenv(sdk.EnvCredential, "pgn_act_v1_test")
	if _, _, _, _, err := resolveExternalAuth(t.TempDir(), "", "", nil, nil, nil, never); err == nil || !strings.Contains(err.Error(), "--network") {
		t.Fatalf("env mode without network: %v", err)
	}
	_, cfg, sdkCfg, expected, err := resolveExternalAuth(t.TempDir(), "", "01900000-0000-7000-8000-000000000001", nil, nil, nil, never)
	if err != nil || cfg.Network != "01900000-0000-7000-8000-000000000001" || sdkCfg.Credential != "pgn_act_v1_test" || expected != "" {
		t.Fatalf("env mode: cfg=%#v credential=%q expected=%q err=%v", cfg, sdkCfg.Credential, expected, err)
	}

	// Saved-profile mode: explicit name, overrides refused, single auto-select,
	// multiple names refused.
	t.Setenv(sdk.EnvCredential, "")
	dir := t.TempDir()
	saveExternalTestProfile(t, dir, "solo")

	if _, _, _, _, err := resolveExternalAuth(dir, "solo", "", nil, nil, nil, func(string) bool { return true }); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("profile + overrides: %v", err)
	}
	p, cfg, sdkCfg, expected, err := resolveExternalAuth(dir, "solo", "", nil, nil, nil, never)
	if err != nil || p == nil || p.Principal != "01900000-0000-7000-8000-000000000002" || cfg.Network != "01900000-0000-7000-8000-000000000001" || sdkCfg.Server != "https://app.pagnet.dev" || expected != p.Principal {
		t.Fatalf("explicit profile: p=%#v cfg=%#v server=%q expected=%q err=%v", p, cfg, sdkCfg.Server, expected, err)
	}
	if p.Grants == nil || len(p.Events) != 1 {
		t.Fatalf("profile policy not preserved: %#v", p)
	}
	if _, _, _, _, err := resolveExternalAuth(dir, "", "", nil, nil, nil, never); err != nil {
		t.Fatalf("single profile auto-select: %v", err)
	}
	saveExternalTestProfile(t, dir, "other")
	if _, _, _, _, err := resolveExternalAuth(dir, "", "", nil, nil, nil, never); err == nil || !strings.Contains(err.Error(), "multiple external profiles") {
		t.Fatalf("multiple profiles: %v", err)
	}
}
