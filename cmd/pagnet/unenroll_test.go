package main

// `pagnet unenroll` state clearing (the accounts model): the host
// credential + identity must be removed exactly where `pagnet enroll`
// wrote them — the active account's config — while the user login
// token, the server URL, and the current network survive. The machine-
// wide legacy flat file is swept when it still carries identity, and a
// worker dir (account "") clears its own flat config.

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeYAMLFile(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

func assertIdentityCleared(t *testing.T, m map[string]any) {
	t.Helper()
	for _, k := range []string{"credential", "hostId", "hostName", "allowedRoots", "rootsMode"} {
		if _, ok := m[k]; ok {
			t.Errorf("identity key %q still present after unenroll", k)
		}
	}
}

func TestClearHostState_AccountModel(t *testing.T) {
	root := t.TempDir()
	accPath := filepath.Join(root, "accounts", "default", "config.yaml")
	writeYAMLFile(t, accPath, map[string]any{
		"serverUrl":      "http://127.0.0.1:18080",
		"credential":     "host_deadbeef",
		"hostId":         "h-1",
		"hostName":       "rev-host",
		"allowedRoots":   []string{"/tmp/repo"},
		"rootsMode":      "allow_list",
		"token":          "derived-user-credential",
		"currentNetwork": "net-1",
	})
	globalPath := filepath.Join(root, "config.yaml")
	writeYAMLFile(t, globalPath, map[string]any{"currentAccount": "default"})

	if err := clearHostState(root, "default"); err != nil {
		t.Fatal(err)
	}

	acc := readYAMLMap(t, accPath)
	assertIdentityCleared(t, acc)
	if acc["serverUrl"] != "http://127.0.0.1:18080" ||
		acc["token"] != "derived-user-credential" ||
		acc["currentNetwork"] != "net-1" {
		t.Errorf("unenroll must keep serverUrl/token/currentNetwork, got %v", acc)
	}
	// The machine-wide config (current account record) is untouched.
	if g := readYAMLMap(t, globalPath); g["currentAccount"] != "default" {
		t.Errorf("global currentAccount changed: %v", g)
	}
}

func TestClearHostState_LegacyFlatSweep(t *testing.T) {
	root := t.TempDir()
	// An account context exists (so the lazy migration is a no-op) AND an
	// orphaned legacy flat file still carries identity: both are cleared.
	writeYAMLFile(t, filepath.Join(root, "accounts", "work", "config.yaml"), map[string]any{
		"serverUrl":  "http://127.0.0.1:18080",
		"credential": "host_workcred",
		"hostId":     "h-2",
	})
	writeYAMLFile(t, filepath.Join(root, "config.yaml"), map[string]any{
		"currentAccount": "work",
		"credential":     "host_orphan",
		"hostId":         "h-9",
	})

	if err := clearHostState(root, "work"); err != nil {
		t.Fatal(err)
	}

	assertIdentityCleared(t, readYAMLMap(t, filepath.Join(root, "accounts", "work", "config.yaml")))
	flat := readYAMLMap(t, filepath.Join(root, "config.yaml"))
	assertIdentityCleared(t, flat)
	if flat["currentAccount"] != "work" {
		t.Errorf("flat currentAccount must survive, got %v", flat)
	}
}

func TestClearHostState_WorkerFlat(t *testing.T) {
	root := t.TempDir()
	writeYAMLFile(t, filepath.Join(root, "config.yaml"), map[string]any{
		"serverUrl":  "http://127.0.0.1:18080",
		"credential": "host_workercred",
		"hostId":     "h-3",
		"hostName":   "worker-1",
		"noScan":     true,
	})

	// account "" = a worker dir: its flat config is the one and only file.
	if err := clearHostState(root, ""); err != nil {
		t.Fatal(err)
	}

	flat := readYAMLMap(t, filepath.Join(root, "config.yaml"))
	assertIdentityCleared(t, flat)
	if flat["serverUrl"] != "http://127.0.0.1:18080" || flat["noScan"] != true {
		t.Errorf("worker flat must keep serverUrl/noScan, got %v", flat)
	}
	if _, err := os.Stat(filepath.Join(root, "accounts")); !os.IsNotExist(err) {
		t.Errorf("worker unenroll must not create an accounts dir (err=%v)", err)
	}
}

func TestClearHostState_NothingToClear(t *testing.T) {
	root := t.TempDir()
	if err := clearHostState(root, "default"); err != nil {
		t.Fatalf("absent state must not be an error: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("unenroll must not create files when there is nothing to clear: %v", entries)
	}
}

func TestClearHostState_MalformedFile(t *testing.T) {
	root := t.TempDir()
	accDir := filepath.Join(root, "accounts", "default")
	if err := os.MkdirAll(accDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A YAML sequence is not a mapping — the clear must fail, not clobber.
	if err := os.WriteFile(filepath.Join(accDir, "config.yaml"), []byte("- a\n- b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearHostState(root, "default"); err == nil {
		t.Fatal("malformed account config must be an error")
	}
}
