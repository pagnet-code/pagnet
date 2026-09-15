package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSaveCurrentNetworkPreservesUnknownKeys (external audit F-007): the
// state file is user-owned and may carry keys this version does not know
// about. SaveCurrentNetwork must set currentNetwork WITHOUT dropping the
// unknown keys a typed-struct round-trip would silently lose.
func TestSaveCurrentNetworkPreservesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// A config with a known key (serverUrl), an unknown key
	// (futureFeature), and a nested unknown value.
	seed := "serverUrl: https://example.test\nfutureFeature: {enabled: true, level: 3}\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveCurrentNetwork(dir, "prod"); err != nil {
		t.Fatalf("SaveCurrentNetwork: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if m["currentNetwork"] != "prod" {
		t.Errorf("currentNetwork = %v, want prod", m["currentNetwork"])
	}
	if m["serverUrl"] != "https://example.test" {
		t.Errorf("serverUrl = %v, want https://example.test (known key lost)", m["serverUrl"])
	}
	if _, ok := m["futureFeature"]; !ok {
		t.Errorf("unknown key futureFeature was DROPPED (F-007): file = %s", b)
	}
	// The nested unknown value must survive intact.
	ff, ok := m["futureFeature"].(map[string]any)
	if !ok {
		t.Fatalf("futureFeature not a mapping: %T", m["futureFeature"])
	}
	if ff["enabled"] != true || ff["level"] != int(3) {
		t.Errorf("futureFeature value altered: %v", ff)
	}
}

// TestSaveCurrentNetworkTightens0644To0600 (external audit F-008): a state
// file left world-readable (0644) must be tightened to 0600 on re-save.
// os.WriteFile alone keeps the existing loose mode; the atomic writer
// creates a fresh 0600 file and renames it into place.
func TestSaveCurrentNetworkTightens0644To0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("serverUrl: https://example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveCurrentNetwork(dir, "prod"); err != nil {
		t.Fatalf("SaveCurrentNetwork: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode after re-save = %o, want 0600", perm)
	}
}

// TestSaveCurrentNetworkNewFile (external audit F-008): saving into a
// fresh state dir creates a 0600 file with the currentNetwork key.
func TestSaveCurrentNetworkNewFile(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCurrentNetwork(dir, "staging"); err != nil {
		t.Fatalf("SaveCurrentNetwork: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "currentNetwork: staging") {
		t.Errorf("new file missing currentNetwork: %s", b)
	}
	fi, _ := os.Stat(filepath.Join(dir, "config.yaml"))
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("new config mode = %o, want 0600", perm)
	}
}
