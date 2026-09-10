package config

// AutoUpdate (P6 worker auto-update): ON by default, opt-out via
// PAGNET_AUTO_UPDATE=0/false/off/no or the state file's
// `autoUpdate: false`. Zero value here means ON (the inverse of NoScan).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDaemon_AutoUpdateDefaultsOn(t *testing.T) {
	t.Setenv("PAGNET_AUTO_UPDATE", "")
	cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if !cfg.AutoUpdate {
		t.Fatal("AutoUpdate must default to true (opt-out)")
	}
}

func TestLoadDaemon_AutoUpdateFromEnv(t *testing.T) {
	for _, v := range []string{"0", "false", "off", "no", "OFF", "No"} {
		t.Run("off/"+v, func(t *testing.T) {
			t.Setenv("PAGNET_AUTO_UPDATE", v)
			cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatalf("LoadDaemon: %v", err)
			}
			if cfg.AutoUpdate {
				t.Fatalf("PAGNET_AUTO_UPDATE=%s must disable AutoUpdate", v)
			}
		})
	}
	for _, v := range []string{"1", "true", "on", "yes", "garbage"} {
		t.Run("on/"+v, func(t *testing.T) {
			t.Setenv("PAGNET_AUTO_UPDATE", v)
			cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatalf("LoadDaemon: %v", err)
			}
			if !cfg.AutoUpdate {
				t.Fatalf("PAGNET_AUTO_UPDATE=%s must keep AutoUpdate ON", v)
			}
		})
	}
}

func TestLoadDaemon_AutoUpdateFromStateFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"),
		[]byte("autoUpdate: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_AUTO_UPDATE", "")
	cfg, err := LoadDaemon(state)
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if cfg.AutoUpdate {
		t.Fatal("state file autoUpdate: false must disable AutoUpdate")
	}
}

func TestLoadDaemon_AutoUpdateFileTrueKeepsOn(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"),
		[]byte("autoUpdate: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_AUTO_UPDATE", "")
	cfg, err := LoadDaemon(state)
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if !cfg.AutoUpdate {
		t.Fatal("state file autoUpdate: true must keep AutoUpdate ON")
	}
}

func TestLoadDaemon_AutoUpdateAbsentKeepsOn(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// A state file WITHOUT the key: default ON (only an explicit false
	// disables — the pointer distinguishes absent from false).
	if err := os.WriteFile(filepath.Join(state, "config.yaml"),
		[]byte("hostName: worker-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_AUTO_UPDATE", "")
	cfg, err := LoadDaemon(state)
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if !cfg.AutoUpdate {
		t.Fatal("an absent autoUpdate key must keep AutoUpdate ON")
	}
}
