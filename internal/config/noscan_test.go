package config

// NoScan: automatic git-repository discovery can be turned off per run
// (PAGNET_SCAN_WORKSPACES) or persisted in the state file (noScan, written
// by `pagnet worker --no-scan`). Zero value everywhere means scan ON.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDaemon_NoScanDefaultsOff(t *testing.T) {
	t.Setenv("PAGNET_SCAN_WORKSPACES", "")
	cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if cfg.NoScan {
		t.Fatal("NoScan must default to false (scan ON) with no config")
	}
}

func TestLoadDaemon_NoScanFromEnv(t *testing.T) {
	for _, v := range []string{"0", "false", "off", "no", "OFF", "No"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("PAGNET_SCAN_WORKSPACES", v)
			cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatalf("LoadDaemon: %v", err)
			}
			if !cfg.NoScan {
				t.Fatalf("PAGNET_SCAN_WORKSPACES=%s must set NoScan", v)
			}
		})
	}
	for _, v := range []string{"1", "true", "on", "yes", "garbage"} {
		t.Run("on/"+v, func(t *testing.T) {
			t.Setenv("PAGNET_SCAN_WORKSPACES", v)
			cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatalf("LoadDaemon: %v", err)
			}
			if cfg.NoScan {
				t.Fatalf("PAGNET_SCAN_WORKSPACES=%s must NOT set NoScan", v)
			}
		})
	}
}

func TestLoadDaemon_NoScanFromStateFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"),
		[]byte("noScan: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_SCAN_WORKSPACES", "")
	cfg, err := LoadDaemon(state)
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if !cfg.NoScan {
		t.Fatal("state file noScan: true must be picked up")
	}
}

func TestLoadDaemon_NoScanFileFalseIsNoop(t *testing.T) {
	// An explicit noScan: false (written by `pagnet worker --scan` to
	// clear a stored --no-scan) is a no-op: false is the default and
	// can never turn scanning off.
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"),
		[]byte("noScan: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_SCAN_WORKSPACES", "")
	cfg, err := LoadDaemon(state)
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if cfg.NoScan {
		t.Fatal("noScan: false must keep scanning ON")
	}
}
