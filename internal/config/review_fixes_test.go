package config

// Regression tests for the section-by-section review fixes (config scope).

import (
	"os"
	"path/filepath"
	"testing"
)

// F1: the daemon must NOT os.Setenv values from the env files —
// deploy/.env carries control-plane secrets (DATABASE_URL,
// PAGNET_ADMIN_TOKEN) and the daemon spawns untrusted agent processes.
// The daemon only READS its own keys from the files.
func TestLoadDaemon_DoesNotSetenvEnvFileValues(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(".env", []byte(
		"PAGNET_SERVER=http://127.0.0.1:19999\n"+
			"DATABASE_URL=postgres://must-not-leak\n"+
			"PAGNET_ADMIN_TOKEN=must-not-leak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force a clean slate for the keys the test asserts on.
	t.Setenv("PAGNET_SERVER", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PAGNET_ADMIN_TOKEN", "")

	cfg, err := LoadDaemon(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if cfg.ServerURL != "http://127.0.0.1:19999" {
		t.Fatalf("ServerURL = %q, want the .env value (files still feed daemon keys)", cfg.ServerURL)
	}
	if os.Getenv("DATABASE_URL") != "" {
		t.Fatal("DATABASE_URL must NOT be set in the daemon process env")
	}
	if os.Getenv("PAGNET_ADMIN_TOKEN") != "" {
		t.Fatal("PAGNET_ADMIN_TOKEN must NOT be set in the daemon process env")
	}
	if os.Getenv("PAGNET_SERVER") != "" {
		t.Fatal("PAGNET_SERVER must NOT be set in the daemon process env")
	}
}

// F1: process environment still wins over the env files.
func TestLoadDaemon_ProcessEnvWinsOverFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(".env", []byte("PAGNET_SERVER=http://from-file:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAGNET_SERVER", "http://from-env:2")
	cfg, err := LoadDaemon(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("LoadDaemon: %v", err)
	}
	if cfg.ServerURL != "http://from-env:2" {
		t.Fatalf("ServerURL = %q, want process env to win", cfg.ServerURL)
	}
}
