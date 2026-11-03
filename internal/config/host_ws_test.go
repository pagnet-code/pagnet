package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDaemonHostWSIPv4Only(t *testing.T) {
	// Isolate the default from developer env files.
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		value   string
		want    bool
		invalid bool
	}{
		{"", false, false},
		{"false", false, false},
		{"true", true, false},
		{"1", true, false},
		{"garbage", false, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("PAGNET_HOST_WS_IPV4_ONLY", tc.value)
			cfg, err := LoadDaemon(filepath.Join(t.TempDir(), "state"))
			if (err != nil) != tc.invalid {
				t.Fatalf("LoadDaemon error = %v, invalid = %v", err, tc.invalid)
			}
			if cfg.HostWSIPv4Only != tc.want {
				t.Fatalf("HostWSIPv4Only = %v, want %v", cfg.HostWSIPv4Only, tc.want)
			}
		})
	}
}

func TestLoadDaemonHostWSIPv4OnlyEnvFile(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PAGNET_HOST_WS_IPV4_ONLY", "")
	if err := os.WriteFile(".env", []byte("PAGNET_HOST_WS_IPV4_ONLY=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDaemon(t.TempDir())
	if err != nil || !cfg.HostWSIPv4Only {
		t.Fatalf("env file: enabled = %v, error = %v", cfg.HostWSIPv4Only, err)
	}
	t.Setenv("PAGNET_HOST_WS_IPV4_ONLY", "false")
	cfg, err = LoadDaemon(t.TempDir())
	if err != nil || cfg.HostWSIPv4Only {
		t.Fatalf("environment override: enabled = %v, error = %v", cfg.HostWSIPv4Only, err)
	}
}
