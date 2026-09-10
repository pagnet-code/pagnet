package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// daemonFileConfig mirrors the persistent subset of Daemon stored in
// stateDir/config.yaml (written by `pagnet login`). Zero values are
// "not set" (env wins).
type daemonFileConfig struct {
	ServerURL      string   `yaml:"serverUrl"`
	Credential     string   `yaml:"credential"`
	HostID         string   `yaml:"hostId"`
	HostName       string   `yaml:"hostName"`
	AllowedRoots   []string `yaml:"allowedRoots"`
	RootsMode      string   `yaml:"rootsMode"`
	CurrentNetwork string   `yaml:"currentNetwork"`
	// NoScan disables automatic git discovery. The file can only set it
	// true (zero value = scan ON, so "false" is indistinguishable from
	// absent); re-enabling goes through `pagnet worker --scan`, which
	// rewrites the file explicitly.
	NoScan bool `yaml:"noScan"`
	// Debug enables development/test-only behavior (registers the
	// deterministic fake runtime). The file can only set it true (zero
	// value = off); a production state file leaves it absent.
	Debug bool `yaml:"debug"`
	// AutoUpdate is worker self-update (P6). A pointer: the default is
	// ON, so only an EXPLICIT `autoUpdate: false` in the state file
	// disables it (absent = default ON — unlike the bool fields above,
	// where false is the zero value and indistinguishable from absent).
	AutoUpdate *bool `yaml:"autoUpdate"`
}

func loadDaemonYAML(path string, cfg *Daemon) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var fc daemonFileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return err
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = fc.ServerURL
	}
	if cfg.Credential == "" {
		cfg.Credential = fc.Credential
	}
	if cfg.HostID == "" {
		cfg.HostID = fc.HostID
	}
	if cfg.HostName == "" {
		cfg.HostName = fc.HostName
	}
	if len(cfg.AllowedRoots) == 0 {
		cfg.AllowedRoots = fc.AllowedRoots
	}
	if cfg.RootsMode == "" {
		cfg.RootsMode = fc.RootsMode
	}
	if cfg.CurrentNetwork == "" {
		cfg.CurrentNetwork = fc.CurrentNetwork
	}
	if fc.NoScan {
		cfg.NoScan = true
	}
	if fc.Debug {
		cfg.Debug = true
	}
	// Only an explicit `autoUpdate: false` disables (default ON, P6);
	// `autoUpdate: true` and an absent key both keep it enabled.
	if fc.AutoUpdate != nil && !*fc.AutoUpdate {
		cfg.AutoUpdate = false
	}
	return nil
}

// SaveCurrentNetwork persists the user's default network choice into the
// daemon state file (`pagnet network use`). It merges with the existing
// config rather than rewriting the whole file.
func SaveCurrentNetwork(stateDir, network string) error {
	path := filepath.Join(stateDir, "config.yaml")
	var fc daemonFileConfig
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, &fc); err != nil {
			return err
		}
	}
	fc.CurrentNetwork = network
	b, err := yaml.Marshal(&fc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
