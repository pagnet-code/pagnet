package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// daemonFileConfig mirrors the persistent subset of Daemon stored in
// stateDir/config.yaml (written by `agentnet login`). Zero values are
// "not set" (env wins).
type daemonFileConfig struct {
	ServerURL      string   `yaml:"serverUrl"`
	Credential     string   `yaml:"credential"`
	HostID         string   `yaml:"hostId"`
	HostName       string   `yaml:"hostName"`
	AllowedRoots   []string `yaml:"allowedRoots"`
	CurrentNetwork string   `yaml:"currentNetwork"`
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
	if cfg.CurrentNetwork == "" {
		cfg.CurrentNetwork = fc.CurrentNetwork
	}
	return nil
}

// SaveCurrentNetwork persists the user's default network choice into the
// daemon state file (`agentnet network use`). It merges with the existing
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
