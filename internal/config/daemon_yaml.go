package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// daemonFileConfig mirrors the persistent subset of Daemon stored in
// stateDir/config.yaml (written by `agentnet login`). Zero values are
// "not set" (env wins).
type daemonFileConfig struct {
	ServerURL    string   `yaml:"serverUrl"`
	Credential   string   `yaml:"credential"`
	HostID       string   `yaml:"hostId"`
	HostName     string   `yaml:"hostName"`
	AllowedRoots []string `yaml:"allowedRoots"`
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
	return nil
}
