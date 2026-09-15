package config

import (
	"bytes"
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
//
// The round-trip goes through a generic yaml.Node, NOT the typed
// daemonFileConfig struct: the state file is user-owned and may carry keys
// this version does not know about, and a typed round-trip would silently
// DROP them (external audit F-007). Only the currentNetwork key is set;
// every other key is preserved verbatim.
//
// The write is atomic (temp+rename) and 0600 (external audit F-008): a
// crash mid-write must not corrupt the config, and re-saving a file that
// was left world-readable (0644) tightens it back to 0600 — os.WriteFile
// alone would keep the existing loose mode.
func SaveCurrentNetwork(stateDir, network string) error {
	path := filepath.Join(stateDir, "config.yaml")
	var doc yaml.Node
	if b, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(b)) > 0 {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return err
		}
	}
	// Locate (or create) the top-level mapping node.
	var mapping *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		mapping = doc.Content[0]
	}
	if mapping == nil {
		mapping = &yaml.Node{Kind: yaml.MappingNode}
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{mapping}}
	}
	// Set currentNetwork: update in place if present, else append.
	const keyName = "currentNetwork"
	set := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: network}
	found := false
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == keyName {
			mapping.Content[i+1] = set
			found = true
			break
		}
	}
	if !found {
		mapping.Content = append(mapping.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: keyName},
			set,
		)
	}
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic0600(path, b)
}

// writeFileAtomic0600 writes b to path atomically (temp file in the same
// directory, fsync, rename) with mode 0600. The temp file is created 0600
// and chmod'd before it is linked into place, so the result is 0600
// regardless of the previous file's mode (external audit F-008).
func writeFileAtomic0600(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
