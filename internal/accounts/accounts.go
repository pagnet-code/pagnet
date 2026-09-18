// Package accounts manages the CLI's Pagnet account contexts.
//
// The CLI may hold several Pagnet accounts (personal/work) for the same
// server URL. An account is a directory under <state-dir>/accounts/<name>/
// holding its own config.yaml (serverUrl, host identity + credential,
// current network, the user's derived client credential). The machine-wide
// <state-dir>/config.yaml holds only the CURRENT account and account
// labels — never a credential or a host identity.
//
// One account may have its own enrollment of this machine (personal → Host
// A, work → Host B on the same box is legitimate); host IDs/credentials
// never leak across accounts.
//
// Backward compatibility: existing users have a legacy FLAT
// <state-dir>/config.yaml (serverUrl, credential, hostId, ...). MigrateLegacy
// performs a small lazy/one-time migration: when legacy state exists and no
// account contexts do, the current state becomes the "default" account
// context, preserving every field (no credential loss, no manual moves).
package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultAccount is the account context the legacy flat state migrates to
// and the fallback when no current account is recorded.
const DefaultAccount = "default"

// accountsDirName is the subdirectory of the state dir holding account
// contexts.
const accountsDirName = "accounts"

// nameRe constrains account names to a filesystem- and CLI-safe slug.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Global is the machine-wide config (<state-dir>/config.yaml): the current
// account and per-account display labels. It holds NO credential and NO
// host identity.
type Global struct {
	// CurrentAccount is the active account context name.
	CurrentAccount string `yaml:"currentAccount,omitempty"`
	// Labels maps an account name to an optional display label (e.g.
	// "work"). Empty labels fall back to the account name.
	Labels map[string]string `yaml:"labels,omitempty"`
}

// ValidateName reports whether name is a usable account context name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return errors.New("account names must be lowercase alphanumeric (plus . _ -), starting with a letter or digit, max 64 chars")
	}
	return nil
}

// AccountsDir returns <root>/accounts.
func AccountsDir(root string) string {
	return filepath.Join(root, accountsDirName)
}

// ConfigDir returns the account context's directory: <root>/accounts/<name>.
func ConfigDir(root, name string) string {
	return filepath.Join(AccountsDir(root), name)
}

// ConfigPath returns the account context's config file path.
func ConfigPath(root, name string) string {
	return filepath.Join(ConfigDir(root, name), "config.yaml")
}

// globalPath returns the machine-wide config file path.
func globalPath(root string) string {
	return filepath.Join(root, "config.yaml")
}

// LoadGlobal reads the machine-wide config (currentAccount, labels). A
// missing or empty file yields a zero Global (CurrentAccount empty → the
// caller falls back to DefaultAccount).
func LoadGlobal(root string) (Global, error) {
	var g Global
	b, err := os.ReadFile(globalPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return g, nil
		}
		return g, err
	}
	if err := yaml.Unmarshal(b, &g); err != nil {
		return g, err
	}
	return g, nil
}

// SaveGlobal writes the machine-wide config (atomic, 0600).
func SaveGlobal(root string, g Global) error {
	b, err := yaml.Marshal(&g)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	return writeFileAtomic0600(globalPath(root), b)
}

// ActiveAccount resolves the active account name: the explicit override
// (the --account flag, when set), else the global config's currentAccount,
// else DefaultAccount.
func ActiveAccount(root, override string) string {
	if override != "" {
		return override
	}
	if g, err := LoadGlobal(root); err == nil && g.CurrentAccount != "" {
		return g.CurrentAccount
	}
	return DefaultAccount
}

// SetCurrent records account as the current account in the global config,
// preserving any existing labels.
func SetCurrent(root, account string) error {
	if err := ValidateName(account); err != nil {
		return err
	}
	g, err := LoadGlobal(root)
	if err != nil {
		return err
	}
	g.CurrentAccount = account
	return SaveGlobal(root, g)
}

// SetLabel records a display label for account in the global config.
func SetLabel(root, account, label string) error {
	if err := ValidateName(account); err != nil {
		return err
	}
	g, err := LoadGlobal(root)
	if err != nil {
		return err
	}
	if g.Labels == nil {
		g.Labels = map[string]string{}
	}
	if label == "" {
		delete(g.Labels, account)
	} else {
		g.Labels[account] = label
	}
	return SaveGlobal(root, g)
}

// List returns the account context names under <root>/accounts, sorted.
// An absent/empty accounts dir yields an empty slice.
func List(root string) ([]string, error) {
	entries, err := os.ReadDir(AccountsDir(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// Exists reports whether the account context directory exists.
func Exists(root, name string) bool {
	info, err := os.Stat(ConfigDir(root, name))
	return err == nil && info.IsDir()
}

// MigrateLegacy performs the one-time legacy migration. When the state dir
// holds a legacy FLAT config.yaml (server/credential/host fields) and no
// account contexts exist, the legacy state becomes the DefaultAccount
// context: its config.yaml is copied to accounts/default/config.yaml (every
// field preserved, including the user credential fallback and metadata),
// and the machine-wide config.yaml is rewritten to hold only the current
// account. The migration is idempotent: once accounts/default exists it is
// a no-op, and a state dir with no legacy content is left untouched.
//
// It returns true when it migrated, false otherwise.
func MigrateLegacy(root string) (bool, error) {
	// Already migrated (or the user created account contexts): no-op.
	if names, err := List(root); err != nil {
		return false, err
	} else if len(names) > 0 {
		return false, nil
	}
	// Read the legacy flat config.
	b, err := os.ReadFile(globalPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // no legacy config, nothing to migrate
		}
		return false, err
	}
	var legacy map[string]any
	if err := yaml.Unmarshal(b, &legacy); err != nil {
		return false, nil // not a mapping; leave it alone
	}
	if len(legacy) == 0 {
		return false, nil
	}
	// Only migrate a config that looks like the legacy flat daemon config
	// (it carries a server, a host credential/identity, or a user token).
	// A config that already holds only currentAccount/labels is not legacy.
	isLegacy := false
	for _, k := range []string{"serverUrl", "credential", "hostId", "hostName", "token"} {
		if _, ok := legacy[k]; ok {
			isLegacy = true
			break
		}
	}
	if !isLegacy {
		return false, nil
	}
	// Create accounts/default/config.yaml with the legacy content verbatim
	// (a copy, not a move — the original bytes are preserved exactly).
	defDir := ConfigDir(root, DefaultAccount)
	if err := os.MkdirAll(defDir, 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(ConfigPath(root, DefaultAccount), b, 0o600); err != nil {
		return false, err
	}
	// Rewrite the machine-wide config to hold only the current account.
	g := Global{CurrentAccount: DefaultAccount}
	if err := SaveGlobal(root, g); err != nil {
		return false, err
	}
	return true, nil
}

// writeFileAtomic0600 writes b to path atomically (temp file in the same
// directory, fsync, rename) with mode 0600.
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

// TrimServer normalizes a server URL for use in a keyring key (no trailing
// slash). Exported so the CLI's credential storage scopes keys consistently.
func TrimServer(server string) string {
	return strings.TrimSuffix(server, "/")
}
