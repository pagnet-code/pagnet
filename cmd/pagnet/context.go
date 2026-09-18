package main

// Account-aware context resolution: the machine-wide state dir, the active
// account, the account's config, and the control-plane URL precedence.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/internal/config"
)

// machineStateDir resolves the machine-wide state dir: the --state-dir
// override when given, else ~/.pagnet.
func machineStateDir(override string) string {
	if override != "" {
		return override
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".pagnet")
}

// isWorkerDir reports whether dir is a single-directory worker state dir
// (<home>/.pagnet/workers/<hash>). Workers keep a FLAT config in their own
// dir and do not use account contexts (they are a separate, simpler flow).
func isWorkerDir(dir string) bool {
	home, _ := os.UserHomeDir()
	workersRoot := filepath.Join(home, ".pagnet", "workers")
	return strings.HasPrefix(dir, workersRoot+string(os.PathSeparator))
}

// loadAccountConfig loads the daemon config for the machine-wide state dir
// root: the ACTIVE account's config (serverUrl, credential, hostId, ...)
// with root as cfg.StateDir (the daemon's machine-wide state: sqlite, sock,
// log). It performs the one-time legacy migration first. For a worker dir
// (no account contexts) it loads the flat config directly.
//
// It returns the config and the active account name ("" for workers).
func loadAccountConfig(root string) (config.Daemon, string, error) {
	if isWorkerDir(root) {
		cfg, err := config.LoadDaemon(root)
		return cfg, "", err
	}
	if _, err := accounts.MigrateLegacy(root); err != nil {
		return config.Daemon{}, "", err
	}
	acc := accounts.ActiveAccount(root, accountFlag)
	accDir := accounts.ConfigDir(root, acc)
	cfg, err := config.LoadDaemon(accDir)
	if err != nil {
		return config.Daemon{}, acc, err
	}
	cfg.StateDir = root // machine-wide state, not the account dir
	return cfg, acc, nil
}

// accountConfigDir returns the active account's config dir for root ("" for
// a worker dir, which uses its own flat config). Callers that write the
// account's config.yaml or its user credential use this.
func accountConfigDir(root, account string) string {
	if account == "" {
		return root // worker / flat
	}
	return accounts.ConfigDir(root, account)
}

// resolveServerURL applies the control-plane URL precedence:
//
//  1. the explicit --server flag
//  2. $PAGNET_SERVER (folded into cfg.ServerURL by LoadDaemon, which also
//     folds the env files' PAGNET_SERVER)
//  3. the persisted account config's serverUrl (cfg.ServerURL)
//  4. the build default (defaultServerURL, stamped at release-build time)
//
// cfg.ServerURL already carries precedence 2 over 3 (env wins over file),
// so this resolves the full chain. The result is trimmed of a trailing slash.
func resolveServerURL(cfg config.Daemon) string {
	if serverURL != "" {
		return strings.TrimSuffix(serverURL, "/")
	}
	if cfg.ServerURL != "" {
		return strings.TrimSuffix(cfg.ServerURL, "/")
	}
	return defaultServerURL
}

// interactiveMode reports whether the CLI may prompt a human: a TTY is
// present AND --non-interactive was not passed. --non-interactive forces
// fail-fast (never prompt, never open a browser, never wait).
func interactiveMode() bool {
	return !nonInteractive && hasTTYFn()
}

// storedServerURLRaw reads the raw serverUrl from the account's config file
// (NOT env-folded) — the server the account's host credential is tied to.
// Used for safe control-plane switching (§3): a credential stored for server
// A must never be sent to a different, explicitly selected server B.
func storedServerURLRaw(root, account string) string {
	if account == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(accounts.ConfigDir(root, account), "config.yaml"))
	if err != nil {
		return ""
	}
	var fc struct {
		ServerURL string `yaml:"serverUrl"`
	}
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return ""
	}
	return strings.TrimSuffix(fc.ServerURL, "/")
}

// ensureServerSwitch implements §3 (safe control-plane switching): if the
// resolved server differs from the serverUrl the account's host credential
// is tied to, the stored credential is stale (for the old server) and must
// NOT be sent to the new server. Non-interactive fails cleanly (never
// re-enrolls, never hangs). Interactive confirms, then runs a FRESH
// enrollment for the new server (preserving unrelated local config).
func ensureServerSwitch(root, account string, cfg *config.Daemon) error {
	stored := storedServerURLRaw(root, account)
	if stored == "" || cfg.Credential == "" {
		return nil // no stored credential to protect (fresh / not enrolled)
	}
	resolved := resolveServerURL(*cfg)
	if resolved == "" || resolved == stored {
		return nil // same server — no switch
	}
	if !interactiveMode() {
		return fmt.Errorf("server changed from %s to %s — the stored host credential is for %s and will not be sent to %s; re-enroll with `pagnet enroll --server %s` (--non-interactive never re-enrolls)",
			stored, resolved, stored, resolved, resolved)
	}
	ok, err := confirmSwitch(stored, resolved)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("switch cancelled — the host was not re-enrolled")
	}
	if err := enrollHostForeground(root, account, "", nil, ""); err != nil {
		return err
	}
	if cfg2, _, err := loadAccountConfig(root); err == nil {
		*cfg = cfg2
	}
	return nil
}

// confirmSwitch asks the user to confirm a control-plane switch (interactive
// only). A non-"y" answer declines.
func confirmSwitch(stored, resolved string) (bool, error) {
	line, err := askLineFn(fmt.Sprintf(
		"Switch control plane from %s to %s? The host will be re-enrolled for the new server. [y/N] ",
		stored, resolved))
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}
