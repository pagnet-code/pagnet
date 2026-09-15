// Package config loads host daemon configuration.
//
// Precedence: process environment > deploy/.env > ./.env > defaults.
// The env files are a convenience for local development; real deployments
// set the environment explicitly (or use a state dir for the daemon).
//
// The small env helpers (envDuration, loadEnvFileMap) are duplicated from
// internal/configserver on purpose: after the repo split the two packages
// live in different modules, so they cannot share an import.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/internal/runtime"
)

// Daemon is the host daemon configuration.
type Daemon struct {
	// ServerURL is the control plane base URL (https:// or http://localhost).
	ServerURL string
	// Credential is the host credential (Bearer) issued at enrollment.
	Credential string
	// HostID is the host's registered id (set at enrollment).
	HostID string
	// StateDir is the daemon's local state directory (default ~/.pagnet).
	StateDir string
	// HostName is the host's registered name.
	HostName string
	// AllowedRoots confines workspace discovery and launches.
	AllowedRoots []string
	// RootsMode is the roots enforcement mode (allow_all by default,
	// allow_list to confine to AllowedRoots). Empty = allow_all.
	RootsMode string
	// HeartbeatInterval for the outbound connection.
	HeartbeatInterval time.Duration
	// RuntimeEnv carries extra KEY=VALUE env pairs applied to spawned
	// runtime processes. Real deployments leave it empty; the E2E suite
	// uses it for fake-runtime simulation knobs (e.g. PAGNET_FAKE_
	// RATELIMIT). Set via PAGNET_RUNTIME_ENV (comma-separated).
	RuntimeEnv []string
	// CurrentNetwork is the user's selected default network (addendum:
	// `pagnet network use <name>`). Empty means "use the only network,
	// or ask".
	CurrentNetwork string
	// NoScan disables automatic git-repository discovery on the allowed
	// roots. Zero value = scan ON (backwards compatible); when set, the
	// daemon reports no discovered workspaces and workspaces are managed
	// explicitly (UI "Add", `pagnet run .`, `pagnet workspaces add`).
	NoScan bool
	// Debug enables development/test-only behavior (registers the
	// deterministic fake runtime). Default FALSE — a production daemon
	// never offers the fake runtime. Set via PAGNET_DEBUG or the state
	// file's `debug:` field; the `--debug` flag (pagnet serve) ORs in on top.
	Debug bool
	// AutoUpdate enables worker self-update (P6): when the control plane
	// advertises a newer release and the daemon is idle, it downloads the
	// release tarball and re-execs in place (same PID). Default TRUE —
	// opt out via PAGNET_AUTO_UPDATE=0/false/off/no, the state file's
	// `autoUpdate: false`, or the `--no-auto-update` flag (pagnet serve).
	AutoUpdate bool
}

// LoadDaemon reads daemon config: env, then the env files (deploy/.env,
// .env) for the daemon's own keys only, then the daemon state file
// (stateDir/config.yaml) for persistent values (server URL, host name).
//
// Unlike the server's LoadServer, the daemon NEVER os.Setenv values from
// the env files: deploy/.env carries control-plane secrets (DATABASE_URL,
// PAGNET_ADMIN_TOKEN) and the daemon spawns untrusted agent processes —
// a value set in the daemon's process environment would be inherited by
// every runtime (spec §86.10: agent processes must not receive
// control-plane credentials). The env files are consulted as a value
// source only, for the keys the daemon itself needs.
func LoadDaemon(stateDir string) (Daemon, error) {
	// deploy/.env wins over ./.env, matching the LoadEnvFile order used
	// by the server (first file seen sets the value).
	envFiles := loadEnvFileMap(".env")
	for k, v := range loadEnvFileMap("deploy/.env") {
		envFiles[k] = v
	}
	get := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if v, ok := envFiles[key]; ok && v != "" {
			return v
		}
		return def
	}
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = filepath.Join(home, ".pagnet")
	}
	cfg := Daemon{
		StateDir:  stateDir,
		ServerURL: get("PAGNET_SERVER", ""),
		// HostName resolves as: explicit env > the registered name in
		// the state file > the machine hostname. The file name must beat
		// the hostname guess — a worker state dir is that directory's
		// worker, not "this machine" (the guess would mislabel every
		// single-directory worker after its host name).
		HostName:          get("PAGNET_HOST_NAME", ""),
		HeartbeatInterval: envDuration("PAGNET_HEARTBEAT_INTERVAL", 15*time.Second),
		// Auto-update is ON by default (P6): the daemon re-execs itself
		// when the control plane advertises a newer release and the
		// worker is idle. Opt-out below (env / state file / CLI flag).
		AutoUpdate: true,
	}
	if env := get("PAGNET_RUNTIME_ENV", ""); env != "" {
		for _, kv := range strings.Split(env, ",") {
			if kv = strings.TrimSpace(kv); kv != "" {
				cfg.RuntimeEnv = append(cfg.RuntimeEnv, kv)
			}
		}
	}
	// PAGNET_SCAN_WORKSPACES=0/false/off/no turns off automatic git
	// discovery for this run (a state-file noScan already set can only
	// be cleared by `pagnet worker --scan` rewriting the file).
	if v := strings.ToLower(strings.TrimSpace(get("PAGNET_SCAN_WORKSPACES", ""))); v != "" {
		switch v {
		case "0", "false", "off", "no":
			cfg.NoScan = true
		}
	}
	// PAGNET_DEBUG=1/true/on/yes enables development/test-only behavior
	// (registers the deterministic fake runtime). Default off: a
	// production daemon never offers the fake runtime.
	if v := strings.ToLower(strings.TrimSpace(get("PAGNET_DEBUG", ""))); v != "" {
		switch v {
		case "1", "true", "on", "yes":
			cfg.Debug = true
		}
	}
	// PAGNET_AUTO_UPDATE=0/false/off/no disables worker self-update
	// (default ON, P6). Anything else — or unset — keeps it enabled.
	if v := strings.ToLower(strings.TrimSpace(get("PAGNET_AUTO_UPDATE", ""))); v != "" {
		switch v {
		case "0", "false", "off", "no":
			cfg.AutoUpdate = false
		}
	}
	if file := filepath.Join(stateDir, "config.yaml"); exists(file) {
		if err := loadDaemonYAML(file, &cfg); err == nil {
			// file values fill gaps only (hostName fills the empty
			// default above; an explicit PAGNET_HOST_NAME still wins)
		}
	}
	if cfg.HostName == "" {
		cfg.HostName = defaultHostName()
	}
	// SEC-410: runtime env pairs are appended AFTER the ChildEnv filter,
	// so they must pass the blocklist or the daemon refuses to start
	// (fail closed; the documented PAGNET_FAKE_* simulation namespace is
	// the only PAGNET_ exception).
	if err := runtime.ValidateExtraEnv(cfg.RuntimeEnv); err != nil {
		return Daemon{}, err
	}
	return cfg, nil
}

func defaultHostName() string {
	hostname, _ := os.Hostname()
	if hostname != "" {
		return hostname
	}
	return "pagnet-host"
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// loadEnvFileMap parses KEY=VALUE lines from p into a map without touching
// the process environment. Missing file is not an error.
func loadEnvFileMap(p string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(p)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key == "" {
			continue
		}
		out[key] = val
	}
	return out
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}
