// Package config loads server and daemon configuration.
//
// Precedence: process environment > deploy/.env > ./.env > defaults.
// The env files are a convenience for local development; real deployments
// set the environment explicitly (or use a state dir for the daemon).
package config

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrMissingDSN is returned when no DATABASE_URL is configured.
var ErrMissingDSN = errors.New("DATABASE_URL is not set (see deploy/example.env)")

// Server is the control plane configuration.
type Server struct {
	// Addr is the listen address (e.g. ":18080").
	Addr string
	// DSN is the PostgreSQL connection string.
	DSN string
	// AuthMode: "dev" (local development, no token on localhost) or "token".
	AuthMode string
	// AdminToken is the Bearer token for administrative API access.
	AdminToken string
	// HeartbeatInterval is the expected host heartbeat period.
	HeartbeatInterval time.Duration
	// OfflineThreshold marks hosts offline after this silence.
	OfflineThreshold time.Duration
	// LogLevel: debug | info | warn | error
	LogLevel string
	// Telegram configures the Telegram channel gateway (addendum Phase G).
	// Enabled when BotToken is set. The token is server-side only (§15).
	Telegram Telegram
}

// Telegram is the Telegram channel gateway configuration.
type Telegram struct {
	// BotToken: server-side only — never passed to runtimes/MCP/logs (§15).
	BotToken string
	// SecretToken authenticates the public webhook (Telegram's supported
	// secret-token mechanism). Generated at startup when empty.
	SecretToken string
	// WebhookURL is registered via setWebhook when set.
	WebhookURL string
	// AllowedUsers / AllowedChats: explicit §15 restrictions (comma-
	// separated ids). When both are empty the pairing binding is the gate.
	AllowedUsers []string
	AllowedChats []string
}

// Enabled reports whether the Telegram channel should be started.
func (t Telegram) Enabled() bool { return t.BotToken != "" }

// LoadServer reads server configuration from environment (with env-file
// fallback).
func LoadServer() (Server, error) {
	LoadEnvFile("deploy/.env")
	LoadEnvFile(".env")

	cfg := Server{
		Addr:              envOr("AGENTNET_ADDR", ":18080"),
		DSN:               envOr("DATABASE_URL", ""),
		AuthMode:          envOr("AGENTNET_AUTH_MODE", "dev"),
		AdminToken:        envOr("AGENTNET_ADMIN_TOKEN", ""),
		HeartbeatInterval: envDuration("AGENTNET_HEARTBEAT_INTERVAL", 15*time.Second),
		OfflineThreshold:  envDuration("AGENTNET_OFFLINE_THRESHOLD", 45*time.Second),
		LogLevel:          envOr("AGENTNET_LOG_LEVEL", "info"),
		Telegram: Telegram{
			BotToken:    envOr("AGENTNET_TG_BOT_TOKEN", ""),
			SecretToken: envOr("AGENTNET_TG_SECRET_TOKEN", ""),
			WebhookURL:  envOr("AGENTNET_TG_WEBHOOK_URL", ""),
		},
	}
	if v := os.Getenv("AGENTNET_TG_ALLOWED_USERS"); v != "" {
		cfg.Telegram.AllowedUsers = splitCSV(v)
	}
	if v := os.Getenv("AGENTNET_TG_ALLOWED_CHATS"); v != "" {
		cfg.Telegram.AllowedChats = splitCSV(v)
	}
	if cfg.DSN == "" {
		return cfg, ErrMissingDSN
	}
	return cfg, nil
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Daemon is the host daemon configuration.
type Daemon struct {
	// ServerURL is the control plane base URL (https:// or http://localhost).
	ServerURL string
	// Credential is the host credential (Bearer) issued at enrollment.
	Credential string
	// HostID is the host's registered id (set at enrollment).
	HostID string
	// StateDir is the daemon's local state directory (default ~/.agentnet).
	StateDir string
	// HostName is the host's registered name.
	HostName string
	// AllowedRoots confines workspace discovery and launches.
	AllowedRoots []string
	// HeartbeatInterval for the outbound connection.
	HeartbeatInterval time.Duration
	// RuntimeEnv carries extra KEY=VALUE env pairs applied to spawned
	// runtime processes. Real deployments leave it empty; the E2E suite
	// uses it for fake-runtime simulation knobs (e.g. AGENTNET_FAKE_
	// RATELIMIT). Set via AGENTNET_RUNTIME_ENV (comma-separated).
	RuntimeEnv []string
	// CurrentNetwork is the user's selected default network (addendum:
	// `agentnet network use <name>`). Empty means "use the only network,
	// or ask".
	CurrentNetwork string
}

// LoadDaemon reads daemon config: env, then the env files (deploy/.env,
// .env) for the daemon's own keys only, then the daemon state file
// (stateDir/config.yaml) for persistent values (server URL, host name).
//
// Unlike LoadServer, the daemon NEVER os.Setenv values from the env files:
// deploy/.env carries control-plane secrets (DATABASE_URL,
// AGENTNET_ADMIN_TOKEN) and the daemon spawns untrusted agent processes —
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
		stateDir = filepath.Join(home, ".agentnet")
	}
	cfg := Daemon{
		StateDir:          stateDir,
		ServerURL:         get("AGENTNET_SERVER", ""),
		HostName:          get("AGENTNET_HOST_NAME", defaultHostName()),
		HeartbeatInterval: envDuration("AGENTNET_HEARTBEAT_INTERVAL", 15*time.Second),
	}
	if env := get("AGENTNET_RUNTIME_ENV", ""); env != "" {
		for _, kv := range strings.Split(env, ",") {
			if kv = strings.TrimSpace(kv); kv != "" {
				cfg.RuntimeEnv = append(cfg.RuntimeEnv, kv)
			}
		}
	}
	if file := filepath.Join(stateDir, "config.yaml"); exists(file) {
		if err := loadDaemonYAML(file, &cfg); err == nil {
			// file values fill gaps only
		}
	}
	return cfg, nil
}

func defaultHostName() string {
	hostname, _ := os.Hostname()
	if hostname != "" {
		return hostname
	}
	return "agentnet-host"
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// LoadEnvFile reads KEY=VALUE lines from p and sets any variable that is not
// already present in the environment. Missing file is not an error.
// Restricted to LoadServer: the server process is trusted, while the daemon
// (which spawns agent processes) must use loadEnvFileMap instead.
func LoadEnvFile(p string) {
	for k, v := range loadEnvFileMap(p) {
		if _, present := os.LookupEnv(k); !present {
			_ = os.Setenv(k, v)
		}
	}
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
