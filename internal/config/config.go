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
}

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
	}
	if cfg.DSN == "" {
		return cfg, ErrMissingDSN
	}
	return cfg, nil
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
}

// LoadDaemon reads daemon config: env, then the daemon state file
// (stateDir/config.yaml) for persistent values (server URL, host name).
func LoadDaemon(stateDir string) (Daemon, error) {
	LoadEnvFile("deploy/.env")
	LoadEnvFile(".env")
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = filepath.Join(home, ".agentnet")
	}
	cfg := Daemon{
		StateDir:          stateDir,
		ServerURL:         envOr("AGENTNET_SERVER", ""),
		HostName:          envOr("AGENTNET_HOST_NAME", defaultHostName()),
		HeartbeatInterval: envDuration("AGENTNET_HEARTBEAT_INTERVAL", 15*time.Second),
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
func LoadEnvFile(p string) {
	f, err := os.Open(p)
	if err != nil {
		return
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
		if _, present := os.LookupEnv(key); !present {
			_ = os.Setenv(key, val)
		}
	}
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
