// Package config loads server and daemon configuration.
//
// Precedence: process environment > deploy/.env > ./.env > defaults.
// The env files are a convenience for local development; real deployments
// set the environment explicitly (or use a state dir for the daemon).
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pagnet/internal/runtime"
)

// ErrMissingDSN is returned when no DATABASE_URL is configured.
var ErrMissingDSN = errors.New("DATABASE_URL is not set (see deploy/example.env)")

// Server is the control plane configuration.
type Server struct {
	// Addr is the listen address (e.g. "127.0.0.1:18080").
	Addr string
	// DSN is the PostgreSQL connection string.
	DSN string
	// AuthMode: "token" (single admin bearer), "local" (DB users,
	// Argon2id, sessions + API tokens) or "oidc" (external identity
	// provider, config-driven). Validation is fail-closed (SEC-005):
	// unknown modes and under-specified modes refuse startup.
	AuthMode string
	// AdminToken is the Bearer token for administrative API access in
	// token mode. Empty in token mode is allowed: the server bootstraps
	// a random token at startup and prints it exactly once (log) — the
	// zero-setup open-source launch path.
	AdminToken string
	// OIDC configures the oidc auth mode. Provider-agnostic standard
	// OIDC (Keycloak is one of many valid issuers) — nothing about a
	// specific provider is hardcoded.
	OIDC OIDC
	// CORSOrigins are the allowed browser origins (CORS + WebSocket origin
	// validation). Entries are exact origins ("https://console.example.com")
	// or the shorthand "localhost" (http(s) on loopback, any port). Empty
	// means same-origin only (hosted deployments behind one origin).
	CORSOrigins []string
	// TrustedProxies are the peers (CIDR or IP) allowed to forward the
	// real client address via X-Forwarded-For / X-Real-IP (SEC-422).
	// Empty = direct connections only; forwarding headers from any peer
	// are ignored and rate-limit keys use the TCP peer.
	TrustedProxies []string
	// ReleaseDir, when set, serves worker bootstrap tarballs produced by
	// `make release` at GET /download/<file> (the wget-install path for
	// enrolling workers without root).
	ReleaseDir string
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

// OIDC configures the oidc auth mode (standard OIDC, any provider).
type OIDC struct {
	// Issuer is the OIDC issuer base URL (discovery: / .well-known/openid-
	// configuration). e.g. https://keycloak.example.com/realms/pagnet.
	Issuer string
	// ClientID / ClientSecret are the registered confidential client.
	ClientID     string
	ClientSecret string
	// RedirectURI is the EXACT URI registered with the provider for the
	// authorization-code redirect (no wildcards; validated in Validate).
	RedirectURI string
}

// Enabled reports whether the OIDC config is present (used for startup
// checks in oidc mode).
func (o OIDC) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

// LoadServer reads server configuration from environment (with env-file
// fallback).
func LoadServer() (Server, error) {
	LoadEnvFile("deploy/.env")
	LoadEnvFile(".env")

	cfg := Server{
		Addr:              envOr("PAGNET_ADDR", "127.0.0.1:18080"),
		DSN:               envOr("DATABASE_URL", ""),
		AuthMode:          envOr("PAGNET_AUTH_MODE", "token"),
		AdminToken:        envOr("PAGNET_ADMIN_TOKEN", ""),
		HeartbeatInterval: envDuration("PAGNET_HEARTBEAT_INTERVAL", 15*time.Second),
		OfflineThreshold:  envDuration("PAGNET_OFFLINE_THRESHOLD", 45*time.Second),
		LogLevel:          envOr("PAGNET_LOG_LEVEL", "info"),
		Telegram: Telegram{
			BotToken:    envOr("PAGNET_TG_BOT_TOKEN", ""),
			SecretToken: envOr("PAGNET_TG_SECRET_TOKEN", ""),
			WebhookURL:  envOr("PAGNET_TG_WEBHOOK_URL", ""),
		},
	}
	if v := os.Getenv("PAGNET_TG_ALLOWED_USERS"); v != "" {
		cfg.Telegram.AllowedUsers = splitCSV(v)
	}
	if v := os.Getenv("PAGNET_TG_ALLOWED_CHATS"); v != "" {
		cfg.Telegram.AllowedChats = splitCSV(v)
	}
	if v := os.Getenv("PAGNET_CORS_ORIGINS"); v != "" {
		cfg.CORSOrigins = splitCSV(v)
	}
	if v := os.Getenv("PAGNET_TRUSTED_PROXIES"); v != "" {
		cfg.TrustedProxies = splitCSV(v)
	}
	if v := os.Getenv("PAGNET_RELEASE_DIR"); v != "" {
		cfg.ReleaseDir = v
	}
	cfg.OIDC = OIDC{
		Issuer:       envOr("OIDC_ISSUER", ""),
		ClientID:     envOr("OIDC_CLIENT_ID", ""),
		ClientSecret: envOr("OIDC_CLIENT_SECRET", ""),
		RedirectURI:  envOr("OIDC_REDIRECT_URI", ""),
	}
	if cfg.DSN == "" {
		return cfg, ErrMissingDSN
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate enforces fail-closed auth/startup invariants (SEC-005). There is
// deliberately no permissive fallback: a configuration that cannot be proven
// safe refuses to start.
func (s Server) Validate() error {
	switch s.AuthMode {
	case "token":
		// Empty AdminToken is the zero-setup path: the server bootstraps
		// a random token at startup and prints it exactly once. A
		// configured token must be strong.
		if s.AdminToken == "" {
			break
		}
		if len(s.AdminToken) < 32 {
			return fmt.Errorf("config: PAGNET_ADMIN_TOKEN must be at least 32 characters (got %d)", len(s.AdminToken))
		}
		for _, weak := range []string{"change-me", "changeme", "admin", "secret", "password", "pagnet"} {
			if strings.EqualFold(s.AdminToken, weak) {
				return fmt.Errorf("config: PAGNET_ADMIN_TOKEN is a known weak value (%q); set a high-entropy token", weak)
			}
		}
	case "local":
		// DB users + Argon2id + sessions. No extra env required; the
		// first admin is created at first run (setup endpoint / CLI).
	case "oidc":
		if s.OIDC.Issuer == "" {
			return errors.New("config: PAGNET_AUTH_MODE=oidc requires OIDC_ISSUER")
		}
		if !strings.HasPrefix(s.OIDC.Issuer, "https://") && !isLoopbackURLOrEmpty(s.OIDC.Issuer, "http://") {
			return fmt.Errorf("config: OIDC_ISSUER must be https:// (got %q); loopback http is allowed only for local development", s.OIDC.Issuer)
		}
		if s.OIDC.ClientID == "" || s.OIDC.ClientSecret == "" {
			return errors.New("config: PAGNET_AUTH_MODE=oidc requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET")
		}
		if s.OIDC.RedirectURI == "" {
			return errors.New("config: PAGNET_AUTH_MODE=oidc requires OIDC_REDIRECT_URI (the exact URI registered with the provider)")
		}
		if !strings.HasPrefix(s.OIDC.RedirectURI, "https://") && !strings.HasPrefix(s.OIDC.RedirectURI, "http://") {
			return fmt.Errorf("config: OIDC_REDIRECT_URI must be a full http(s) URI (got %q)", s.OIDC.RedirectURI)
		}
		if strings.ContainsAny(s.OIDC.RedirectURI, "*") {
			return errors.New("config: OIDC_REDIRECT_URI must not contain wildcards (the provider must accept it exactly)")
		}
	default:
		return fmt.Errorf("config: unknown PAGNET_AUTH_MODE %q (want \"token\", \"local\" or \"oidc\")", s.AuthMode)
	}
	return nil
}

// isLoopbackURLOrEmpty reports whether uri starts with prefix and is a
// loopback host (local development against a local IdP / test mocks).
func isLoopbackURLOrEmpty(uri, prefix string) bool {
	if !strings.HasPrefix(uri, prefix) {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackAddr reports whether a listen address binds only to loopback.
// An empty host (":18080") binds all interfaces and is NOT loopback.
func IsLoopbackAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
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
	// StateDir is the daemon's local state directory (default ~/.pagnet).
	StateDir string
	// HostName is the host's registered name.
	HostName string
	// AllowedRoots confines workspace discovery and launches.
	AllowedRoots []string
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
}

// LoadDaemon reads daemon config: env, then the env files (deploy/.env,
// .env) for the daemon's own keys only, then the daemon state file
// (stateDir/config.yaml) for persistent values (server URL, host name).
//
// Unlike LoadServer, the daemon NEVER os.Setenv values from the env files:
// deploy/.env carries control-plane secrets (DATABASE_URL,
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
