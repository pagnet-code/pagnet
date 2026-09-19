package sdk

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Version is the SDK version reported in endpoint.register (sdkVersion) and
// the default User-Agent. It is stamped at release build time
// (-ldflags "-X github.com/pagnet-code/pagnet/sdk.Version=vX.Y.Z").
var Version = "dev"

// Environment variables read by ConfigFromEnv.
const (
	// EnvServer is the control-plane base URL (https://...).
	EnvServer = "PAGNET_SERVER"
	// EnvCredential is the principal credential: an activation credential
	// (pgn_act_v1_..., one-time) or the durable endpoint credential
	// (pgn_epd_v1_...).
	EnvCredential = "PAGNET_CREDENTIAL"
	// EnvStateDir overrides the principal state directory (default
	// ~/.pagnet).
	EnvStateDir = "PAGNET_STATE_DIR"
)

// Config configures a Client.
//
// Credential classes (north-star §26): the SDK accepts ONLY principal
// credentials — never an account token, a host credential, or a human user
// token. Two classes exist:
//
//   - Activation credential (pgn_act_v1_...): one-time, issued when a
//     service/agent is created. On the first successful endpoint.register
//     the server returns the durable endpoint credential in
//     endpoint.auth_ok and invalidates the activation credential. The SDK
//     persists the durable credential in the keyring and uses it on all
//     later connects.
//   - Endpoint credential (pgn_epd_v1_...): durable, revocable, rotatable,
//     scoped to (principal, endpoint). Revocation kills the live
//     connection; the SDK stops reconnecting with a clear error (a dead
//     credential cannot be fixed by retrying).
type Config struct {
	// Server is the control-plane base URL (https://app.pagnet.dev or a
	// self-hosted origin). Required.
	Server string
	// Credential is the principal credential (activation OR endpoint).
	// Required unless the keyring already holds the durable credential for
	// this principal (see Connect: a consumed activation credential
	// transparently falls back to the stored endpoint credential).
	Credential string
	// StateDir is the principal state directory (default ~/.pagnet). The
	// per-principal keyring lives under <StateDir>/principals/<principalID>/
	// — see the package docs for the layout.
	StateDir string
	// UserAgent is the HTTP/WebSocket User-Agent (default
	// "pagnet-sdk-go/<version>").
	UserAgent string
}

// ConfigFromEnv builds a Config from the environment: PAGNET_SERVER,
// PAGNET_CREDENTIAL, and optionally PAGNET_STATE_DIR. This is the
// server-deployment path (north-star §26): the credential comes from the
// process environment / secret store, never from a random file.
func ConfigFromEnv() Config {
	return Config{
		Server:     os.Getenv(EnvServer),
		Credential: os.Getenv(EnvCredential),
		StateDir:   os.Getenv(EnvStateDir),
	}
}

// Validate checks the config. It rejects nothing by credential CONTENT —
// the server decides whether a credential is valid; the SDK only checks
// shape (a principal credential carries the pgn_ prefix).
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server) == "" {
		return fmt.Errorf("sdk: Server is required (set Config.Server or %s)", EnvServer)
	}
	u, err := url.Parse(c.Server)
	if err != nil {
		return fmt.Errorf("sdk: Server is not a valid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("sdk: Server must be an http(s) URL, got %q", u.Scheme)
	}
	if strings.TrimSpace(c.Credential) == "" {
		return fmt.Errorf("sdk: Credential is required (set Config.Credential or %s)", EnvCredential)
	}
	if !strings.HasPrefix(c.Credential, "pgn_") {
		return fmt.Errorf("sdk: Credential does not look like a principal credential (pgn_act_v1_... or pgn_epd_v1_...) — the SDK accepts principal credentials only, never account/host/user tokens")
	}
	return nil
}

// stateDir resolves the effective state directory.
func (c Config) stateDir() (string, error) {
	dir := c.StateDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("sdk: resolve home dir for state dir: %w", err)
		}
		dir = filepath.Join(home, ".pagnet")
	}
	return filepath.Clean(dir), nil
}

// userAgent resolves the effective User-Agent.
func (c Config) userAgent() string {
	if strings.TrimSpace(c.UserAgent) != "" {
		return c.UserAgent
	}
	return "pagnet-sdk-go/" + Version
}

// serverBase returns the server URL with any trailing slash trimmed.
func (c Config) serverBase() string {
	return strings.TrimSuffix(strings.TrimSpace(c.Server), "/")
}
