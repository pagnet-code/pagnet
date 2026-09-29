package sdk

import (
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid https", Config{Server: "https://app.pagnet.dev", Credential: "pgn_epd_v1_abc"}, false},
		{"valid http (local test)", Config{Server: "http://127.0.0.1:8080", Credential: "pgn_act_v1_abc"}, false},
		{"valid http (localhost)", Config{Server: "http://localhost:18080", Credential: "pgn_act_v1_abc"}, false},
		{"missing server", Config{Credential: "pgn_epd_v1_abc"}, true},
		{"blank server", Config{Server: "   ", Credential: "pgn_epd_v1_abc"}, true},
		{"bad scheme", Config{Server: "ftp://x", Credential: "pgn_epd_v1_abc"}, true},
		{"missing credential", Config{Server: "https://x"}, true},
		{"non-pgn credential", Config{Server: "https://x", Credential: "acct_token_123"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestConfigValidate_Netpolicy pins F-SDK-1: the SDK is a
// principal-credential holder, so its server URL is held to the same
// netpolicy the daemon enforces — plain HTTP to a non-loopback remote is
// refused (naming the URL), unless the development opt-in is set.
func TestConfigValidate_Netpolicy(t *testing.T) {
	// The opt-in may be inherited from the test environment: pin it OFF
	// for the refusal case and ON for the opt-in case.
	t.Setenv("PAGNET_INSECURE_REMOTE_HTTP", "")

	// Non-loopback plain HTTP without the opt-in: refused, naming the URL.
	err := Config{Server: "http://control.example.com", Credential: "pgn_epd_v1_abc"}.Validate()
	if err == nil {
		t.Fatal("Validate() with non-loopback http:// and no opt-in: accepted, want a refusal")
	}
	if !strings.Contains(err.Error(), "http://control.example.com") {
		t.Fatalf("refusal = %q, want it to name the URL", err)
	}

	// With the opt-in: accepted (the one-line stderr diagnostic is
	// netpolicy's, at most once per process).
	t.Setenv("PAGNET_INSECURE_REMOTE_HTTP", "1")
	if err := (Config{Server: "http://control.example.com", Credential: "pgn_epd_v1_abc"}).Validate(); err != nil {
		t.Fatalf("Validate() with the opt-in: %v, want accepted", err)
	}
	t.Setenv("PAGNET_INSECURE_REMOTE_HTTP", "")

	// Loopback http and https stay accepted regardless.
	if err := (Config{Server: "http://127.0.0.1:18080", Credential: "pgn_epd_v1_abc"}).Validate(); err != nil {
		t.Fatalf("Validate() loopback http: %v, want accepted", err)
	}
	if err := (Config{Server: "https://control.example.com", Credential: "pgn_epd_v1_abc"}).Validate(); err != nil {
		t.Fatalf("Validate() https: %v, want accepted", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvServer, "https://env.example")
	t.Setenv(EnvCredential, "pgn_epd_v1_env")
	t.Setenv(EnvStateDir, "/tmp/env-state")
	c := ConfigFromEnv()
	if c.Server != "https://env.example" || c.Credential != "pgn_epd_v1_env" || c.StateDir != "/tmp/env-state" {
		t.Fatalf("ConfigFromEnv() = %+v", c)
	}
}

func TestConfigFromEnvUnset(t *testing.T) {
	t.Setenv(EnvServer, "")
	t.Setenv(EnvCredential, "")
	t.Setenv(EnvStateDir, "")
	c := ConfigFromEnv()
	if c.Server != "" || c.Credential != "" || c.StateDir != "" {
		t.Fatalf("ConfigFromEnv() with unset env = %+v, want empty", c)
	}
}

func TestServerBaseTrimsTrailingSlash(t *testing.T) {
	c := Config{Server: "https://x/"}
	if got := c.serverBase(); got != "https://x" {
		t.Fatalf("serverBase() = %q", got)
	}
}

func TestUserAgentDefault(t *testing.T) {
	c := Config{Server: "https://x"}
	ua := c.userAgent()
	if ua != "pagnet-sdk-go/"+Version {
		t.Fatalf("userAgent() default = %q", ua)
	}
	c.UserAgent = "custom/1.0"
	if got := c.userAgent(); got != "custom/1.0" {
		t.Fatalf("userAgent() = %q", got)
	}
}

func TestStateDirExplicit(t *testing.T) {
	c := Config{StateDir: "/tmp/explicit-state"}
	d, err := c.stateDir()
	if err != nil {
		t.Fatal(err)
	}
	if d != "/tmp/explicit-state" {
		t.Fatalf("stateDir() = %q", d)
	}
}
