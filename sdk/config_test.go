package sdk

import (
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
