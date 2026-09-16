package netpolicy

import (
	"strings"
	"testing"
)

// IsLoopbackHost: the loopback definition is an IP literal that is
// loopback, or the literal "localhost" (case-insensitive). Everything
// else — private ranges, public hosts, bare names — is NOT loopback.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"Localhost", true},
		{"localhost:18080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:18080", true},
		{"127.5.6.7", true}, // 127.0.0.0/8 is all loopback
		{"::1", true},
		{"[::1]", true},
		{"[::1]:18080", true},
		{"10.0.0.5", false},     // private, not loopback
		{"192.168.1.10", false}, // private, not loopback
		{"172.16.0.1", false},   // private, not loopback
		{"0.0.0.0", false},      // not loopback
		{"8.8.8.8", false},      // public
		{"example.com", false},  // public hostname
		{"controlplane.internal", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			if got := IsLoopbackHost(tc.host); got != tc.want {
				t.Fatalf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// Check: the http-vs-https x loopback-vs-remote matrix. The opt-in env is
// unset for the refusal cases and set for the opt-in case.
func TestCheck(t *testing.T) {
	t.Run("https is always allowed", func(t *testing.T) {
		t.Setenv(EnvInsecure, "")
		for _, u := range []string{
			"https://example.com",
			"https://controlplane.internal:8443",
			"wss://example.com/ws",
		} {
			if err := Check(u, false); err != nil {
				t.Fatalf("Check(%q) = %v, want nil", u, err)
			}
		}
	})

	t.Run("loopback http is always allowed", func(t *testing.T) {
		t.Setenv(EnvInsecure, "")
		for _, u := range []string{
			"http://127.0.0.1:18080",
			"http://localhost:18080",
			"http://[::1]:18080",
			"ws://127.0.0.1:18080/api/v1/hosts/ws",
		} {
			if err := Check(u, false); err != nil {
				t.Fatalf("Check(%q) = %v, want nil (loopback http is allowed)", u, err)
			}
		}
	})

	t.Run("non-loopback http is refused", func(t *testing.T) {
		t.Setenv(EnvInsecure, "")
		for _, u := range []string{
			"http://example.com",
			"http://10.0.0.5:18080",
			"ws://controlplane.internal:18080/api/v1/hosts/ws",
		} {
			err := Check(u, false)
			if err == nil {
				t.Fatalf("Check(%q) = nil, want a refusal", u)
			}
			if !strings.Contains(err.Error(), u) {
				t.Fatalf("Check(%q) error %q does not name the URL", u, err)
			}
		}
	})

	t.Run("empty URL is allowed (absence is the caller's concern)", func(t *testing.T) {
		t.Setenv(EnvInsecure, "")
		if err := Check("", false); err != nil {
			t.Fatalf("Check(\"\") = %v, want nil", err)
		}
	})

	t.Run("opt-in via env allows non-loopback http", func(t *testing.T) {
		t.Setenv(EnvInsecure, "1")
		if err := Check("http://example.com", false); err != nil {
			t.Fatalf("Check with opt-in = %v, want nil", err)
		}
	})

	t.Run("opt-in via flag allows non-loopback http", func(t *testing.T) {
		t.Setenv(EnvInsecure, "")
		if err := Check("http://example.com", true); err != nil {
			t.Fatalf("Check with flag opt-in = %v, want nil", err)
		}
	})

	t.Run("garbage env value is not an opt-in", func(t *testing.T) {
		t.Setenv(EnvInsecure, "maybe")
		if err := Check("http://example.com", false); err == nil {
			t.Fatal("Check with a non-true env value must refuse")
		}
	})
}
