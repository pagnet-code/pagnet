package config

import (
	"testing"
)

func TestValidateDevModeRequiresLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:18080", true},
		{"localhost:18080", true},
		{"[::1]:18080", true},
		{":18080", false},        // all interfaces
		{"0.0.0.0:18080", false}, // all interfaces
		{"192.168.1.10:18080", false},
	}
	for _, c := range cases {
		s := Server{Addr: c.addr, AuthMode: "dev"}
		err := s.Validate()
		if c.ok && err != nil {
			t.Errorf("Validate(%q, dev) = %v, want nil", c.addr, err)
		}
		if !c.ok && err == nil {
			t.Errorf("Validate(%q, dev) = nil, want error", c.addr)
		}
	}
}

func TestValidateTokenModeCredentials(t *testing.T) {
	base := Server{Addr: "127.0.0.1:18080", AuthMode: "token"}

	if err := base.Validate(); err == nil {
		t.Error("token mode without a token must fail")
	}
	short := base
	short.AdminToken = "too-short"
	if err := short.Validate(); err == nil {
		t.Error("short token must fail")
	}
	for _, weak := range []string{"change-me", "changeme", "admin", "secret", "password", "pagnet"} {
		w := base
		w.AdminToken = weak
		if err := w.Validate(); err == nil {
			t.Errorf("weak token %q must fail", weak)
		}
	}
	strong := base
	strong.AdminToken = "a9F3xK2mQ7vL5pR8tB1nD4gH6jC0sW3e"
	if err := strong.Validate(); err != nil {
		t.Errorf("strong token must pass: %v", err)
	}
}

func TestValidateUnknownMode(t *testing.T) {
	s := Server{Addr: "127.0.0.1:18080", AuthMode: "oidc"}
	if err := s.Validate(); err == nil {
		t.Error("unknown auth mode must fail")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:18080": true,
		"localhost:18080": true,
		":18080":          false,
		"0.0.0.0:18080":   false,
		"10.0.0.5:18080":  false,
	}
	for addr, want := range cases {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
