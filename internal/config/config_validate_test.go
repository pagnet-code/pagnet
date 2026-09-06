package config

import (
	"testing"
)

func TestValidateTokenModeCredentials(t *testing.T) {
	base := Server{Addr: "127.0.0.1:18080", AuthMode: "token"}

	// Empty token is the zero-setup bootstrap path: the server generates
	// and prints one at startup.
	if err := base.Validate(); err != nil {
		t.Errorf("token mode without a token must pass (bootstrap): %v", err)
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

func TestValidateLocalMode(t *testing.T) {
	s := Server{Addr: "127.0.0.1:18080", AuthMode: "local"}
	if err := s.Validate(); err != nil {
		t.Errorf("local mode must pass with no extra env: %v", err)
	}
}

func TestValidateOIDCMode(t *testing.T) {
	full := Server{
		Addr:     "127.0.0.1:18080",
		AuthMode: "oidc",
		OIDC: OIDC{
			Issuer:       "https://keycloak.example.com/realms/pagnet",
			ClientID:     "pagnet",
			ClientSecret: "s3cret",
			RedirectURI:  "https://pagnet.example.com/api/v1/auth/oidc/callback",
		},
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("full oidc config must pass: %v", err)
	}

	missing := func(mutate func(*Server)) {
		s := full
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Error("incomplete oidc config must fail")
		}
	}
	missing(func(s *Server) { s.OIDC.Issuer = "" })
	missing(func(s *Server) { s.OIDC.ClientID = "" })
	missing(func(s *Server) { s.OIDC.ClientSecret = "" })
	missing(func(s *Server) { s.OIDC.RedirectURI = "" })

	// The issuer must be https, except loopback for local dev/test IdPs.
	nonTLS := full
	nonTLS.OIDC.Issuer = "http://keycloak.example.com/realms/pagnet"
	if err := nonTLS.Validate(); err == nil {
		t.Error("non-loopback http issuer must fail")
	}
	localIssuer := full
	localIssuer.OIDC.Issuer = "http://127.0.0.1:18081/realms/pagnet"
	if err := localIssuer.Validate(); err != nil {
		t.Errorf("loopback http issuer (local dev) must pass: %v", err)
	}

	// Wildcard redirect URIs are never accepted.
	wild := full
	wild.OIDC.RedirectURI = "https://pagnet.example.com/*/callback"
	if err := wild.Validate(); err == nil {
		t.Error("wildcard redirect URI must fail")
	}
}

func TestValidateUnknownModes(t *testing.T) {
	for _, mode := range []string{"dev", "bogus", "Token"} {
		s := Server{Addr: "127.0.0.1:18080", AuthMode: mode}
		if err := s.Validate(); err == nil {
			t.Errorf("auth mode %q must fail", mode)
		}
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
