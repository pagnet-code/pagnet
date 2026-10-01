//go:build unix

package main

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/sdk"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalProfileIdentityMismatchDoesNotConsumeOrConnect(t *testing.T) {
	principal, network := domain.NewID().String(), domain.NewID().String()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/api/v1/auth/principal/me" {
			t.Fatal("credential consumed or runtime contacted")
		}
		json.NewEncoder(w).Encode(map[string]any{"principal": map[string]string{"ID": domain.NewID().String()}, "memberships": []any{map[string]string{"NetworkID": network, "State": "active"}}})
	}))
	defer srv.Close()
	p := externalprofile.Profile{Version: 1, Principal: principal, Network: network, Server: srv.URL, Credential: "pgn_act_v1_never-consumed"}
	if err := verifyExternalProfile(context.Background(), p, sdk.Config{Server: srv.URL, Credential: p.Credential}); err == nil {
		t.Fatal("wrong principal accepted")
	}
	if requests != 1 {
		t.Fatal("unexpected credential operations")
	}
}
func TestExternalProfileCannotOverrideScopeOrBecomeHTTPServer(t *testing.T) {
	dir := t.TempDir()
	path, _ := externalprofile.Path(dir, "work")
	p := externalprofile.Profile{Version: 1, Principal: domain.NewID().String(), Network: domain.NewID().String(), Server: "https://app.pagnet.dev", Credential: "pgn_epd_v1_never-contact-server"}
	if err := externalprofile.SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--network", "--allow-invoke", "--allow-message", "--listen", "--oauth-resource"} {
		cmd := mcpExternalCmd()
		cmd.SetArgs([]string{"--profile", "work", "--state-dir", dir, flag, "override"})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("policy override accepted %s: %v", flag, err)
		}
	}
}
func TestExternalProfileUsesBoundDurableCredentialForRestart(t *testing.T) {
	dir := t.TempDir()
	principal := domain.NewID().String()
	path, _ := externalprofile.Path(dir, "work")
	p := externalprofile.Profile{Version: 1, Principal: principal, Network: domain.NewID().String(), Server: "https://app.pagnet.dev", Credential: "pgn_act_v1_consumed"}
	if err := externalprofile.SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	// Existing SDK identity format is authoritative; keep another profile's
	// credential separate even when its principal happens to be the same.
	state := filepath.Join(dir, "external-profiles", "work.state", "principals", principal)
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "credential"), []byte("pgn_epd_v1_bound"), 0600); err != nil {
		t.Fatal(err)
	}
	_, cfg, err := externalProfileConfig(dir, "work")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Credential != "pgn_epd_v1_bound" {
		t.Fatalf("restart did not use durable credential: %q", cfg.Credential)
	}
	other, _ := externalprofile.Path(dir, "other")
	if err := externalprofile.SaveNew(other, p); err != nil {
		t.Fatal(err)
	}
	_, cfg, err = externalProfileConfig(dir, "other")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Credential != p.Credential {
		t.Fatal("leaked credential between profiles")
	}
}
