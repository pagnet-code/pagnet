package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

func TestJevProfileRestartAndExplicitOverrides(t *testing.T) {
	dir := t.TempDir()
	id := uuid.NewString()
	path := filepath.Join(dir, "services", "jev", id+".json")
	profile := serviceRunnerProfile{Service: id, Server: "https://app.pagnet.dev", Credential: "pgn_act_v1_local_test", Model: "jev-1.13.0", Adapter: "jev"}
	if err := saveServiceRunnerProfile(path, profile); err != nil {
		t.Fatal(err)
	}
	got, err := loadServiceRunnerProfile(path, id)
	if err != nil || got != profile {
		t.Fatalf("restart profile=%+v err=%v", got, err)
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("profile credential not private")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "typesafe-provider-key") {
		t.Fatal("provider key persisted")
	}
	if _, err := loadServiceRunnerProfile(path, uuid.NewString()); err == nil {
		t.Fatal("cross-service profile accepted")
	}
	t.Setenv("TYPESAFE_API_KEY", "typesafe-provider-key")
	cmd := jevServiceCmd()
	cmd.SetArgs([]string{"--service", id, "--state-dir", dir, "--model", "unsupported-model"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "model") {
		t.Fatalf("explicit restart model not applied: %v", err)
	}
	unchanged, err := loadServiceRunnerProfile(path, id)
	if err != nil || unchanged != profile {
		t.Fatal("failed preflight overwrote working profile")
	}
	cmd = jevServiceCmd()
	cmd.SetArgs([]string{"--service", id, "--state-dir", dir, "--server", "https://another.example"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("restart silently changed/ignored server: %v", err)
	}
}

func TestJevProfileRejectsUnsafeAndMalformedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	id := uuid.NewString()
	cases := []string{"{}", `{"service":"` + id + `","extra":"secret"}`, `{"service":"` + id + `"} {}`, strings.Repeat("x", 4097)}
	for _, raw := range cases {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadServiceRunnerProfile(path, id); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if err := saveServiceRunnerProfile(path, serviceRunnerProfile{Service: id}); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(path, 0644)
		if _, err := loadServiceRunnerProfile(path, id); err == nil {
			t.Fatal("world-readable profile accepted")
		}
	}
}

func TestJevSetupProofPinsServiceWithoutConnecting(t *testing.T) {
	id := uuid.NewString()
	credential := "pgn_act_v1_test"
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/api/v1/services/"+id+"/jev/setup" || r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("unexpected setup verification")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"serviceId": id, "integration": "typesafe-jev"})
	}))
	defer server.Close()
	cfg := sdk.Config{Server: server.URL, Credential: credential}
	if err := verifyJevSetup(context.Background(), cfg, id); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatal("setup consumed credential via endpoint connection")
	}
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"serviceId": uuid.NewString(), "integration": "typesafe-jev"})
	}))
	defer wrong.Close()
	cfg.Server = wrong.URL
	if err := verifyJevSetup(context.Background(), cfg, id); err == nil {
		t.Fatal("wrong principal proof accepted")
	}
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, server.URL, http.StatusFound) }))
	defer redirected.Close()
	cfg.Server = redirected.URL
	if err := verifyJevSetup(context.Background(), cfg, id); err == nil {
		t.Fatal("setup redirect accepted")
	}
	if requests != 1 {
		t.Fatal("credential forwarded on redirect")
	}
}

func TestJevLocalKeyBoundsAndPermissions(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "local-provider-key")
	key, err := readJevKey("")
	if err != nil || key != "local-provider-key" {
		t.Fatal("local environment unavailable")
	}
	if runtime.GOOS == "windows" {
		t.Skip("key-file intentionally unsupported without Unix owner/mode semantics")
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(" file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err = readJevKey(path)
	if err != nil || key != "file-key" {
		t.Fatalf("private key file: %v", err)
	}
	_ = os.Chmod(path, 0644)
	if _, err := readJevKey(path); err == nil {
		t.Fatal("public key file accepted")
	}
	_ = os.Chmod(path, 0600)
	_ = os.WriteFile(path, []byte(strings.Repeat("k", 4097)), 0600)
	if _, err := readJevKey(path); err == nil {
		t.Fatal("oversized key accepted")
	}
	if _, err := readJevKey(filepath.Dir(path)); err == nil {
		t.Fatal("directory key accepted")
	}
}
