//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalprofile"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
)

func TestRuntimeConnectRecordsCleanupAndDisconnectPreservesExternalSession(t *testing.T) {
	state, workspace := t.TempDir(), t.TempDir()
	principal, network := domain.NewID().String(), domain.NewID().String()
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/auth/principal/me" {
			t.Error("unexpected control-plane mutation")
		}
		if r.Header.Get("Authorization") != "Bearer pgn_epd_v1_private" {
			t.Error("wrong principal credential")
		}
		json.NewEncoder(w).Encode(map[string]any{"principal": map[string]string{"ID": principal}, "memberships": []any{map[string]string{"NetworkID": network, "State": "active"}}})
	}))
	defer cp.Close()
	p := externalprofile.Profile{Version: 1, Principal: principal, Network: network, Server: cp.URL, Credential: "pgn_epd_v1_private"}
	path, _ := externalprofile.Path(state, "work")
	if err := externalprofile.SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(state, "qwen-token")
	if err := os.WriteFile(tokenFile, []byte("native-operator-private-token"), 0600); err != nil {
		t.Fatal(err)
	}
	disconnectFails := false
	postedName := ""
	modelActions := 0
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer native-operator-private-token" {
			t.Error("principal credential leaked to native runtime")
		}
		switch {
		case r.URL.Path == "/capabilities":
			json.NewEncoder(w).Encode(map[string]any{"v": 1, "mode": "http-bridge", "features": []string{"mcp_server_runtime_mutation", "workspace_qualified_rest_core"}, "workspaces": []any{map[string]any{"id": "owned-workspace", "cwd": workspace, "trusted": true}}})
		case r.Method == "GET" && r.URL.Path == "/session/live/status":
			json.NewEncoder(w).Encode(map[string]string{"sessionId": "live", "workspaceCwd": workspace})
		case r.Method == "POST" && r.URL.Path == "/workspaces/owned-workspace/mcp/servers":
			var payload struct {
				Name   string
				Config map[string]any
			}
			json.NewDecoder(r.Body).Decode(&payload)
			postedName = payload.Name
			raw, _ := json.Marshal(payload)
			if strings.Contains(string(raw), p.Credential) || payload.Config["env"] != nil {
				t.Error("private profile secret sent to runtime")
			}
			json.NewEncoder(w).Encode(map[string]any{"name": postedName, "toolCount": 4})
		case r.Method == "DELETE" && r.URL.Path == "/workspaces/owned-workspace/mcp/servers/"+postedName:
			if disconnectFails {
				w.WriteHeader(503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"name": postedName, "removed": true})
		default:
			modelActions++
			w.WriteHeader(500)
		}
	}))
	defer native.Close()
	cmd := mcpRuntimeConnectCmd()
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--state-dir", state, "--profile", "work", "--url", native.URL, "--workspace", workspace, "--session", "live", "--client-id", "registered", "--token-file", tokenFile})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(state, "runtime-connections", postedName+".json")
	var binding runtimeconnect.Binding
	if err := externalprofile.LoadBinding(record, &binding); err != nil || binding.Name != postedName {
		t.Fatal("cleanup record missing")
	}
	disconnectFails = true
	cmd = mcpRuntimeDisconnectCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--state-dir", state, postedName})
	if err := cmd.Execute(); err == nil {
		t.Fatal("failed disconnect reported success")
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatal("failed disconnect lost cleanup handle")
	}
	disconnectFails = false
	cmd = mcpRuntimeDisconnectCmd()
	cmd.SetOut(output)
	cmd.SetArgs([]string{"--state-dir", state, postedName})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("confirmed disconnect retained record")
	}
	if modelActions != 0 {
		t.Fatal("external model lifecycle changed")
	}
	if strings.Contains(output.String(), p.Credential) || strings.Contains(output.String(), "native-operator-private-token") {
		t.Fatal("command disclosed secret")
	}
}
