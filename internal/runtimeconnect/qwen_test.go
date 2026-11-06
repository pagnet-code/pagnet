package runtimeconnect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestQwenConnectDisconnectAuthenticatedExistingWorkspaceOnly(t *testing.T) {
	token := "operator-token-never-in-payload"
	workspace := t.TempDir()
	var mu sync.Mutex
	var methods []string
	var posted map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("X-Qwen-Client-Id") != "existing-client" {
			t.Error("client not bound")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/capabilities":
			json.NewEncoder(w).Encode(map[string]any{"v": 1, "mode": "http-bridge", "features": []string{"mcp_server_runtime_mutation", "workspace_qualified_rest_core"}, "workspaces": []any{map[string]any{"id": "workspace-id", "cwd": workspace, "trusted": true}}})
		case r.Method == "GET" && r.URL.Path == "/session/existing-session/status":
			json.NewEncoder(w).Encode(map[string]any{"sessionId": "existing-session", "workspaceCwd": workspace, "hasActivePrompt": true})
		case r.Method == "POST" && r.URL.Path == "/workspaces/workspace-id/mcp/servers":
			json.NewDecoder(r.Body).Decode(&posted)
			data, _ := json.Marshal(posted)
			if strings.Contains(string(data), token) || strings.Contains(string(data), "pgn_") {
				t.Fatal("secret in runtime request")
			}
			json.NewEncoder(w).Encode(map[string]any{"name": "pagnet_external_test", "toolCount": 4})
		case r.Method == "DELETE" && r.URL.Path == "/workspaces/workspace-id/mcp/servers/pagnet_external_test":
			json.NewEncoder(w).Encode(map[string]any{"name": "pagnet_external_test", "removed": true})
		default:
			t.Errorf("unexpected lifecycle mutation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	b := Binding{URL: srv.URL, Workspace: workspace, Session: "existing-session", Client: "existing-client", Name: "pagnet_external_test"}
	q, err := NewQwen(b, token)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(workspace, "pagnet")
	state := filepath.Join(workspace, "private-state")
	if err := q.Connect(context.Background(), exe, "work", state); err != nil {
		t.Fatal(err)
	}
	config := posted["config"].(map[string]any)
	args := config["args"].([]any)
	if config["command"] != exe || len(args) != 6 || args[2] != "--profile" || args[3] != "work" || args[5] != state || config["env"] != nil {
		t.Fatalf("not fixed private-profile command: %#v", posted)
	}
	if err := q.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestQwenPreflightFailureNeverMutatesNativeRuntime(t *testing.T) {
	for _, scenario := range []string{"anonymous", "bad-token", "unsupported-version", "missing-feature", "foreign-workspace", "untrusted", "foreign-session", "redirect", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			workspace := t.TempDir()
			mutations := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					mutations++
					w.WriteHeader(500)
					return
				}
				if scenario == "redirect" {
					http.Redirect(w, r, "http://127.0.0.1:1/token", 302)
					return
				}
				if r.Header.Get("Authorization") == "" && scenario != "anonymous" {
					w.WriteHeader(401)
					return
				}
				if scenario == "bad-token" {
					w.WriteHeader(401)
					return
				}
				if scenario == "oversize" {
					w.Write([]byte(strings.Repeat("x", 65537)))
					return
				}
				if strings.Contains(r.URL.Path, "/session/") {
					cwd := workspace
					if scenario == "foreign-session" {
						cwd = "/another-workspace"
					}
					json.NewEncoder(w).Encode(map[string]any{"sessionId": "live", "workspaceCwd": cwd})
					return
				}
				v := 1
				if scenario == "unsupported-version" {
					v = 2
				}
				features := []string{"mcp_server_runtime_mutation", "workspace_qualified_rest_core"}
				if scenario == "missing-feature" {
					features = nil
				}
				cwd := workspace
				if scenario == "foreign-workspace" {
					cwd = "/foreign"
				}
				json.NewEncoder(w).Encode(map[string]any{"v": v, "mode": "http-bridge", "features": features, "workspaces": []any{map[string]any{"id": "owned", "cwd": cwd, "trusted": scenario != "untrusted"}}})
			}))
			defer srv.Close()
			q, err := NewQwen(Binding{URL: srv.URL, Workspace: workspace, Session: "live", Client: "client", Name: "pagnet_external_test"}, "private-token-at-least-16")
			if err != nil {
				t.Fatal(err)
			}
			if err := q.Connect(context.Background(), "/bin/pagnet", "work", workspace); err == nil {
				t.Fatal("accepted unsafe native runtime")
			}
			if mutations != 0 {
				t.Fatal("mutated before verified preflight")
			}
		})
	}
}
func TestQwenOriginRejectsDNSRemoteCredentialsAndHeaders(t *testing.T) {
	for _, origin := range []string{"https://127.0.0.1:4170", "http://localhost:4170", "http://192.168.1.2:4170", "http://user:secret@127.0.0.1:4170", "http://127.0.0.1:4170/?token=secret", "http://127.0.0.1:4170/path"} {
		if _, err := NewQwen(Binding{URL: origin, Workspace: "/work", Session: "session", Client: "client", Name: "owned"}, "private-token-at-least-16"); err == nil {
			t.Fatal("accepted unsafe origin")
		}
	}
}

func TestQwenAutoAnswerRequiresPromptFeaturesAndUsesSavedBinding(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-prompt-feature", true: "supported"}[supported], func(t *testing.T) {
			workspace := t.TempDir()
			mutations := 0
			var gotArgs []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					w.WriteHeader(401)
					return
				}
				switch {
				case r.URL.Path == "/capabilities":
					features := []string{"mcp_server_runtime_mutation", "workspace_qualified_rest_core"}
					if supported {
						features = append(features, "session_prompt", "session_turn_status")
					}
					json.NewEncoder(w).Encode(map[string]any{"v": 1, "mode": "http-bridge", "features": features, "workspaces": []any{map[string]any{"id": "owned", "cwd": workspace, "trusted": true}}})
				case r.Method == "GET" && r.URL.Path == "/session/live/status":
					json.NewEncoder(w).Encode(map[string]string{"sessionId": "live", "workspaceCwd": workspace})
				case r.Method == "POST" && r.URL.Path == "/workspaces/owned/mcp/servers":
					mutations++
					var payload struct{ Config struct{ Args []string } }
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					gotArgs = payload.Config.Args
					json.NewEncoder(w).Encode(map[string]any{"name": "pagnet_external_test", "toolCount": 4})
				default:
					t.Errorf("unexpected runtime action %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer srv.Close()
			q, err := NewQwen(Binding{URL: srv.URL, Workspace: workspace, Session: "live", Client: "registered", Name: "pagnet_external_test", Profile: "work", AutoAnswer: true}, "private-test-token-16")
			if err != nil {
				t.Fatal(err)
			}
			err = q.Connect(context.Background(), "/bin/pagnet", "work", workspace)
			if !supported {
				if err == nil || mutations != 0 {
					t.Fatalf("auto-answer mutated unsupported runtime: %v, %d mutations", err, mutations)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"mcp", "external", "--profile", "work", "--state-dir", workspace, "--receive-asks", "--runtime-binding", "pagnet_external_test"}
			if !reflect.DeepEqual(gotArgs, want) {
				t.Fatalf("args = %v, want %v", gotArgs, want)
			}
			if err := q.Connect(context.Background(), "/bin/pagnet", "foreign", workspace); err == nil || mutations != 1 {
				t.Fatal("foreign profile binding accepted")
			}
		})
	}
}
