package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunManagedRepresentative(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		status   string
		missing  string
		wantErr  string
		wantBody string
	}{
		{name: "local saved runtime", status: "idle", wantBody: `{"hostId":"host-1"}`},
		{name: "remote runtime override", args: []string{"--host", "lince.iot", "--runtime", "codex"}, status: "working", wantBody: `{"hostId":"host-2","runtime":"codex"}`},
		{name: "runtime profile", args: []string{"--profile", "work"}, status: "idle", wantBody: `{"hostId":"host-1","profile":"work"}`},
		{name: "failed launch", status: "failed", wantErr: "is failed", wantBody: `{"hostId":"host-1"}`},
		{name: "blocked launch", status: "auth_required", wantErr: "is auth_required", wantBody: `{"hostId":"host-1"}`},
		{name: "launch 404", missing: "POST", wantErr: "launch managed agent"},
		{name: "poll 404", missing: "GET", wantErr: "poll managed instance", wantBody: `{"hostId":"host-1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/api/v1/representatives/def-1/instances"
			srv := runTestEnv(t, "", map[string]string{
				"GET /api/v1/hosts":                 `[{"ID":"host-2","Name":"lince.iot"}]`,
				"GET /api/v1/networks/net-1/agents": `[{"ID":"def-1","Name":"telegram-v2","ExecutionMode":"managed"}]`,
				"POST " + path:                      `{"ID":"inst-1","Status":"starting"}`,
				"GET " + path:                       `[{"ID":"other-instance","Status":"failed"},{"ID":"inst-1","Status":"` + tc.status + `"}]`,
			})
			delete(srv.routes, "POST /api/v1/networks/net-1/agents/def-1/launch") // Regression: legacy route is a 404.
			if tc.missing != "" {
				delete(srv.routes, tc.missing+" "+path)
			}
			cmd := runCmd()
			cmd.SetArgs(append([]string{"--name", "telegram-v2", "--network", "default"}, tc.args...))
			out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				if !strings.Contains(out, "status="+tc.status) {
					t.Fatalf("status missing: %s", out)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v, want %s", err, tc.wantErr)
			}
			if tc.wantBody != "" {
				raw, ok := srv.lastBody("POST", path)
				if !ok {
					t.Fatal("no managed launch")
				}
				var got, want map[string]any
				if err := json.Unmarshal([]byte(raw), &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(tc.wantBody), &want); err != nil {
					t.Fatal(err)
				}
				if len(got) != len(want) {
					t.Fatalf("launch body=%s, want %s", raw, tc.wantBody)
				}
				for key, value := range want {
					if got[key] != value {
						t.Fatalf("launch body=%s, want %s", raw, tc.wantBody)
					}
				}
			}
			for _, r := range srv.reqs {
				if strings.Contains(r.Path, "workspaces") || strings.Contains(r.Path, "resources") || strings.Contains(r.Path, "rescan") || strings.HasSuffix(r.Path, "/launch") || r.Method == "POST" && r.Path == "/api/v1/networks/net-1/agents" {
					t.Errorf("unexpected workspace/legacy mutation: %+v", r)
				}
			}
		})
	}
}

func TestRunManagedSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector string
		args     []string
		agents   string
		wantErr  string
	}{
		{name: "id", selector: "def-1"},
		{name: "directory", selector: "telegram-v2", args: []string{"."}, wantErr: "omit the directory/resource"},
		{name: "resource", selector: "telegram-v2", args: []string{"github.com/o/r"}, wantErr: "omit the directory/resource"},
		{name: "workspace", selector: "telegram-v2", args: []string{"--workspace", "/work"}, wantErr: "omit the directory/resource"},
		{name: "ambiguous", selector: "telegram-v2", agents: `[{"ID":"def-1","Name":"telegram-v2","ExecutionMode":"managed"},{"ID":"def-2","Name":"telegram-v2","ExecutionMode":"managed"}]`, wantErr: "ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agents := tc.agents
			if agents == "" {
				agents = `[{"ID":"def-1","Name":"telegram-v2","ExecutionMode":"managed"}]`
			}
			path := "/api/v1/representatives/def-1/instances"
			srv := runTestEnv(t, "", map[string]string{"GET /api/v1/networks/net-1/agents": agents, "POST " + path: `{"ID":"inst-1"}`, "GET " + path: `[{"ID":"inst-1","Status":"idle"}]`})
			cmd := runCmd()
			cmd.SetArgs(append([]string{"--name", tc.selector}, tc.args...))
			_, err := captureStdoutErr(t, func() error { return cmd.Execute() })
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v, want %s", err, tc.wantErr)
				}
				for _, r := range srv.reqs {
					if r.Method == "POST" {
						t.Errorf("selection error mutated server: %+v", r)
					}
				}
			}
		})
	}
}

func TestRunExistingLegacyDefinition(t *testing.T) {
	srv := runTestEnv(t, "", map[string]string{"GET /api/v1/networks/net-1/agents": `[{"ID":"def-1","Name":"legacy"}]`})
	cmd := runCmd()
	cmd.SetArgs([]string{".", "--name", "legacy"})
	if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
		t.Fatal(err)
	}
	if srv.noCall("POST", "/api/v1/networks/net-1/agents/def-1/launch") {
		t.Fatal("legacy launch missing")
	}
	if !srv.noCall("POST", "/api/v1/networks/net-1/agents") {
		t.Fatal("duplicate definition")
	}
}

func TestRunManagedPendingCancellation(t *testing.T) {
	path := "/api/v1/representatives/def-1/instances"
	srv := runTestEnv(t, "", map[string]string{
		"GET /api/v1/networks/net-1/agents": `[{"ID":"def-1","Name":"telegram-v2","ExecutionMode":"managed"}]`,
		"POST " + path:                      `{"ID":"inst-1","Status":"starting"}`,
		"GET " + path:                       `[{"ID":"inst-1","Status":"starting"}]`,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--name", "telegram-v2"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != context.Canceled {
		t.Fatalf("error = %v, want cancellation while pending", err)
	}
	if strings.Contains(out, "agent remains") {
		t.Fatalf("pending launch claimed success: %s", out)
	}
	if srv.noCall("GET", path) {
		t.Fatal("managed status was not polled")
	}
}

func TestRunManagedHibernatingTransition(t *testing.T) {
	const path = "/api/v1/representatives/def-1/instances"
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/networks":
			fmt.Fprint(w, `[{"ID":"net-1","Name":"default"}]`)
		case "GET /api/v1/networks/net-1/agents":
			fmt.Fprint(w, `[{"ID":"def-1","Name":"telegram-v2","ExecutionMode":"managed"}]`)
		case "POST " + path:
			fmt.Fprint(w, `{"ID":"inst-1","Status":"starting"}`)
		case "GET " + path:
			status := "hibernating"
			if polls.Add(1) > 1 {
				status = "hibernated"
			}
			fmt.Fprintf(w, `[{"ID":"inst-1","Status":%q}]`, status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	cliFlags(t, srv)
	stateDir := t.TempDir()
	seedHostConfig(t, stateDir, srv.URL, "host-1")
	cmd := runCmd()
	cmd.SetArgs([]string{"--state-dir", stateDir, "--name", "telegram-v2", "--network", "default"})
	out, err := captureStdoutErr(t, func() error { return cmd.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	if polls.Load() != 2 {
		t.Fatalf("polls = %d, want 2", polls.Load())
	}
	if !strings.Contains(out, "status=hibernated") {
		t.Fatalf("final status missing: %s", out)
	}
}
