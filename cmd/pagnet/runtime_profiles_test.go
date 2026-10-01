//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeProfileLocalCLIAndPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	cmd := runtimeProfilesCmd()
	cmd.SetArgs([]string{"--state-dir", dir, "add", "claude-work", "--runtime", "claude-code", "--env", "CLAUDE_CONFIG_DIR=~/.claude-work", "--arg", "literal;$(no-shell)"})
	cmd.SetOut(new(bytes.Buffer))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, runtimeprofile.Filename)
	file, err := runtimeprofile.Load(path)
	if err != nil || len(file.Profiles) != 1 {
		t.Fatal(err)
	}
	file.Profiles[0].Env["PROFILE_SECRET"] = "never-print-this"
	if err := runtimeprofile.Save(path, file); err != nil {
		t.Fatal(err)
	}
	output := new(bytes.Buffer)
	cmd = runtimeProfilesCmd()
	cmd.SetOut(output)
	cmd.SetArgs([]string{"--state-dir", dir, "list"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "never-print") || strings.Contains(output.String(), "CLAUDE_CONFIG_DIR") {
		t.Fatal("list exposed environment")
	}
	var rows []map[string]any
	if json.Unmarshal(output.Bytes(), &rows) != nil || len(rows) != 1 || rows[0]["name"] != "claude-work" {
		t.Fatalf("profile name missing %s", output)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("profile file not private")
	}
	cmd = runtimeProfilesCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetArgs([]string{"--state-dir", dir, "add", "claude-work", "--runtime", "codex"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("existing profile silently changed")
	}
}
func TestRunUsesReportedRuntimeProfileOnlyInLaunch(t *testing.T) {
	work := t.TempDir()
	host := `{"host":{"ID":"host-1","Name":"testhost","Status":"online"},"workspaces":[{"ID":"ws-1","Path":` + mustJSONString(work) + `}],"runtimes":[],"runtimeProfiles":[{"name":"claude-work","runtime":"claude-code","available":true}]}`
	srv := runTestEnv(t, "", map[string]string{"GET /api/v1/hosts/host-1": host})
	cmd := runCmd()
	cmd.SetArgs([]string{"--name", "profile-agent", "--profile", "claude-work", "--workspace", work})
	if _, err := captureStdoutErr(t, func() error { return cmd.Execute() }); err != nil {
		t.Fatal(err)
	}
	create, _ := srv.lastBody("POST", "/api/v1/networks/net-1/agents")
	launch, _ := srv.lastBody("POST", "/api/v1/networks/net-1/agents/def-1/launch")
	var c, l map[string]any
	_ = json.Unmarshal([]byte(create), &c)
	_ = json.Unmarshal([]byte(launch), &l)
	if c["runtime"] != "claude-code" || c["profile"] != nil || l["profile"] != "claude-work" || l["runtime"] != "claude-code" {
		t.Fatalf("incorrect definition/launch profile contract create=%s launch=%s", create, launch)
	}
}
func mustJSONString(value string) string { raw, _ := json.Marshal(value); return string(raw) }
