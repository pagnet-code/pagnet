package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestInjectQwenMCP_MergesWithUserProjectSettings verifies the binding
// rule "never overwrite a user's own settings": the user's project-level
// .qwen/settings.json is preserved and only the agentnet server entry is
// upserted into mcpServers.
func TestInjectQwenMCP_MergesWithUserProjectSettings(t *testing.T) {
	ws := t.TempDir()
	dir := filepath.Join(ws, ".qwen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	userSettings := `{"mcpServers":{"mine":{"command":"/usr/bin/mine"}},"tools":{"approvalMode":"default"}}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(userSettings), 0o644); err != nil {
		t.Fatal(err)
	}

	spec := TurnSpec{
		Workspace: ws,
		Env: []string{
			`AGENTNET_MCP_CONFIG={"mcpServers":{"agentnet":{"command":"agentnet-mcp","args":["--socket","/x/agentnetd.sock"]}}}`,
		},
	}
	if err := injectQwenMCP(spec); err != nil {
		t.Fatalf("inject: %v", err)
	}

	var merged map[string]any
	b, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &merged); err != nil {
		t.Fatalf("merged file not valid JSON: %v", err)
	}
	servers, _ := merged["mcpServers"].(map[string]any)
	if _, ok := servers["mine"]; !ok {
		t.Fatalf("user MCP server lost: %v", servers)
	}
	ag, _ := servers["agentnet"].(map[string]any)
	if ag == nil || ag["command"] != "agentnet-mcp" {
		t.Fatalf("agentnet entry missing/wrong: %v", servers)
	}
	if tools, _ := merged["tools"].(map[string]any); tools == nil || tools["approvalMode"] != "default" {
		t.Fatalf("user top-level key lost: %v", merged)
	}
}

func TestInjectQwenMCP_Idempotent(t *testing.T) {
	ws := t.TempDir()
	spec := TurnSpec{
		Workspace: ws,
		Env:       []string{`AGENTNET_MCP_CONFIG={"mcpServers":{"agentnet":{"command":"agentnet-mcp"}}}`},
	}
	if err := injectQwenMCP(spec); err != nil {
		t.Fatalf("first inject: %v", err)
	}
	path := filepath.Join(ws, ".qwen", "settings.json")
	b1, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fi1, _ := os.Stat(path)
	if err := injectQwenMCP(spec); err != nil {
		t.Fatalf("second inject: %v", err)
	}
	b2, _ := os.ReadFile(path)
	fi2, _ := os.Stat(path)
	if string(b1) != string(b2) {
		t.Fatalf("second inject changed the file:\n%s\nvs\n%s", b1, b2)
	}
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatalf("second inject rewrote the file (mtime changed)")
	}
}

func TestInjectQwenMCP_InvalidUserConfigFailsLoudly(t *testing.T) {
	ws := t.TempDir()
	dir := filepath.Join(ws, ".qwen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := TurnSpec{
		Workspace: ws,
		Env:       []string{`AGENTNET_MCP_CONFIG={"mcpServers":{"agentnet":{"command":"agentnet-mcp"}}}`},
	}
	if err := injectQwenMCP(spec); err == nil {
		t.Fatal("want error: must not silently clobber an invalid user config")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	if string(b) != "{not json" {
		t.Fatalf("user config modified despite error: %s", b)
	}
}

func TestInjectQwenMCP_NoEnvNoop(t *testing.T) {
	ws := t.TempDir()
	if err := injectQwenMCP(TurnSpec{Workspace: ws}); err != nil {
		t.Fatalf("want no-op without AGENTNET_MCP_CONFIG, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(ws, ".qwen")); !os.IsNotExist(err) {
		t.Fatal(".qwen dir created although there was nothing to inject")
	}
}

func TestStoredSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if id, err := readStoredSession(path); id != "" || err == nil {
		t.Fatalf("missing file: id=%q err=%v, want empty + error", id, err)
	}
	if err := writeStoredSession(path, "abc-123"); err != nil {
		t.Fatal(err)
	}
	id, err := readStoredSession(path)
	if err != nil || id != "abc-123" {
		t.Fatalf("round trip = %q, %v; want abc-123", id, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("session file mode = %v, want 0600 (session ids are local state)", fi.Mode())
	}
}

func TestQwenModelSelection(t *testing.T) {
	t.Setenv("AGENTNET_QWEN_MODEL", "from-env")
	q := NewQwen("")
	if q.model() != "from-env" {
		t.Fatalf("model = %q, want from-env", q.model())
	}
	q.Model = "explicit"
	if q.model() != "explicit" {
		t.Fatalf("model = %q, want explicit (field wins)", q.model())
	}
	q.Model = ""
	t.Setenv("AGENTNET_QWEN_MODEL", "")
	if q.model() != "" {
		t.Fatalf("model = %q, want empty (user default applies)", q.model())
	}
}
