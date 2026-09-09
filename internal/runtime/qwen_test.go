package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeQwenScript writes a shell stub that records its argv, consumes the
// stdin prompt, and replays the canned NDJSON from QWEN_FAKE_OUT (with
// optional stderr / exit code). This lets the tests exercise the real
// adapter logic (parsing, session capture, resume, MCP args) without a
// reachable provider.
const fakeQwenScript = `#!/usr/bin/env bash
: > "$QWEN_FAKE_ARGS"
while [ $# -gt 0 ]; do
  printf '%s\n' "$1" >> "$QWEN_FAKE_ARGS"
  shift
done
cat > /dev/null
cat "$QWEN_FAKE_OUT" 2>/dev/null
if [ -n "$QWEN_FAKE_STDERR" ]; then printf '%s\n' "$QWEN_FAKE_STDERR" >&2; fi
if [ -n "$QWEN_FAKE_EXIT" ]; then exit "$QWEN_FAKE_EXIT"; fi
exit 0
`

// runQwenStub runs StartTurn against a stubbed qwen CLI and returns the
// normalized events plus the argv the adapter built.
func runQwenStub(t *testing.T, spec TurnSpec, out string, stubEnv map[string]string) ([]TurnEvent, []string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "qwen")
	if err := os.WriteFile(script, []byte(fakeQwenScript), 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.ndjson")
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	t.Setenv("QWEN_FAKE_OUT", outPath)
	t.Setenv("QWEN_FAKE_ARGS", argsPath)
	for k, v := range stubEnv {
		t.Setenv(k, v)
	}

	q := NewQwen(script)
	events := make(chan TurnEvent, 64)
	if err := q.StartTurn(context.Background(), spec, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	// No args file means the adapter returned before spawning (e.g. a
	// resume with no stored id is session-lost without a process).
	var argv []string
	if b, err := os.ReadFile(argsPath); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line != "" {
				argv = append(argv, line)
			}
		}
	}
	var evs []TurnEvent
	for ev := range events {
		evs = append(evs, ev)
	}
	return evs, argv
}

func qwenSpec(dir string) TurnSpec {
	return TurnSpec{
		InstanceID: "inst-1",
		Workspace:  dir,
		SessionDir: filepath.Join(dir, "pagnet-session"),
		Input:      "Reply with exactly one word: OK",
	}
}

// TestQwen_ModelAndMCPArgs verifies the inline --mcp-config injection:
// the daemon-rendered JSON is passed verbatim on the command line and NO
// file is written into the workspace (the user's code directory must
// stay clean; qwen merges --mcp-config with the user's own MCP servers).
func TestQwen_ModelAndMCPArgs(t *testing.T) {
	const sid = "66666666-3333-4444-5555-666666666666"
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `"}
{"type":"result","subtype":"success","is_error":false,"result":"OK","session_id":"` + sid + `"}
`
	const mcp = `{"mcpServers":{"pagnet":{"command":"pagnet-mcp","args":["--socket","/s/pagnetd.sock"],"env":{"PAGNET_INSTANCE_ID":"inst-1"}}}}`
	spec := qwenSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG=" + mcp}
	evs, argv := runQwenStub(t, spec, out, map[string]string{"PAGNET_QWEN_MODEL": "qwen-coder"})
	if len(evs) == 0 {
		t.Fatalf("no events")
	}
	if argAfter(argv, "-m") != "qwen-coder" {
		t.Fatalf("-m = %q, want qwen-coder (argv %v)", argAfter(argv, "-m"), argv)
	}
	if argAfter(argv, "--mcp-config") != mcp {
		t.Fatalf("--mcp-config = %q, want the daemon-rendered JSON", argAfter(argv, "--mcp-config"))
	}
	// No file was written to the workspace for MCP (inline injection only).
	entries, _ := os.ReadDir(spec.Workspace)
	for _, e := range entries {
		if e.Name() == ".qwen" {
			t.Fatalf("adapter wrote .qwen/ into the workspace (must not touch user config files)")
		}
	}
}

func TestQwen_InvalidMCPConfigFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "qwen")
	if err := os.WriteFile(script, []byte(fakeQwenScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QWEN_FAKE_OUT", filepath.Join(dir, "out.ndjson"))
	t.Setenv("QWEN_FAKE_ARGS", filepath.Join(dir, "args.txt"))
	if err := os.WriteFile(filepath.Join(dir, "out.ndjson"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	q := NewQwen(script)
	spec := qwenSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG={not json"}
	events := make(chan TurnEvent, 8)
	if err := q.StartTurn(context.Background(), spec, events); err == nil {
		t.Fatal("want error: invalid PAGNET_MCP_CONFIG must not run silently")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "args.txt"))
	if strings.TrimSpace(string(b)) != "" {
		t.Fatalf("process spawned despite invalid PAGNET_MCP_CONFIG (argv %s)", b)
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
	t.Setenv("PAGNET_QWEN_MODEL", "from-env")
	q := NewQwen("")
	if q.model() != "from-env" {
		t.Fatalf("model = %q, want from-env", q.model())
	}
	q.Model = "explicit"
	if q.model() != "explicit" {
		t.Fatalf("model = %q, want explicit (field wins)", q.model())
	}
	q.Model = ""
	t.Setenv("PAGNET_QWEN_MODEL", "")
	if q.model() != "" {
		t.Fatalf("model = %q, want empty (user default applies)", q.model())
	}
}
