package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClaudeScript writes a shell stub that records its argv, consumes the
// stdin prompt, and replays the canned NDJSON from CLAUDE_FAKE_OUT (with
// optional stderr / exit code). This lets the tests exercise the real
// adapter logic (parsing, session capture, resume, classification) without
// a reachable provider.
const fakeClaudeScript = `#!/usr/bin/env bash
: > "$CLAUDE_FAKE_ARGS"
while [ $# -gt 0 ]; do
  printf '%s\n' "$1" >> "$CLAUDE_FAKE_ARGS"
  shift
done
cat > /dev/null
cat "$CLAUDE_FAKE_OUT" 2>/dev/null
if [ -n "$CLAUDE_FAKE_STDERR" ]; then printf '%s\n' "$CLAUDE_FAKE_STDERR" >&2; fi
if [ -n "$CLAUDE_FAKE_EXIT" ]; then exit "$CLAUDE_FAKE_EXIT"; fi
exit 0
`

// runClaudeStub runs StartTurn against a stubbed claude CLI and returns the
// normalized events plus the argv the adapter built.
func runClaudeStub(t *testing.T, spec TurnSpec, out string, stubEnv map[string]string) ([]TurnEvent, []string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "claude")
	if err := os.WriteFile(script, []byte(fakeClaudeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.ndjson")
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	// The child (stub script) reads these from ITS environment; pass them
	// as explicit injection pairs so they bypass the ChildEnv allowlist
	// (external audit F-009). Adapter-side env stays on t.Setenv.
	spec.Env = append(spec.Env, "CLAUDE_FAKE_OUT="+outPath, "CLAUDE_FAKE_ARGS="+argsPath)
	for k, v := range stubEnv {
		t.Setenv(k, v)
	}

	c := NewClaude(script)
	events := make(chan TurnEvent, 64)
	if err := c.StartTurn(context.Background(), spec, events); err != nil {
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

func claudeSpec(dir string) TurnSpec {
	return TurnSpec{
		InstanceID: "inst-1",
		Workspace:  dir,
		SessionDir: filepath.Join(dir, "pagnet-session"),
		Input:      "Reply with exactly one word: OK",
	}
}

func argHas(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

func argAfter(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

func TestClaude_ColdTurn(t *testing.T) {
	const sid = "11111111-2222-3333-4444-555555555555"
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `","model":"claude-sonnet-5","cwd":"/x"}
{"type":"assistant","message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"OK"}]},"session_id":"` + sid + `"}
{"type":"result","subtype":"success","is_error":false,"result":"OK","session_id":"` + sid + `","usage":{"input_tokens":120,"output_tokens":7,"cache_read_input_tokens":40}}
`
	dir := t.TempDir()
	evs, argv := runClaudeStub(t, claudeSpec(dir), out, nil)

	if !argHas(argv, "-p") || !argHas(argv, "--output-format") || argAfter(argv, "--output-format") != "stream-json" {
		t.Fatalf("argv missing headless stream-json flags: %v", argv)
	}
	if argAfter(argv, "--resume") != "" {
		t.Fatalf("cold start must not pass --resume: %v", argv)
	}
	var got []string
	for _, ev := range evs {
		got = append(got, ev.Type)
	}
	// session started -> turn started -> output -> completed
	if len(evs) != 4 ||
		evs[0].Type != EventSessionStarted || evs[0].SessionID != sid ||
		evs[1].Type != EventTurnStarted ||
		evs[2].Type != EventTurnOutput || evs[2].Output != "OK" ||
		evs[3].Type != EventTurnCompleted {
		t.Fatalf("events = %v", got)
	}
	if evs[3].Model != "claude-sonnet-5" {
		t.Fatalf("completed model = %q", evs[3].Model)
	}
	if evs[3].InputTokens == nil || *evs[3].InputTokens != 120 ||
		evs[3].OutputTokens == nil || *evs[3].OutputTokens != 7 ||
		evs[3].CachedTokens == nil || *evs[3].CachedTokens != 40 {
		t.Fatalf("completed tokens = %+v", evs[3])
	}
	// The EXACT captured id is persisted for resume (Phase E).
	id, err := readStoredSession(filepath.Join(dir, "pagnet-session", claudeSessionFile))
	if err != nil || id != sid {
		t.Fatalf("stored session = %q, %v; want %q", id, err, sid)
	}
}

func TestClaude_ResumeExactID(t *testing.T) {
	const sid = "aaaa1111-2222-3333-4444-555566667777"
	dir := t.TempDir()
	spec := claudeSpec(dir)
	spec.Resume = true
	if err := os.MkdirAll(spec.SessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStoredSession(filepath.Join(spec.SessionDir, claudeSessionFile), sid); err != nil {
		t.Fatal(err)
	}
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `","model":"claude-sonnet-5"}
{"type":"result","subtype":"success","is_error":false,"result":"OK","session_id":"` + sid + `"}
`
	evs, argv := runClaudeStub(t, spec, out, nil)
	if argAfter(argv, "--resume") != sid {
		t.Fatalf("--resume = %q, want the exact stored id %q (argv %v)", argAfter(argv, "--resume"), sid, argv)
	}
	if evs[0].Type != EventSessionResumed || evs[0].SessionID != sid {
		t.Fatalf("first event = %+v, want session.resumed %s", evs[0], sid)
	}
}

func TestClaude_ResumeNoStoredIDIsSessionLost(t *testing.T) {
	dir := t.TempDir()
	spec := claudeSpec(dir)
	spec.Resume = true
	out := `{"type":"system","subtype":"init","session_id":"9999"}
`
	evs, _ := runClaudeStub(t, spec, out, nil)
	if len(evs) != 1 || evs[0].Type != EventSessionLost {
		t.Fatalf("events = %+v, want session.lost (no silent fresh session)", evs)
	}
}

func TestClaude_ResumeRebaseIsSessionLost(t *testing.T) {
	const stored = "aaaa1111-2222-3333-4444-555566667777"
	const rebased = "bbbb1111-2222-3333-4444-555566667777"
	dir := t.TempDir()
	spec := claudeSpec(dir)
	spec.Resume = true
	if err := os.MkdirAll(spec.SessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStoredSession(filepath.Join(spec.SessionDir, claudeSessionFile), stored); err != nil {
		t.Fatal(err)
	}
	out := `{"type":"system","subtype":"init","session_id":"` + rebased + `","model":"claude-sonnet-5"}
`
	evs, _ := runClaudeStub(t, spec, out, nil)
	if len(evs) != 1 || evs[0].Type != EventSessionLost || evs[0].SessionID != stored {
		t.Fatalf("events = %+v, want session.lost for stored id %s", evs, stored)
	}
}

func TestClaude_MissingSessionIsSessionLost(t *testing.T) {
	const sid = "00000000-0000-0000-0000-000000000000"
	dir := t.TempDir()
	spec := claudeSpec(dir)
	spec.Resume = true
	if err := os.MkdirAll(spec.SessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStoredSession(filepath.Join(spec.SessionDir, claudeSessionFile), sid); err != nil {
		t.Fatal(err)
	}
	// The CLI's real shape (verified against claude 2.1.220): no init, a
	// result line with is_error + errors, the same text on stderr, exit 1.
	out := `{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"` + sid + `","errors":["No conversation found with session ID: ` + sid + `"]}
`
	evs, _ := runClaudeStub(t, spec, out, map[string]string{
		"CLAUDE_FAKE_STDERR": "No conversation found with session ID: " + sid,
		"CLAUDE_FAKE_EXIT":   "1",
	})
	if len(evs) != 1 || evs[0].Type != EventSessionLost || evs[0].SessionID != sid {
		t.Fatalf("events = %+v, want session.lost for %s", evs, sid)
	}
}

func TestClaude_AuthFailureClassified(t *testing.T) {
	const sid = "33333333-2222-3333-4444-555555555555"
	// The CLI's real auth-failure shape (verified against claude 2.1.220):
	// init with a fresh id, then a result line that IS an error.
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `","model":"claude-opus-5"}
{"type":"assistant","message":{"model":"<synthetic>","content":[{"type":"text","text":"Failed to authenticate: OAuth session expired and could not be refreshed"}]},"error":"authentication_failed","is_api_error_message":true}
{"type":"result","subtype":"success","is_error":true,"result":"Failed to authenticate: OAuth session expired and could not be refreshed","session_id":"` + sid + `","terminal_reason":"api_error"}
`
	evs, _ := runClaudeStub(t, claudeSpec(t.TempDir()), out, map[string]string{"CLAUDE_FAKE_EXIT": "1"})
	var failed *TurnEvent
	for i := range evs {
		if evs[i].Type == EventTurnFailed {
			failed = &evs[i]
		}
	}
	if failed == nil {
		t.Fatalf("no turn.failed event: %+v", evs)
	}
	if string(failed.FailureKind) != "auth_required" {
		t.Fatalf("failure kind = %q, want auth_required (text: %q)", failed.FailureKind, failed.Error)
	}
	if failed.RetryAt != nil {
		t.Fatalf("retryAt = %v, want nil (auth is a human action, never a timer)", *failed.RetryAt)
	}
}

func TestClaude_RateLimitDressedAsSuccess(t *testing.T) {
	const sid = "44444444-2222-3333-4444-555555555555"
	text := "Quota exhausted: Your token-plan 1-week quota has been exhausted. The quota will reset at 09-07 07:45:00 UTC."
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `","model":"claude-sonnet-5"}
{"type":"assistant","message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"` + text + `"}]}}
{"type":"result","subtype":"success","is_error":false,"result":"` + text + `","session_id":"` + sid + `"}
`
	evs, _ := runClaudeStub(t, claudeSpec(t.TempDir()), out, nil)
	var failed *TurnEvent
	for i := range evs {
		if evs[i].Type == EventTurnFailed {
			failed = &evs[i]
		}
	}
	if failed == nil {
		t.Fatalf("no turn.failed event: %+v", evs)
	}
	if string(failed.FailureKind) != "rate_limited" {
		t.Fatalf("failure kind = %q, want rate_limited", failed.FailureKind)
	}
	if failed.RetryAt == nil {
		t.Fatalf("retryAt = nil, want the provider-supplied reset time")
	}
}

func TestClaude_ModelAndMCPArgs(t *testing.T) {
	const sid = "55555555-2222-3333-4444-555555555555"
	out := `{"type":"system","subtype":"init","session_id":"` + sid + `"}
{"type":"result","subtype":"success","is_error":false,"result":"OK","session_id":"` + sid + `"}
`
	const mcp = `{"mcpServers":{"pagnet":{"command":"/usr/local/bin/pagnet","args":["mcp","worker","--socket","/s/pagnetd.sock"],"env":{"PAGNET_INSTANCE_ID":"inst-1"}}}}`
	spec := claudeSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG=" + mcp}
	evs, argv := runClaudeStub(t, spec, out, map[string]string{"PAGNET_CLAUDE_MODEL": "claude-sonnet-5"})
	if len(evs) == 0 {
		t.Fatalf("no events")
	}
	if argAfter(argv, "--model") != "claude-sonnet-5" {
		t.Fatalf("--model = %q, want claude-sonnet-5 (argv %v)", argAfter(argv, "--model"), argv)
	}
	if argAfter(argv, "--mcp-config") != mcp {
		t.Fatalf("--mcp-config = %q, want the daemon-rendered JSON", argAfter(argv, "--mcp-config"))
	}
	if !argHas(argv, "--permission-mode") || argAfter(argv, "--permission-mode") != "bypassPermissions" {
		t.Fatalf("managed turns run unattended: want --permission-mode bypassPermissions (argv %v)", argv)
	}
	// No file was written to the workspace for MCP (inline injection only).
	entries, _ := os.ReadDir(spec.Workspace)
	for _, e := range entries {
		if e.Name() == ".mcp.json" {
			t.Fatalf("adapter wrote .mcp.json to the workspace (must not touch user config files)")
		}
	}
}

func TestClaude_InvalidMCPConfigFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "claude")
	if err := os.WriteFile(script, []byte(fakeClaudeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_FAKE_OUT", filepath.Join(dir, "out.ndjson"))
	t.Setenv("CLAUDE_FAKE_ARGS", filepath.Join(dir, "args.txt"))
	if err := os.WriteFile(filepath.Join(dir, "out.ndjson"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewClaude(script)
	spec := claudeSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG={not json"}
	events := make(chan TurnEvent, 8)
	if err := c.StartTurn(context.Background(), spec, events); err == nil {
		t.Fatal("want error: invalid PAGNET_MCP_CONFIG must not run silently")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "args.txt"))
	if strings.TrimSpace(string(b)) != "" {
		t.Fatalf("process spawned despite invalid PAGNET_MCP_CONFIG (argv %s)", b)
	}
}

func TestClaude_ModelSelection(t *testing.T) {
	t.Setenv("PAGNET_CLAUDE_MODEL", "from-env")
	c := NewClaude("")
	if c.model() != "from-env" {
		t.Fatalf("model = %q, want from-env", c.model())
	}
	c.Model = "explicit"
	if c.model() != "explicit" {
		t.Fatalf("model = %q, want explicit (field wins)", c.model())
	}
	c.Model = ""
	t.Setenv("PAGNET_CLAUDE_MODEL", "")
	if c.model() != "" {
		t.Fatalf("model = %q, want empty (user default applies)", c.model())
	}
}

// TestClaude_InteractiveCmdNoBypassPermissions (external audit F-014):
// the interactive REPL is a human-in-the-loop session; it must NOT carry
// --permission-mode bypassPermissions (a human in the TUI keeps the CLI's
// normal approve/deny flow). Only the unattended managed turn (StartTurn)
// bypasses permissions.
func TestClaude_InteractiveCmdNoBypassPermissions(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := claudeSpec(t.TempDir())
	cmd, err := NewClaude(bin).InteractiveCmd(spec)
	if err != nil {
		t.Fatalf("InteractiveCmd: %v", err)
	}
	if argHas(cmd.Args, "--permission-mode") {
		t.Fatalf("interactive REPL must not bypass permissions (human approves in the TUI): %v", cmd.Args)
	}
}

func TestClaude_StopKillsProcess(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "claude")
	// A single-process stub that hangs until killed. The adapter closes stdin
	// after writing the prompt, so a `read` builtin would return at once on
	// EOF (the process would exit before Stop, racing the test). `exec sleep`
	// replaces bash with one sleep process that ignores stdin and hangs;
	// killing it releases the stdout pipe immediately.
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := NewClaude(script)
	events := make(chan TurnEvent, 16)
	done := make(chan error, 1)
	go func() { done <- c.StartTurn(context.Background(), claudeSpec(dir), events) }()
	// Let the process spawn.
	for i := 0; i < 200; i++ {
		if c.PID("inst-1") != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := c.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("StartTurn did not return after Stop")
	}
}

// TestStoredSessionRoundTrip covers the SHARED session-persistence helper
// (readStoredSession / writeStoredSession — used by the process-per-turn
// adapters): the exact captured id round-trips and the file is 0600
// (session ids are local state).
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
