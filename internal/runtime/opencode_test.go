package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOpenCodeScript records the adapter's argv (one arg per line),
// optionally replays canned NDJSON from OPENCODE_FAKE_OUT, and exits with
// the optional OPENCODE_FAKE_EXIT code (default 0). The opencode CLI is not
// installed on this host, so the tests exercise only the deterministic
// adapter logic — binary resolution, arg construction, the MCP config
// rendering, and the exit classification — never a faked opencode response.
const fakeOpenCodeScript = `#!/usr/bin/env bash
: > "$OPENCODE_FAKE_ARGS"
while [ $# -gt 0 ]; do
  printf '%s\n' "$1" >> "$OPENCODE_FAKE_ARGS"
  shift
done
cat "$OPENCODE_FAKE_OUT" 2>/dev/null
if [ -n "$OPENCODE_FAKE_EXIT" ]; then exit "$OPENCODE_FAKE_EXIT"; fi
exit 0
`

// runOpenCodeStub runs StartTurn against a stubbed opencode CLI and returns
// the argv the adapter built. The stub records argv and exits 0 (no output
// is replayed: the real CLI's NDJSON shape is not faked here).
func runOpenCodeStub(t *testing.T, spec TurnSpec, stubEnv map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "opencode")
	if err := os.WriteFile(script, []byte(fakeOpenCodeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	// The child (stub script) reads this from ITS environment; pass it as
	// an explicit injection pair so it bypasses the ChildEnv allowlist
	// (external audit F-009). Adapter-side env stays on t.Setenv.
	spec.Env = append(spec.Env, "OPENCODE_FAKE_ARGS="+argsPath)
	for k, v := range stubEnv {
		t.Setenv(k, v)
	}

	o := NewOpenCode(script)
	events := make(chan TurnEvent, 64)
	if err := o.StartTurn(context.Background(), spec, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	// StartTurn closes the channel; drain it (the stub emits no output, so
	// at most a single turn.completed arrives).
	for range events {
	}
	b, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("adapter did not spawn the process (argv not recorded): %v", err)
	}
	var argv []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			argv = append(argv, line)
		}
	}
	return argv
}

func opencodeSpec(dir string) TurnSpec {
	return TurnSpec{
		InstanceID: "inst-1",
		Workspace:  dir,
		SessionDir: filepath.Join(dir, "pagnet-session"),
		Input:      "Reply with exactly one word: OK",
	}
}

// TestOpenCode_BinaryNotFound: with no opencode on PATH (and none next to
// the executable) the adapter reports unavailable.
func TestOpenCode_BinaryNotFound(t *testing.T) {
	// Point PATH at an empty dir so a host that happens to have opencode
	// installed still exercises the not-found path.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	o := NewOpenCode("")
	if o.Available() {
		t.Fatal("Available() = true, want false (no opencode binary)")
	}
	if _, ok := o.BinaryPath(); ok {
		t.Fatal("BinaryPath() ok = true, want false (no opencode binary)")
	}
}

// TestOpenCode_ModelSelection: the model override precedence is explicit
// field > PAGNET_OPENCODE_MODEL env > empty (user default).
func TestOpenCode_ModelSelection(t *testing.T) {
	t.Setenv("PAGNET_OPENCODE_MODEL", "from-env")
	o := NewOpenCode("")
	if o.model() != "from-env" {
		t.Fatalf("model = %q, want from-env", o.model())
	}
	o.Model = "explicit"
	if o.model() != "explicit" {
		t.Fatalf("model = %q, want explicit (field wins)", o.model())
	}
	o.Model = ""
	t.Setenv("PAGNET_OPENCODE_MODEL", "")
	if o.model() != "" {
		t.Fatalf("model = %q, want empty (user default applies)", o.model())
	}
}

// TestOpenCode_ArgConstruction: the turn argv is the documented one-shot
// form — `run --format json` plus the model (turn precedence over env) and
// the resume session — with the prompt as the trailing positional.
func TestOpenCode_ArgConstruction(t *testing.T) {
	spec := opencodeSpec(t.TempDir())
	spec.Model = "anthropic/claude-sonnet-4-5"
	spec.Resume = true
	const stored = "ses_stored_123"
	if err := os.MkdirAll(spec.SessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeStoredSession(filepath.Join(spec.SessionDir, opencodeSessionFile), stored); err != nil {
		t.Fatal(err)
	}
	// The turn's model must win over the env default.
	argv := runOpenCodeStub(t, spec, map[string]string{"PAGNET_OPENCODE_MODEL": "env-model"})

	if argv[0] != "run" || argAfter(argv, "--format") != "json" {
		t.Fatalf("argv must start with `run --format json`: %v", argv)
	}
	if argAfter(argv, "--model") != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("--model = %q, want the turn's model (precedence over env): %v", argAfter(argv, "--model"), argv)
	}
	if argAfter(argv, "--session") != stored {
		t.Fatalf("--session = %q, want the stored id %q: %v", argAfter(argv, "--session"), stored, argv)
	}
	if argv[len(argv)-1] != spec.Input {
		t.Fatalf("trailing positional = %q, want the prompt %q: %v", argv[len(argv)-1], spec.Input, argv)
	}
}

// TestOpenCode_ColdTurnNoResume: a fresh turn passes no --session.
func TestOpenCode_ColdTurnNoResume(t *testing.T) {
	spec := opencodeSpec(t.TempDir())
	argv := runOpenCodeStub(t, spec, nil)
	if argHas(argv, "--session") {
		t.Fatalf("cold start must not pass --session: %v", argv)
	}
	if argHas(argv, "--model") {
		t.Fatalf("no model set: must not pass --model: %v", argv)
	}
}

// TestOpenCode_ProcessDiesMidTurnIsProcessError is the process-per-turn
// regression (spec E): the CLI confirms the session (the turn started) and
// streams partial output, then DIES — a hard SIGKILL, exit 137, no terminal
// output. The turn must settle as a FAILED turn (process_error), never as a
// completed one: that is what lets the daemon's legacy path mark the
// instance failed/recoverable instead of stranding it `working` forever.
// The captured session id is preserved (written when the session is
// confirmed), so the explicit retry resumes by the exact stored id — the
// existing resume semantics.
func TestOpenCode_ProcessDiesMidTurnIsProcessError(t *testing.T) {
	const sid = "ses_died_midturn"
	out := `{"type":"step_start","timestamp":1,"sessionID":"` + sid + `"}
{"type":"text","timestamp":2,"sessionID":"` + sid + `","part":{"type":"text","text":"partial"}}
`
	dir := t.TempDir()
	script := filepath.Join(dir, "opencode")
	if err := os.WriteFile(script, []byte(fakeOpenCodeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.ndjson")
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := opencodeSpec(t.TempDir())
	// The child (stub script) reads these from ITS environment; pass them
	// as explicit injection pairs so they bypass the ChildEnv allowlist
	// (external audit F-009). Exit 137 = the SIGKILL death code.
	spec.Env = append(spec.Env,
		"OPENCODE_FAKE_ARGS="+filepath.Join(dir, "args.txt"),
		"OPENCODE_FAKE_OUT="+outPath,
		"OPENCODE_FAKE_EXIT=137",
	)

	o := NewOpenCode(script)
	events := make(chan TurnEvent, 64)
	if err := o.StartTurn(context.Background(), spec, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	var evs []TurnEvent
	for ev := range events {
		evs = append(evs, ev)
	}
	var failed *TurnEvent
	for i := range evs {
		switch evs[i].Type {
		case EventTurnCompleted:
			t.Fatalf("a dead process must not complete the turn: %+v", evs)
		case EventTurnFailed:
			failed = &evs[i]
		}
	}
	if failed == nil {
		t.Fatalf("no turn.failed event after the process died mid-turn: %+v", evs)
	}
	if string(failed.FailureKind) != "process_error" {
		t.Fatalf("failure kind = %q, want process_error (error: %q)", failed.FailureKind, failed.Error)
	}
	if !strings.Contains(failed.Error, "137") {
		t.Fatalf("the process_error must carry the exit detail, got %q", failed.Error)
	}
	// The session is PRESERVED (captured when the session was confirmed,
	// before the death): the explicit retry resumes by the exact stored id.
	if id, err := readStoredSession(filepath.Join(spec.SessionDir, opencodeSessionFile)); err != nil || id != sid {
		t.Fatalf("stored session = %q, %v; want %q preserved for the retry", id, err, sid)
	}
}

// TestOpenCode_MCPConfigRendering: the daemon-rendered PAGNET_MCP_CONFIG is
// materialized as an opencode config in the instance's SessionDir (managed
// state, NEVER the workspace) with the pagnet bridge as a local stdio
// server, and OPENCODE_CONFIG points at it. The fixture is the daemon's
// self-spawn shape (packaging migration step 5): command is the daemon's
// own executable, args carry the mcp worker subcommand — opencode must
// materialize command+args as one local stdio command.
func TestOpenCode_MCPConfigRendering(t *testing.T) {
	const mcp = `{"mcpServers":{"pagnet":{"command":"/usr/local/bin/pagnet","args":["mcp","worker","--socket","/s/pagnetd.sock"],"env":{"PAGNET_INSTANCE_ID":"inst-1","PAGNET_NETWORK_ID":"net-1"}}}}`
	spec := opencodeSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG=" + mcp}
	runOpenCodeStub(t, spec, nil)

	cfgPath := filepath.Join(spec.SessionDir, "opencode.json")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("opencode config not written to the SessionDir: %v", err)
	}
	var cfg struct {
		MCP map[string]struct {
			Type        string            `json:"type"`
			Command     []string          `json:"command"`
			Enabled     bool              `json:"enabled"`
			Environment map[string]string `json:"environment"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("opencode config is not valid JSON: %v: %s", err, b)
	}
	srv, ok := cfg.MCP["pagnet"]
	if !ok {
		t.Fatalf("config missing the pagnet MCP server: %s", b)
	}
	if srv.Type != "local" || !srv.Enabled {
		t.Fatalf("pagnet server = %+v, want type=local enabled=true", srv)
	}
	wantCmd := []string{"/usr/local/bin/pagnet", "mcp", "worker", "--socket", "/s/pagnetd.sock"}
	if len(srv.Command) != len(wantCmd) {
		t.Fatalf("command = %v, want %v", srv.Command, wantCmd)
	}
	for i := range wantCmd {
		if srv.Command[i] != wantCmd[i] {
			t.Fatalf("command = %v, want %v", srv.Command, wantCmd)
		}
	}
	if srv.Environment["PAGNET_INSTANCE_ID"] != "inst-1" || srv.Environment["PAGNET_NETWORK_ID"] != "net-1" {
		t.Fatalf("environment = %v, want the instance identity", srv.Environment)
	}
	// No file is written into the workspace (the user's code dir stays
	// clean): the config lives only in the managed SessionDir.
	for _, e := range mustReadDir(t, spec.Workspace) {
		if e.Name() == "opencode.json" || e.Name() == ".opencode" {
			t.Fatalf("adapter wrote %s into the workspace (must stay in the SessionDir)", e.Name())
		}
	}
}

// TestOpenCode_InvalidMCPConfigFailsLoudly: a malformed PAGNET_MCP_CONFIG
// fails the turn before spawning (a turn that cannot inject its network
// tools does not run silently without them).
func TestOpenCode_InvalidMCPConfigFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "opencode")
	if err := os.WriteFile(script, []byte(fakeOpenCodeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	t.Setenv("OPENCODE_FAKE_ARGS", argsPath)

	o := NewOpenCode(script)
	spec := opencodeSpec(t.TempDir())
	spec.Env = []string{"PAGNET_MCP_CONFIG={not json"}
	events := make(chan TurnEvent, 8)
	if err := o.StartTurn(context.Background(), spec, events); err == nil {
		t.Fatal("want error: invalid PAGNET_MCP_CONFIG must not run silently")
	}
	if b, _ := os.ReadFile(argsPath); strings.TrimSpace(string(b)) != "" {
		t.Fatalf("process spawned despite invalid PAGNET_MCP_CONFIG (argv %s)", b)
	}
}

// mustReadDir is a small helper for the workspace-cleanliness assertion.
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read workspace dir: %v", err)
	}
	return entries
}
