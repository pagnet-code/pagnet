//go:build linux || darwin

package runtime

// Qwen Dual Output driver-level tests (runtime-lifecycle refactor, Phase 4).
//
// These tests drive the QwenPersistent driver against a STUB qwen CLI (a
// shell script that records its argv and writes a scripted session_start
// handshake to the events file). They exercise the REAL driver logic
// (launch, argv construction, input-file discipline, resume validation,
// lost-session mapping) without a reachable model — CI-safe.
//
// The endpoint is launched with the stdio-to-tty shape (PTYStdio, B1), so
// these tests require a PTY (Linux / Darwin).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// fakeQwenPersistentScript is a stub qwen CLI for the driver-level tests.
// It records its argv, then (unless told to simulate "No saved session
// found") writes a scripted session_start handshake to the --json-file and
// stays alive. The session id is the -r value (resume) or QWEN_FAKE_SID
// (cold start).
const fakeQwenPersistentScript = `#!/usr/bin/env bash
: > "$QWEN_FAKE_ARGS"
for a in "$@"; do
  printf '%s\n' "$a" >> "$QWEN_FAKE_ARGS"
done
JSON_FILE=""
INPUT_FILE=""
RESUME_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json-file) JSON_FILE="$2"; shift ;;
    --input-file) INPUT_FILE="$2"; shift ;;
    -r) RESUME_ID="$2"; shift ;;
  esac
  shift
done
if [ -n "$QWEN_FAKE_NO_SESSION" ]; then
  printf 'No saved session found\n' >&2
  exit 1
fi
SID="${RESUME_ID:-${QWEN_FAKE_SID:-11111111-aaaa-bbbb-cccc-111111111111}}"
CWD="$(pwd)"
cat > "$JSON_FILE" <<EOF
{"type":"system","subtype":"session_start","session_id":"$SID","data":{"session_id":"$SID","cwd":"$CWD","protocol_version":2,"version":"0.23.4","supported_events":["system","user","assistant","stream_event","control_request","control_response"]}}
EOF
sleep 3600
`

// newQwenPersistentFixture builds a QwenPersistent driver with a stub
// binary and a temp state dir. It returns the driver, the workspace, the
// state dir, the argv file path, and the stub env pairs (to be added to
// sess.Env — the child's environment, which bypasses the ChildEnv
// allowlist, external audit F-009).
func newQwenPersistentFixture(t *testing.T, noSession bool) (*QwenPersistent, string, string, string, []string) {
	t.Helper()
	dir := t.TempDir()
	workspace := t.TempDir()
	stateDir := t.TempDir()
	script := filepath.Join(dir, "qwen")
	if err := os.WriteFile(script, []byte(fakeQwenPersistentScript), 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args.txt")
	// The state dir is read by the DRIVER (the test process), so t.Setenv
	// works for it.
	t.Setenv("PAGNET_STATE_DIR", stateDir)
	// The stub env vars are read by the CHILD (the stub script), so they
	// must be in the child's environment (sess.Env).
	stubEnv := []string{"QWEN_FAKE_ARGS=" + argsPath}
	if noSession {
		stubEnv = append(stubEnv, "QWEN_FAKE_NO_SESSION=1")
	}
	q := NewQwenPersistent(script)
	return q, workspace, stateDir, argsPath, stubEnv
}

// readArgv reads the recorded argv (one arg per line).
func readArgv(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	var argv []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			argv = append(argv, line)
		}
	}
	return argv
}

// argAfter returns the argument following flag in argv ("" when absent).
func qwenArgAfter(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// TestQwenPersistent_LaunchAndInputFile verifies the cold-start launch:
// the argv carries --json-file / --input-file, the input file is created
// fresh (0600 REGULAR, not a FIFO), and the session metadata (id + exact
// cwd) is persisted from the handshake.
func TestQwenPersistent_LaunchAndInputFile(t *testing.T) {
	q, workspace, stateDir, argsPath, stubEnv := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
		Env:        stubEnv,
	}
	events := make(chan session.SessionEvent, 8)
	ep, err := q.Activate(context.Background(), sess, events)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if ep == nil {
		t.Fatal("Activate returned nil endpoint")
	}
	if sess.NativeID == "" {
		t.Fatal("NativeID not set after activation")
	}

	// The argv carries the machine-plane file paths.
	argv := readArgv(t, argsPath)
	if qwenArgAfter(argv, "--json-file") == "" {
		t.Fatalf("--json-file not in argv: %v", argv)
	}
	if qwenArgAfter(argv, "--input-file") == "" {
		t.Fatalf("--input-file not in argv: %v", argv)
	}
	// No -r on a cold start.
	if qwenArgAfter(argv, "-r") != "" {
		t.Fatalf("-r in a cold-start argv: %v", argv)
	}

	// The input file is created fresh (0600 REGULAR, not a FIFO).
	inputPath := filepath.Join(stateDir, "qwen", "inst-1", "input.jsonl")
	fi, err := os.Stat(inputPath)
	if err != nil {
		t.Fatalf("input file not created: %v", err)
	}
	if fi.Mode()&os.ModeType != 0 {
		t.Fatalf("input file is not a regular file: %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("input file mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi.Size() != 0 {
		t.Fatalf("input file is not fresh (size %d, want 0)", fi.Size())
	}

	// The session metadata (id + exact cwd) is persisted from the handshake.
	metaPath := filepath.Join(stateDir, "qwen", "inst-1", "session.json")
	id, cwd, err := readStoredQwenSession(metaPath)
	if err != nil {
		t.Fatalf("session metadata not persisted: %v", err)
	}
	if id == "" {
		t.Fatal("session id not persisted")
	}
	if cwd != workspace {
		t.Fatalf("stored cwd = %q, want %q (byte-identical)", cwd, workspace)
	}

	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_ResumeArgv verifies the resume launch: a materialised
// session with a stored (valid UUID) id is relaunched with -r <id>, and the
// handshake re-bases onto the SAME session (session.resumed).
func TestQwenPersistent_ResumeArgv(t *testing.T) {
	q, workspace, _, argsPath, stubEnv := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
		Env:        stubEnv,
	}
	// Cold start (persists the session id + cwd).
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
		t.Fatalf("cold Activate: %v", err)
	}
	resumeID := sess.NativeID
	if resumeID == "" {
		t.Fatal("NativeID not set after cold start")
	}
	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Resume (the stored id is now the resume target).
	sess.Materialised = true
	events := make(chan session.SessionEvent, 8)
	if _, err := q.Activate(context.Background(), sess, events); err != nil {
		t.Fatalf("resume Activate: %v", err)
	}
	// The argv carries -r <id>.
	argv := readArgv(t, argsPath)
	if got := qwenArgAfter(argv, "-r"); got != resumeID {
		t.Fatalf("-r = %q, want %q (argv %v)", got, resumeID, argv)
	}
	// The activation event is session.resumed (the same session).
	var actEv session.SessionEvent
	select {
	case actEv = <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("no activation event")
	}
	if actEv.Type != session.EventSessionResumed {
		t.Fatalf("activation event = %q, want %q", actEv.Type, session.EventSessionResumed)
	}
	if actEv.SessionID != resumeID {
		t.Fatalf("resumed session id = %q, want %q", actEv.SessionID, resumeID)
	}
	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestQwenPersistent_ResumeNonUUIDRefused verifies that a stored session id
// that is not a valid UUID is refused client-side (a non-UUID -r becomes a
// silent title lookup — doc §5.2). No process is launched.
func TestQwenPersistent_ResumeNonUUIDRefused(t *testing.T) {
	q, workspace, _, argsPath, stubEnv := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{
		InstanceID:   "inst-1",
		Runtime:      domain.RuntimeQwenCode,
		Workspace:    workspace,
		Env:          stubEnv,
		NativeID:     "not-a-uuid",
		Materialised: true,
	}
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	if err == nil {
		t.Fatal("Activate succeeded, want a refusal for a non-UUID resume id")
	}
	if !strings.Contains(err.Error(), "not a valid UUID") {
		t.Fatalf("error = %q, want a non-UUID refusal", err.Error())
	}
	// No process was launched (no argv recorded).
	if _, statErr := os.Stat(argsPath); !os.IsNotExist(statErr) {
		t.Fatalf("argv file exists (a process was launched): %v", statErr)
	}
}

// TestQwenPersistent_ResumeCWDDriftRefused verifies that a resume with a
// cwd drift (the stored cwd != the current workspace) is refused (a cwd
// drift makes the resume look like a lost session — doc §5.3).
func TestQwenPersistent_ResumeCWDDriftRefused(t *testing.T) {
	q, workspace, stateDir, _, stubEnv := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
		Env:        stubEnv,
	}
	// Cold start (persists the session id + cwd).
	if _, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8)); err != nil {
		t.Fatalf("cold Activate: %v", err)
	}
	resumeID := sess.NativeID
	if err := q.Stop("inst-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Resume with a DIFFERENT workspace (cwd drift).
	otherWorkspace := t.TempDir()
	sess.Workspace = otherWorkspace
	sess.Materialised = true
	_, err := q.Activate(context.Background(), sess, make(chan session.SessionEvent, 8))
	if err == nil {
		t.Fatal("Activate succeeded, want a cwd-drift refusal")
	}
	if !strings.Contains(err.Error(), "cwd drift") {
		t.Fatalf("error = %q, want a cwd-drift refusal", err.Error())
	}
	// The session metadata is unchanged (the drift was detected, not
	// overwritten).
	_, cwd, rerr := readStoredQwenSession(filepath.Join(stateDir, "qwen", "inst-1", "session.json"))
	if rerr != nil {
		t.Fatalf("read session metadata: %v", rerr)
	}
	if cwd != workspace {
		t.Fatalf("stored cwd = %q, want the original %q", cwd, workspace)
	}
	_ = resumeID
}

// TestQwenPersistent_LostSession verifies that a resume whose process exits
// 1 before writing the events file ("No saved session found" — doc §5.2)
// maps to session.lost (ErrSessionLost), never a silent fresh session.
func TestQwenPersistent_LostSession(t *testing.T) {
	q, workspace, _, _, stubEnv := newQwenPersistentFixture(t, true) // noSession = true
	sess := &session.RuntimeSession{
		InstanceID:   "inst-1",
		Runtime:      domain.RuntimeQwenCode,
		Workspace:    workspace,
		Env:          stubEnv,
		NativeID:     "33333333-aaaa-bbbb-cccc-333333333333",
		Materialised: true,
	}
	events := make(chan session.SessionEvent, 8)
	_, err := q.Activate(context.Background(), sess, events)
	if !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("Activate error = %v, want ErrSessionLost", err)
	}
	// The activation event is session.lost.
	var actEv session.SessionEvent
	select {
	case actEv = <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("no activation event")
	}
	if actEv.Type != session.EventSessionLost {
		t.Fatalf("activation event = %q, want %q", actEv.Type, session.EventSessionLost)
	}
}

// TestQwenPersistent_WriteInput verifies the input-file writer discipline
// (B6): append-only, one \n-terminated JSON line per write, the exact two
// command shapes (submit / confirmation_response).
func TestQwenPersistent_WriteInput(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.jsonl")
	f, err := os.OpenFile(inputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	e := &qwenEndpoint{inputFile: f}
	// A submit.
	if err := e.writeInput(qwenInputCmd{Type: "submit", Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	// A confirmation_response (allowed).
	allowed := true
	if err := e.writeInput(qwenInputCmd{Type: "confirmation_response", RequestID: "req-1", Allowed: &allowed}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	// One \n-terminated JSON line per write (two writes, two lines).
	if !strings.HasSuffix(string(b), "\n") {
		t.Fatalf("input file does not end with \\n: %q", string(b))
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("input file has %d lines, want 2: %q", len(lines), string(b))
	}
	var cmd1 qwenInputCmd
	if err := json.Unmarshal([]byte(lines[0]), &cmd1); err != nil {
		t.Fatal(err)
	}
	if cmd1.Type != "submit" || cmd1.Text != "hello" {
		t.Fatalf("first line = %+v, want submit/hello", cmd1)
	}
	var cmd2 qwenInputCmd
	if err := json.Unmarshal([]byte(lines[1]), &cmd2); err != nil {
		t.Fatal(err)
	}
	if cmd2.Type != "confirmation_response" || cmd2.RequestID != "req-1" || cmd2.Allowed == nil || !*cmd2.Allowed {
		t.Fatalf("second line = %+v, want confirmation_response/req-1/true", cmd2)
	}
}

// waitForInputLine polls the endpoint's input file until one line contains
// want (or the deadline passes). The driver writes the submit line AFTER it
// has registered the machine turn, so once the line is on disk the turn is
// genuinely in flight — the deterministic sync point for "kill it mid-turn".
func waitForInputLine(t *testing.T, path, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), want) {
			return
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(path)
			t.Fatalf("input file %s never carried %q within %v; content=%q", path, want, timeout, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestQwenPersistent_EndpointDiesMidTurn is the stuck-instance regression.
//
// The endpoint PROCESS dies while a machine turn is in flight (a vendor
// crash, SIGKILL, OOM, or a daemon-side interruption — the WHY does not
// matter, the state machine must tolerate all of them). Both routeEvent (a
// NORMAL terminal runtime event) and cleanupOnExit (the process died) close
// the SAME turnDone channel, so without an explicit per-turn reason Submit's
// `case <-done` cannot tell a settled turn from a cut-off one: it returned
// nil, the Manager treated the submit as normally settled even though the
// events stream carried NO terminal turn event, and the instance could stay
// persisted as working with no live endpoint — permanently unattachable
// ("endpoint is not active; attach refused").
//
// The driver must report session.ErrEndpointGone (the contract
// persistent_fake.go already honors) so the Manager re-activates and retries
// the logical submit instead of wedging.
func TestQwenPersistent_EndpointDiesMidTurn(t *testing.T) {
	q, workspace, stateDir, _, stubEnv := newQwenPersistentFixture(t, false)
	sess := &session.RuntimeSession{
		InstanceID: "inst-1",
		Runtime:    domain.RuntimeQwenCode,
		Workspace:  workspace,
		Env:        stubEnv,
	}
	events := make(chan session.SessionEvent, 8)
	if _, err := q.Activate(context.Background(), sess, events); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	pid := q.PID("inst-1")
	if pid == nil {
		t.Fatal("PID is nil after activation")
	}

	turnEvents := make(chan session.SessionEvent, 16)
	submitErr := make(chan error, 1)
	go func() {
		submitErr <- q.Submit(context.Background(), sess, session.SubmitRequest{
			TurnID: "die-1", Kind: session.SubmitPrompt, Input: "hello",
		}, turnEvents)
	}()

	inputPath := filepath.Join(stateDir, "qwen", "inst-1", "input.jsonl")
	waitForInputLine(t, inputPath, `"type":"submit"`, 10*time.Second)

	// Kill the endpoint mid-turn. The stub never produced a terminal event.
	if err := syscall.Kill(*pid, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL %d: %v", *pid, err)
	}

	select {
	case err := <-submitErr:
		if !errors.Is(err, session.ErrEndpointGone) {
			t.Fatalf("Submit = %v, want session.ErrEndpointGone (a mid-turn endpoint death is NOT a settled turn and NOT a generic process error)", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Submit did not return after the endpoint died mid-turn")
	}

	// The turn was CUT OFF: its stream carries no terminal event (nothing
	// may be fabricated for it).
	select {
	case ev := <-turnEvents:
		t.Fatalf("the cut-off turn's stream carries %q; a mid-turn death must not produce a terminal event", ev.Type)
	default:
	}

	// The endpoint record is gone (the reader's exit path dropped it), so a
	// follow-up submit on the same record is refused as endpoint-gone too.
	if q.Live("inst-1") {
		t.Fatal("endpoint still live after the kill")
	}
	if err := q.Submit(context.Background(), sess, session.SubmitRequest{
		TurnID: "die-2", Kind: session.SubmitPrompt, Input: "again",
	}, make(chan session.SessionEvent, 4)); !errors.Is(err, session.ErrEndpointGone) {
		t.Fatalf("Submit after the death = %v, want session.ErrEndpointGone", err)
	}
	_ = q.Stop("inst-1")
}
