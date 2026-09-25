package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
)

// OpenCode drives the opencode CLI (`opencode`) as a process-per-turn
// runtime (same contract as the Qwen and Claude adapters).
//
// Per-turn invocation (no shell, structured args only):
//
//	opencode run --format json [--model <provider/model>] [--session <id>] <prompt>
//
// The turn prompt is a POSITIONAL argument (`opencode run [message..]`) —
// opencode has no stdin prompt mode for `run`, so (unlike qwen/claude) the
// prompt rides on argv. Output is NDJSON (camelCase):
//
//	{"type":"step_start","timestamp":...,"sessionID":"ses_...","part":{"type":"step-start"}}
//	{"type":"text","timestamp":...,"sessionID":"ses_...","part":{"type":"text","text":"..."}}
//	{"type":"tool_use","timestamp":...,"sessionID":"ses_...","part":{"type":"tool",...}}
//	{"type":"step_finish","timestamp":...,"sessionID":"ses_...","part":{"type":"step-finish"}}
//	{"type":"error","timestamp":...,"sessionID":"ses_...","error":{...}}
//
// Session continuity: the sessionID is captured from the first event that
// carries it and persisted in <SessionDir>/session.json; a resume passes it
// via `--session <id>`. A resume that re-bases onto a different session, or
// a failed resume that never confirms the stored id, is surfaced as
// EventSessionLost — never a silent fresh session (§74/§88).
//
// User config is never touched and no file is written into the workspace.
// The instance-scoped opencode config (the PAGNET_MCP_CONFIG the daemon
// renders per instance, plus the standing document) is materialized in the
// instance's SessionDir (managed state, NEVER the workspace) and pointed at
// with OPENCODE_CONFIG: opencode has no inline --mcp-config flag — its MCP
// servers come from config, so the daemon's MCP bridge is written as a
// local stdio server there. The standing instructions (the pagnet overlay
// + the operator's standing instruction when set) ride the config's
// `instructions` surface — opencode's native standing-instruction class
// (additive context, the same class as AGENTS.md; it does NOT replace the
// system prompt) — as a file in the SessionDir, never the project's
// AGENTS.md.
//
// Model selection: OpenCode.Model (explicit) or the PAGNET_OPENCODE_MODEL
// environment; when empty the user's own default model applies. The model
// is `provider/model` (e.g. anthropic/claude-sonnet-4-5).
type OpenCode struct {
	// Binary is the path to the opencode executable. When empty it is
	// resolved from PATH / next to the current executable.
	Binary string
	// Model overrides the model for managed turns (empty = user default).
	Model string
	// Env is appended to the inherited environment for spawned processes.
	Env []string

	life lifecycleState
}

func NewOpenCode(binary string) *OpenCode {
	return &OpenCode{Binary: binary}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (o *OpenCode) SetLifecycle(l proc.Lifecycle) { o.life.SetLifecycle(l) }

func (o *OpenCode) Name() domain.RuntimeName { return domain.RuntimeOpenCode }

// Native-interaction capability model (plan §8.3): CONSERVATIVE. The
// surface the adapter consumes today carries no documented interaction
// hook, so the adapter reports it cannot observe, defer, or remote-resolve
// native interactions. The runtime DOES have a native interactive TUI (the
// PTY attach path). Wiring real observation is a follow-up — the flags flip
// only when a tested integration exists.
func (o *OpenCode) ObserveInteractions() bool               { return false }
func (o *OpenCode) NativeInteractiveUI() bool               { return true }
func (o *OpenCode) SupportsDeferredInteraction(string) bool { return false }
func (o *OpenCode) SupportsRemoteResolve(string) bool       { return false }

func (o *OpenCode) Available() bool {
	_, err := o.binary()
	return err == nil
}

func (o *OpenCode) BinaryPath() (string, bool) {
	p, err := o.binary()
	return p, err == nil
}

func (o *OpenCode) binary() (string, error) {
	if o.Binary != "" {
		if _, err := os.Stat(o.Binary); err == nil {
			return o.Binary, nil
		}
	}
	if p, err := exec.LookPath("opencode"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "opencode")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("opencode CLI not found on PATH")
}

// model returns the model override (explicit field, then env) or "".
func (o *OpenCode) model() string {
	if o.Model != "" {
		return o.Model
	}
	return os.Getenv("PAGNET_OPENCODE_MODEL")
}

const opencodeSessionFile = "session.json"

// StartTurn runs one opencode turn, streaming normalized events into events.
func (o *OpenCode) StartTurn(ctx context.Context, spec TurnSpec, events chan TurnEvent) error {
	defer close(events)
	bin, err := o.binary()
	if err != nil {
		return err
	}
	if spec.Workspace == "" {
		return fmt.Errorf("opencode adapter requires a workspace")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return err
	}
	sessionPath := filepath.Join(spec.SessionDir, opencodeSessionFile)
	stored, _ := readStoredSession(sessionPath)

	args := []string{"run", "--format", "json"}
	// Model precedence: the turn's resolved model (launch request >
	// definition default) wins over the adapter's own (field, then env).
	turnModel := spec.Model
	if turnModel == "" {
		turnModel = o.model()
	}
	if turnModel != "" {
		args = append(args, "--model", turnModel)
	}
	resuming := false
	if spec.Resume {
		if stored == "" {
			// A resume was requested but this host holds no stored session
			// id — report it honestly instead of starting fresh (§74/§88).
			events <- TurnEvent{Type: EventSessionLost, Error: "resume requested but no stored opencode session id"}
			return nil
		}
		args = append(args, "--session", stored)
		resuming = true
	}
	// The prompt is a positional argument (opencode run [message..]).
	args = append(args, spec.Input)

	// Materialize the instance-scoped opencode config in the managed state
	// dir (NEVER the workspace) and point OPENCODE_CONFIG at it: opencode
	// has no inline --mcp-config flag (its MCP servers come from config),
	// and the standing document rides the config's `instructions` surface
	// (the native standing-instruction class — additive context, never a
	// first-message concatenation, never the project's AGENTS.md). A
	// failure here is visible — the turn does not run silently without its
	// network tools.
	extraEnv := append([]string{}, o.Env...)
	mcpJSON := pagnetMCPConfig(spec.Env)
	if mcpJSON != "" || strings.TrimSpace(spec.StandingInstructions) != "" {
		cfgPath, err := writeOpenCodeConfig(spec.SessionDir, mcpJSON, spec.StandingInstructions)
		if err != nil {
			return err
		}
		extraEnv = append(extraEnv, "OPENCODE_CONFIG="+cfgPath)
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = EnsureTurnMarker(ChildEnv(extraEnv, spec.Env), spec.TurnID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	// The supervisor owns the Start, the process group (Setpgid), the
	// launch guards, and the lifecycle; its ctx watcher terminates the
	// whole group on cancellation.
	h, err := o.life.get().Launch(ctx, proc.LaunchRequest{
		InstanceID: spec.InstanceID,
		TurnID:     spec.TurnID,
		Runtime:    string(o.Name()),
		Class:      proc.ClassTurn,
		Cmd:        cmd,
		Marker:     "PAGNET_TURN_ID=" + spec.TurnID,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		sessionID        string
		terminal         bool
		cancelled        bool
		lastText         string
		errText          string
		sawStoredSession bool
	)
	emit := func(ev TurnEvent) {
		select {
		case events <- ev:
		case <-ctx.Done():
			// The supervisor's ctx watcher terminates the whole group;
			// the owner just stops emitting. defer h.Close() reaps.
			cancelled = true
		}
	}

	for scanner.Scan() {
		var ev opencodeEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		sid := ev.SessionID
		if sid != "" && sessionID == "" {
			if resuming && sid != stored {
				// A requested resume that re-bases onto a different
				// session is a lost session, not a silent fresh one.
				terminal = true
				h.Abort("session_mismatch")
				events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
					Error: "opencode resume started a different session (wanted " + stored + ", got " + sid + ")"}
				_ = h.Wait()
				return nil
			}
			sessionID = sid
			if resuming {
				sawStoredSession = true
			}
			if sid != "" {
				_ = writeStoredSession(sessionPath, sid)
			}
			if resuming {
				emit(TurnEvent{Type: EventSessionResumed, SessionID: sid})
			} else {
				emit(TurnEvent{Type: EventSessionStarted, SessionID: sid})
			}
			emit(TurnEvent{Type: EventTurnStarted, SessionID: sid})
		} else if resuming && sid == stored {
			// The stored session was confirmed on a later event (the first
			// event may carry no id): the resume is live, not lost.
			sawStoredSession = true
		}
		switch ev.Type {
		case "text":
			if ev.Part.Text != "" {
				lastText = ev.Part.Text
				emit(TurnEvent{Type: EventTurnOutput, Output: ev.Part.Text})
			}
		case "error":
			errText = opencodeErrorText(ev.Error)
		}
	}
	// A truncated stream (a line over the scanner buffer, or an I/O
	// error) is a failure, not a clean exit — surface it instead of
	// treating the partial stream as completed (external audit F-012).
	if scanErr := scanner.Err(); scanErr != nil {
		if proc.GroupAlive(h.PGID()) {
			h.Terminate("scan_error")
		}
		_ = h.Wait()
		if cancelled {
			return ctx.Err()
		}
		events <- TurnEvent{
			Type:        EventTurnFailed,
			FailureKind: domain.RuntimeFailureProcessError,
			Error:       fmt.Sprintf("opencode stream error: %v", scanErr),
		}
		return nil
	}

	// NOTE (pipe-hold): unlike qwen/claude, `opencode run --format json`
	// emits no terminal event in the stream — the turn ends when the
	// process exits. So there is no early-break signal here; a
	// descendant holding the stdout pipe blocks until the turn's context
	// expires, at which point the supervisor's ctx watcher terminates the
	// whole group. Bounded, by design.
	//
	// Owner's reap (single Wait) after all stdout is drained; also
	// reclaims any descendants that outlived the runtime (§19/§24).
	waitErr := h.Wait()
	if cancelled {
		return ctx.Err()
	}
	if terminal {
		// The turn ended with a normalized event; a non-zero exit after a
		// reported failure is expected and adds nothing.
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A failed resume that never confirmed the stored session is a lost
	// session, not a turn failure (the stored id does not exist on this
	// host) — never a silent fresh session (§74/§88).
	if resuming && !sawStoredSession {
		events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
			Error: trunc(firstNonEmpty(errText, stderrBuf.String(),
				"opencode resume failed without confirming the stored session"))}
		return nil
	}
	if errText != "" {
		kind, retryAt := ClassifyProviderError(trunc(errText), trunc(lastText))
		events <- TurnEvent{Type: EventTurnFailed, FailureKind: kind,
			Error: trunc(firstNonEmpty(errText, lastText)), RetryAt: retryAt}
		return nil
	}
	if waitErr != nil {
		// Exited non-zero without a structured error: provider-shaped
		// stderr is classified; anything else is a process-level failure.
		kind := domain.RuntimeFailureProcessError
		var retryAt *string
		if LooksLikeProviderError(trunc(stderrBuf.String())) {
			kind, retryAt = ClassifyProviderError(trunc(stderrBuf.String()))
		}
		events <- TurnEvent{Type: EventTurnFailed, FailureKind: kind,
			Error: trunc(firstNonEmpty(stderrBuf.String(), waitErr.Error())), RetryAt: retryAt}
		return nil
	}
	// Exited cleanly: the one-shot run finished the turn.
	events <- TurnEvent{Type: EventTurnCompleted, Model: turnModel}
	return nil
}

// Stop kills the running process for an instance.
func (o *OpenCode) Stop(instanceID string) error { return o.life.get().Stop(instanceID) }

func (o *OpenCode) PID(instanceID string) *int { return o.life.get().PID(instanceID) }

// InteractiveCmd builds the interactive opencode TUI (the PTY terminal,
// addendum §7/§8): the default interactive mode (no `run`), with the same
// model override, session resume, and OPENCODE_CONFIG bridge as a turn. Not
// started: the daemon runs it under a PTY and owns its lifecycle.
func (o *OpenCode) InteractiveCmd(spec TurnSpec) (*exec.Cmd, error) {
	bin, err := o.binary()
	if err != nil {
		return nil, err
	}
	if spec.Workspace == "" {
		return nil, fmt.Errorf("opencode adapter requires a workspace")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	var args []string
	// Model precedence: the turn's resolved model wins over the adapter's
	// own (field, then env).
	turnModel := spec.Model
	if turnModel == "" {
		turnModel = o.model()
	}
	if turnModel != "" {
		args = append(args, "--model", turnModel)
	}
	if spec.Resume {
		stored, _ := readStoredSession(filepath.Join(spec.SessionDir, opencodeSessionFile))
		if stored != "" {
			args = append(args, "--session", stored)
		}
	}
	// Same instance-scoped config as a turn: the interactive TUI gets its
	// network tools from the daemon's MCP bridge and its standing context
	// from the config's `instructions` surface.
	extraEnv := append([]string{}, o.Env...)
	mcpJSON := pagnetMCPConfig(spec.Env)
	if mcpJSON != "" || strings.TrimSpace(spec.StandingInstructions) != "" {
		cfgPath, err := writeOpenCodeConfig(spec.SessionDir, mcpJSON, spec.StandingInstructions)
		if err != nil {
			return nil, err
		}
		extraEnv = append(extraEnv, "OPENCODE_CONFIG="+cfgPath)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(extraEnv, spec.Env)
	return cmd, nil
}

// writeOpenCodeConfig materializes the instance-scoped opencode config in
// the instance's SessionDir (managed state, never the workspace) and
// returns the config path ("" when there is nothing to materialize). It
// carries the two pagnet-managed surfaces:
//
//   - mcp: the daemon-rendered PAGNET_MCP_CONFIG ({"mcpServers": {...}})
//     as a local stdio server — opencode has no inline --mcp-config flag,
//     so its MCP servers come from config.
//   - instructions: the standing document (the pagnet overlay + the
//     operator's standing instruction when set) as an instruction file —
//     opencode's native standing-instruction surface (the same class as
//     AGENTS.md: additive standing context, NOT a system-prompt
//     replacement). The file is written into the SessionDir (standing.md)
//     and referenced by absolute path; the project's AGENTS.md is never
//     touched.
//
// The config is pointed at with OPENCODE_CONFIG — instance-scoped, so the
// user's own opencode config is untouched.
func writeOpenCodeConfig(sessionDir, mcpJSON, standingInstructions string) (string, error) {
	cfg := map[string]any{}
	if mcpJSON != "" {
		var src struct {
			MCPServers map[string]struct {
				Command string            `json:"command"`
				Args    []string          `json:"args"`
				Env     map[string]string `json:"env"`
			} `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(mcpJSON), &src); err != nil {
			return "", fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
		}
		if len(src.MCPServers) == 0 {
			return "", fmt.Errorf("PAGNET_MCP_CONFIG has no mcpServers")
		}
		mcp := map[string]any{}
		for name, s := range src.MCPServers {
			if s.Command == "" {
				return "", fmt.Errorf("PAGNET_MCP_CONFIG server %q has no command", name)
			}
			entry := map[string]any{
				"type":    "local",
				"command": append([]string{s.Command}, s.Args...),
				"enabled": true,
			}
			if len(s.Env) > 0 {
				entry["environment"] = s.Env
			}
			mcp[name] = entry
		}
		cfg["mcp"] = mcp
	}
	if strings.TrimSpace(standingInstructions) != "" {
		if err := os.MkdirAll(sessionDir, 0o700); err != nil { // SEC-415: runtime state
			return "", err
		}
		standingPath := filepath.Join(sessionDir, "standing.md")
		if err := os.WriteFile(standingPath, []byte(standingInstructions), 0o600); err != nil {
			return "", err
		}
		cfg["instructions"] = []string{standingPath}
	}
	if len(cfg) == 0 {
		return "", nil
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(sessionDir, 0o700); err != nil { // SEC-415: runtime state
		return "", err
	}
	path := filepath.Join(sessionDir, "opencode.json")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// --- opencode --format json wire shapes --------------------------------------

type opencodeEvent struct {
	Type      string          `json:"type"`
	Timestamp int64           `json:"timestamp"`
	SessionID string          `json:"sessionID"`
	Part      opencodePart    `json:"part"`
	Error     json.RawMessage `json:"error"`
}

type opencodePart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// opencodeErrorText extracts a human-readable message from an opencode
// error event's `error` field, which is either a plain string or an object
// carrying a message. It falls back to the raw JSON so nothing is lost.
func opencodeErrorText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var e struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &e); err == nil && e.Message != "" {
		return e.Message
	}
	return strings.TrimSpace(string(raw))
}
