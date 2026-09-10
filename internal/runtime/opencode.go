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

	"pagnet/internal/domain"
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
// MCP injection (the PAGNET_MCP_CONFIG the daemon renders per instance) is
// materialized as an opencode config in the instance's SessionDir (managed
// state, NEVER the workspace) and pointed at with OPENCODE_CONFIG: opencode
// has no inline --mcp-config flag — its MCP servers come from config, so the
// daemon's pagnet-mcp bridge is written as a local stdio server there.
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

	track procTracker
}

func NewOpenCode(binary string) *OpenCode {
	return &OpenCode{Binary: binary, track: procTracker{procs: map[string]*exec.Cmd{}}}
}

func (o *OpenCode) Name() domain.RuntimeName { return domain.RuntimeOpenCode }

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

	// Materialize the MCP bridge as an opencode config in the managed state
	// dir (NEVER the workspace) and point OPENCODE_CONFIG at it: opencode
	// has no inline --mcp-config flag, its MCP servers come from config. A
	// failure here is visible — the turn does not run silently without its
	// network tools.
	extraEnv := append([]string{}, o.Env...)
	if mcpJSON := pagnetMCPConfig(spec.Env); mcpJSON != "" {
		cfgPath, err := writeOpenCodeMCPConfig(spec.SessionDir, mcpJSON)
		if err != nil {
			return err
		}
		extraEnv = append(extraEnv, "OPENCODE_CONFIG="+cfgPath)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(extraEnv, spec.Env)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn opencode: %w", err)
	}
	o.track.track(spec.InstanceID, cmd)
	defer o.track.release(spec.InstanceID, cmd)

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
			cancelled = true
			_ = cmd.Process.Kill()
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
				_ = cmd.Process.Kill()
				events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
					Error: "opencode resume started a different session (wanted " + stored + ", got " + sid + ")"}
				_ = cmd.Wait()
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

	waitErr := cmd.Wait()
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
func (o *OpenCode) Stop(instanceID string) error { return o.track.stop(instanceID) }

func (o *OpenCode) PID(instanceID string) *int { return o.track.pid(instanceID) }

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
	// Same MCP bridge injection as a turn: the interactive TUI gets its
	// network tools from the daemon's pagnet-mcp bridge via the config.
	extraEnv := append([]string{}, o.Env...)
	if mcpJSON := pagnetMCPConfig(spec.Env); mcpJSON != "" {
		cfgPath, err := writeOpenCodeMCPConfig(spec.SessionDir, mcpJSON)
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

// writeOpenCodeMCPConfig materializes the daemon-rendered PAGNET_MCP_CONFIG
// ({"mcpServers": {...}}) as an opencode config in the instance's SessionDir
// (managed state, never the workspace) and returns the config path. opencode
// has no inline --mcp-config flag — its MCP servers come from config — so the
// daemon's pagnet-mcp bridge is written as a local stdio server
// ({"mcp": {name: {type:"local", command:[...], environment:{...}}}}) and
// pointed at with OPENCODE_CONFIG.
func writeOpenCodeMCPConfig(sessionDir, mcpJSON string) (string, error) {
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
	cfg := map[string]any{"mcp": mcp}
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
