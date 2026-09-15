package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
)

// Claude drives the Claude Code CLI (`claude`) as a process-per-turn
// runtime (addendum Phase E: real session ids, exact-id resume, token
// metadata, availability classification).
//
// Per-turn invocation (no shell, structured args only):
//
//	claude -p --verbose --output-format stream-json \
//	    [--model <model>] [--resume <session-id>] [--mcp-config <json>] \
//	    --permission-mode bypassPermissions
//
// with the turn prompt on STDIN (text input). Output is NDJSON:
//
//	{"type":"system","subtype":"init","session_id":...,"model":...}
//	{"type":"assistant","message":{"model":...,"content":[{"type":"text","text":...}]}}
//	{"type":"result","session_id":...,"is_error":...,"result":...,"usage":{...}}
//
// Session continuity (Phase E): Claude scopes sessions to the working
// directory and assigns the id on init. The adapter captures the EXACT id
// and persists it in <SessionDir>/session.json; a resume passes it via
// `--resume <id>`. A resume that starts a different session, or exits with
// "No conversation found with session ID", is surfaced as EventSessionLost
// — never a silent fresh session (§74/§88).
//
// User config is never touched. MCP injection (the PAGNET_MCP_CONFIG the
// daemon renders per instance) is passed as an inline --mcp-config JSON
// string: it merges with the user's own MCP servers without writing any
// file, so there is nothing to clobber and the global user config is
// untouched (rule 11).
//
// Model selection: Claude.Model (explicit) or the PAGNET_CLAUDE_MODEL
// environment; when empty the user's own default model applies.
type Claude struct {
	// Binary is the path to the claude executable. When empty it is
	// resolved from PATH / next to the current executable.
	Binary string
	// Model overrides the model for managed turns (empty = user default).
	Model string
	// Env is appended to the inherited environment for spawned processes.
	Env []string

	life lifecycleState
}

func NewClaude(binary string) *Claude {
	return &Claude{Binary: binary}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (c *Claude) SetLifecycle(l proc.Lifecycle) { c.life.SetLifecycle(l) }

func (c *Claude) Name() domain.RuntimeName { return domain.RuntimeClaudeCode }

// Native-interaction capability model (plan §8.3): CONSERVATIVE. The
// stream-json surface the adapter consumes today carries no documented
// interaction hook, so the adapter reports it cannot observe, defer, or
// remote-resolve native interactions. The runtime DOES have a native
// interactive TUI (the PTY attach path). Wiring real observation is a
// follow-up — the flags flip only when a tested integration exists.
func (c *Claude) ObserveInteractions() bool               { return false }
func (c *Claude) NativeInteractiveUI() bool               { return true }
func (c *Claude) SupportsDeferredInteraction(string) bool { return false }
func (c *Claude) SupportsRemoteResolve(string) bool       { return false }

func (c *Claude) Available() bool {
	_, err := c.binary()
	return err == nil
}

func (c *Claude) BinaryPath() (string, bool) {
	p, err := c.binary()
	return p, err == nil
}

func (c *Claude) binary() (string, error) {
	if c.Binary != "" {
		if _, err := os.Stat(c.Binary); err == nil {
			return c.Binary, nil
		}
	}
	if p, err := exec.LookPath("claude"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "claude")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("claude CLI not found on PATH")
}

// model returns the model override (explicit field, then env) or "".
func (c *Claude) model() string {
	if c.Model != "" {
		return c.Model
	}
	return os.Getenv("PAGNET_CLAUDE_MODEL")
}

// pagnetMCPConfig extracts the daemon-rendered PAGNET_MCP_CONFIG
// (inline JSON: {"mcpServers": {...}}) from the turn's env, "" when absent.
func pagnetMCPConfig(env []string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "PAGNET_MCP_CONFIG=") {
			return strings.TrimPrefix(kv, "PAGNET_MCP_CONFIG=")
		}
	}
	return ""
}

const (
	claudeSessionFile = "session.json"
	// claudeMissingSession is the CLI's error text when a resumed session
	// id does not exist on this host (stderr and result.errors).
	claudeMissingSession = "No conversation found with session ID"
)

// StartTurn runs one Claude turn, streaming normalized events into events.
func (c *Claude) StartTurn(ctx context.Context, spec TurnSpec, events chan TurnEvent) error {
	defer close(events)
	bin, err := c.binary()
	if err != nil {
		return err
	}
	if spec.Workspace == "" {
		return fmt.Errorf("claude adapter requires a workspace (claude sessions are CWD-scoped)")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return err
	}
	sessionPath := filepath.Join(spec.SessionDir, claudeSessionFile)
	stored, _ := readStoredSession(sessionPath)

	// --permission-mode bypassPermissions is the EXPLICIT permission
	// config for the UNATTENDED managed turn (external audit F-014): no
	// human is present to approve tool use, so the turn must act without
	// approval. This is deliberate and scoped to managed turns only — the
	// interactive REPL (InteractiveCmd) does NOT carry it, so a human in
	// the TUI keeps the CLI's normal approve/deny flow.
	args := []string{"-p", "--verbose", "--output-format", "stream-json",
		"--permission-mode", "bypassPermissions"}
	// Model precedence: the turn's resolved model (launch request >
	// definition default) wins over the adapter's own (field, then env).
	turnModel := spec.Model
	if turnModel == "" {
		turnModel = c.model()
	}
	if turnModel != "" {
		args = append(args, "--model", turnModel)
	}
	// Standing instruction (AGENT.md): native extra system context. The
	// file lives in the daemon state dir (never the workspace) and is
	// re-applied every turn, so it persists across the session.
	if spec.AgentMDPath != "" {
		args = append(args, "--append-system-prompt-file", spec.AgentMDPath)
	}
	resuming := false
	if spec.Resume {
		if stored == "" {
			// A resume was requested but this host holds no stored session
			// id — report it honestly instead of starting fresh (§74/§88).
			events <- TurnEvent{Type: EventSessionLost, Error: "resume requested but no stored claude session id"}
			return nil
		}
		args = append(args, "--resume", stored)
		resuming = true
	}
	// Inject the MCP bridge as an inline --mcp-config (merges with the
	// user's own MCP servers, writes no file). A failure here is visible
	// — the turn does not run silently without its network tools.
	if mcpJSON := pagnetMCPConfig(spec.Env); mcpJSON != "" {
		var cfg struct {
			MCPServers map[string]any `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(mcpJSON), &cfg); err != nil {
			return fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
		}
		if len(cfg.MCPServers) == 0 {
			return fmt.Errorf("PAGNET_MCP_CONFIG has no mcpServers")
		}
		args = append(args, "--mcp-config", mcpJSON)
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = EnsureTurnMarker(ChildEnv(c.Env, spec.Env), spec.TurnID)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	// The supervisor owns the Start, the process group (Setpgid), the
	// launch guards, and the lifecycle; its ctx watcher terminates the
	// whole group on cancellation.
	h, err := c.life.get().Launch(ctx, proc.LaunchRequest{
		InstanceID: spec.InstanceID,
		TurnID:     spec.TurnID,
		Runtime:    string(c.Name()),
		Class:      proc.ClassTurn,
		Cmd:        cmd,
		Marker:     "PAGNET_TURN_ID=" + spec.TurnID,
	})
	if err != nil {
		return err
	}
	defer h.Close()

	// The prompt goes on stdin: no ARG_MAX limit, no shell, no quoting.
	_, _ = io.WriteString(stdin, spec.Input)
	_ = stdin.Close()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		sessionID string
		model     string
		terminal  bool
		cancelled bool
		lastText  string
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
		var ev claudeEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "system":
			if ev.Subtype != "init" {
				continue
			}
			sid := ev.SessionID
			if resuming && sid != "" && sid != stored {
				// A requested resume that re-bases onto a different
				// session is a lost session, not a silent fresh one.
				terminal = true
				h.Abort("session_mismatch")
				events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
					Error: "claude resume started a different session (wanted " + stored + ", got " + sid + ")"}
				_ = h.Wait()
				return nil
			}
			sessionID = sid
			model = ev.Model
			if sid != "" {
				_ = writeStoredSession(sessionPath, sid)
			}
			if resuming {
				emit(TurnEvent{Type: EventSessionResumed, SessionID: sid})
			} else {
				emit(TurnEvent{Type: EventSessionStarted, SessionID: sid})
			}
			emit(TurnEvent{Type: EventTurnStarted, SessionID: sid})
		case "assistant":
			if m := ev.Message.Model; m != "" && m != "<synthetic>" {
				model = m
			}
			for _, part := range ev.Message.Content {
				if part.Type == "text" && part.Text != "" {
					lastText = part.Text
					emit(TurnEvent{Type: EventTurnOutput, Output: part.Text})
				}
			}
		case "result":
			if ev.SessionID != "" {
				sessionID = ev.SessionID
				_ = writeStoredSession(sessionPath, sessionID)
			}
			terminal = true
			// (Only ev.Errors is safe to read here; stderrBuf is owned by
			// the copy goroutine until cmd.Wait below.)
			if resuming && errorsIndicateMissingSession(ev.Errors) {
				// §74/§88: the stored session does not exist on this
				// host. Report it as lost — never a silent fresh session.
				emit(TurnEvent{Type: EventSessionLost, SessionID: stored,
					Error: trunc(claudeMissingSession + ": " + stored)})
				break
			}
			if ev.IsError {
				// A reported failure: classify the text the CLI put on
				// the result line (result + errors carry the full
				// message; stderr is only read after Wait).
				kind, retryAt := ClassifyProviderError(trunc(ev.Result),
					trunc(strings.Join(ev.Errors, "\n")))
				emit(TurnEvent{Type: EventTurnFailed, FailureKind: kind,
					Error:   trunc(firstNonEmpty(ev.Result, strings.Join(ev.Errors, "\n"))),
					RetryAt: retryAt})
				break
			}
			// Providers can surface a 429/quota error inside a
			// "successful" result (is_error=false). Only text with a
			// strong provider-error signature counts as a failure —
			// ordinary task results must not (Phase I).
			if LooksLikeProviderError(trunc(ev.Result), trunc(lastText)) {
				kind, retryAt := ClassifyProviderError(trunc(ev.Result), trunc(lastText))
				emit(TurnEvent{Type: EventTurnFailed, FailureKind: kind,
					Error: trunc(ev.Result), RetryAt: retryAt})
				break
			}
			emit(TurnEvent{
				Type:         EventTurnCompleted,
				Model:        model,
				InputTokens:  intPtr(ev.Usage.InputTokens),
				OutputTokens: intPtr(ev.Usage.OutputTokens),
				CachedTokens: intPtr(ev.Usage.CacheRead),
			})
		}
		if terminal {
			// The turn is over: stop scanning. A descendant that
			// outlived the runtime and holds the stdout pipe would
			// otherwise block this read until the turn's context
			// expires (the 2026-09-15 pipe-hold hazard).
			break
		}
	}
	// A truncated stream (a line over the scanner buffer, or an I/O
	// error) before a terminal event is a failure, not a clean exit —
	// surface it instead of treating the partial stream as completed
	// (external audit F-012).
	if scanErr := scanner.Err(); scanErr != nil && !terminal {
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
			Error:       fmt.Sprintf("claude stream error: %v", scanErr),
		}
		return nil
	}
	// The turn reported a terminal event, but a descendant may still be
	// alive holding the stdout/stderr pipes. Terminate the group so the
	// Wait below reaps promptly instead of blocking on the held pipe.
	if terminal && proc.GroupAlive(h.PGID()) {
		h.Terminate("turn_ended")
	}
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
	if resuming && sessionMissingInStderr(stderrBuf.String()) {
		events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
			Error: trunc(stderrBuf.String())}
		return nil
	}
	// Exited without a result line. Provider-shaped stderr is
	// classified; anything else is a process-level failure, not a
	// provider mystery.
	kind := domain.RuntimeFailureProcessError
	var retryAt *string
	if LooksLikeProviderError(trunc(stderrBuf.String())) {
		kind, retryAt = ClassifyProviderError(trunc(stderrBuf.String()))
	}
	events <- TurnEvent{Type: EventTurnFailed, FailureKind: kind,
		Error: trunc(firstNonEmpty(stderrBuf.String(), errorString(waitErr))), RetryAt: retryAt}
	return nil
}

// errorsIndicateMissingSession reports whether the CLI's result.errors
// carry the "resumed session does not exist" message (safe to inspect
// while the process runs).
func errorsIndicateMissingSession(errors []string) bool {
	for _, e := range errors {
		if strings.Contains(e, claudeMissingSession) {
			return true
		}
	}
	return false
}

// sessionMissingInStderr reports whether stderr carries the CLI's
// "resumed session does not exist" message. Only call after cmd.Wait
// (the stderr copy goroutine owns the buffer until then).
func sessionMissingInStderr(stderr string) bool {
	return strings.Contains(stderr, claudeMissingSession)
}

// Stop kills the running process for an instance.
func (c *Claude) Stop(instanceID string) error { return c.life.get().Stop(instanceID) }

func (c *Claude) PID(instanceID string) *int { return c.life.get().PID(instanceID) }

// InteractiveCmd builds the interactive claude REPL (the PTY terminal,
// addendum §7/§8): the same CLI minus the one-shot turn flags
// (-p / --output-format stream-json). The browser sees the ACTUAL Claude
// Code UI of whatever version is installed — pagnet never re-implements it.
// Not started: the daemon runs it under a PTY and owns its lifecycle.
func (c *Claude) InteractiveCmd(spec TurnSpec) (*exec.Cmd, error) {
	bin, err := c.binary()
	if err != nil {
		return nil, err
	}
	if spec.Workspace == "" {
		return nil, fmt.Errorf("claude adapter requires a workspace (claude sessions are CWD-scoped)")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	// NO --permission-mode here (external audit F-014): the interactive
	// REPL is a HUMAN-in-the-loop session — the browser shows the actual
	// Claude Code TUI, and the human approves/denies tool use through the
	// CLI's normal permission flow. Bypassing permissions in an interactive
	// session would silently auto-approve every tool call, defeating the
	// oversight the TUI exists to provide. Only the UNATTENDED managed
	// turn (StartTurn, no human present) carries the explicit
	// --permission-mode bypassPermissions config it needs to act without
	// approval.
	args := []string{}
	// Model precedence: the turn's resolved model wins over the adapter's
	// own (field, then env).
	turnModel := spec.Model
	if turnModel == "" {
		turnModel = c.model()
	}
	if turnModel != "" {
		args = append(args, "--model", turnModel)
	}
	// Standing instruction (AGENT.md): native extra system context.
	if spec.AgentMDPath != "" {
		args = append(args, "--append-system-prompt-file", spec.AgentMDPath)
	}
	if spec.Resume {
		stored, _ := readStoredSession(filepath.Join(spec.SessionDir, claudeSessionFile))
		if stored != "" {
			args = append(args, "--resume", stored)
		}
	}
	// Same MCP bridge injection as a turn: the interactive CLI gets its
	// network tools from the daemon's MCP bridge.
	if mcpJSON := pagnetMCPConfig(spec.Env); mcpJSON != "" {
		var cfg struct {
			MCPServers map[string]any `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(mcpJSON), &cfg); err != nil {
			return nil, fmt.Errorf("invalid PAGNET_MCP_CONFIG: %w", err)
		}
		if len(cfg.MCPServers) == 0 {
			return nil, fmt.Errorf("PAGNET_MCP_CONFIG has no mcpServers")
		}
		args = append(args, "--mcp-config", mcpJSON)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(c.Env, spec.Env)
	return cmd, nil
}

// --- claude stream-json wire shapes -------------------------------------------

type claudeEvent struct {
	Type      string      `json:"type"`
	Subtype   string      `json:"subtype"`
	SessionID string      `json:"session_id"`
	IsError   bool        `json:"is_error"`
	Result    string      `json:"result"`
	Errors    []string    `json:"errors"`
	Usage     claudeUsage `json:"usage"`
	Message   claudeMsg   `json:"message"`
	Model     string      `json:"model"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	CacheRead    int `json:"cache_read_input_tokens"`
}

type claudeMsg struct {
	Model   string       `json:"model"`
	Content []claudePart `json:"content"`
}

type claudePart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
