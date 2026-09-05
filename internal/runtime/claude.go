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

	"pagnet/internal/domain"
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

	track procTracker
}

func NewClaude(binary string) *Claude {
	return &Claude{Binary: binary, track: procTracker{procs: map[string]*exec.Cmd{}}}
}

func (c *Claude) Name() domain.RuntimeName { return domain.RuntimeClaudeCode }

func (c *Claude) Available() bool {
	_, err := c.binary()
	return err == nil
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
	if err := os.MkdirAll(spec.SessionDir, 0o755); err != nil {
		return err
	}
	sessionPath := filepath.Join(spec.SessionDir, claudeSessionFile)
	stored, _ := readStoredSession(sessionPath)

	args := []string{"-p", "--verbose", "--output-format", "stream-json",
		"--permission-mode", "bypassPermissions"}
	if model := c.model(); model != "" {
		args = append(args, "--model", model)
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

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(c.Env, spec.Env)
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

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn claude: %w", err)
	}
	c.track.track(spec.InstanceID, cmd)
	defer c.track.release(spec.InstanceID, cmd)

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
			cancelled = true
			_ = cmd.Process.Kill()
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
				_ = cmd.Process.Kill()
				events <- TurnEvent{Type: EventSessionLost, SessionID: stored,
					Error: "claude resume started a different session (wanted " + stored + ", got " + sid + ")"}
				_ = cmd.Wait()
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
		Error: trunc(firstNonEmpty(stderrBuf.String(), waitErr.Error())), RetryAt: retryAt}
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
func (c *Claude) Stop(instanceID string) error { return c.track.stop(instanceID) }

func (c *Claude) PID(instanceID string) *int { return c.track.pid(instanceID) }

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
