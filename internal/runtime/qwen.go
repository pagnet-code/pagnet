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

// Qwen drives the qwen-code CLI (`qwen`) as a process-per-turn runtime
// (addendum Phases D + I: real session ids, exact-id resume, token
// metadata, rate-limit classification).
//
// Per-turn invocation (no shell, structured args only):
//
//	qwen -o stream-json [-m <model>] [-r <session-id>]
//
// with the turn prompt on STDIN. Output is NDJSON:
//
//	{"type":"system","subtype":"init", "session_id":..., "model":...}
//	{"type":"assistant","message":{"content":[{"type":"text","text":...}]}}
//	{"type":"result","session_id":..., "is_error":..., "result":..., "usage":{...}}
//
// Session continuity: qwen scopes sessions to the working directory and
// assigns the id on init. The adapter captures the EXACT id (Phase D) and
// persists it in <SessionDir>/session.json; a resume passes it via
// `-r <id>` and a failed resume (exit 1, "No saved session found") is
// surfaced as EventSessionLost — never a silent fresh session (§74/§88).
//
// User config is never touched and no file is written into the
// workspace. MCP injection (the PAGNET_MCP_CONFIG the daemon renders
// per instance) is passed as an inline --mcp-config JSON string: it
// merges with the user's own MCP servers (project and global config)
// without writing any file, so there is nothing to clobber and the
// user's code directory stays clean.
//
// Model selection: Qwen.Model (explicit) or the PAGNET_QWEN_MODEL
// environment; when empty the user's own default model applies.
type Qwen struct {
	// Binary is the path to the qwen executable. When empty it is
	// resolved from PATH / next to the current executable.
	Binary string
	// Model overrides the model for managed turns (empty = user default).
	Model string
	// Env is appended to the inherited environment for spawned processes.
	Env []string

	track procTracker
}

func NewQwen(binary string) *Qwen {
	return &Qwen{Binary: binary, track: procTracker{procs: map[string]*exec.Cmd{}}}
}

func (q *Qwen) Name() domain.RuntimeName { return domain.RuntimeQwenCode }

func (q *Qwen) Available() bool {
	_, err := q.binary()
	return err == nil
}

func (q *Qwen) BinaryPath() (string, bool) {
	p, err := q.binary()
	return p, err == nil
}

func (q *Qwen) binary() (string, error) {
	if q.Binary != "" {
		if _, err := os.Stat(q.Binary); err == nil {
			return q.Binary, nil
		}
	}
	if p, err := exec.LookPath("qwen"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "qwen")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("qwen CLI not found on PATH")
}

// model returns the model override (explicit field, then env) or "".
func (q *Qwen) model() string {
	if q.Model != "" {
		return q.Model
	}
	return os.Getenv("PAGNET_QWEN_MODEL")
}

const qwenSessionFile = "session.json"

// StartTurn runs one qwen turn, streaming normalized events into events.
func (q *Qwen) StartTurn(ctx context.Context, spec TurnSpec, events chan TurnEvent) error {
	defer close(events)
	bin, err := q.binary()
	if err != nil {
		return err
	}
	if spec.Workspace == "" {
		return fmt.Errorf("qwen adapter requires a workspace (qwen sessions are CWD-scoped)")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return err
	}
	sessionPath := filepath.Join(spec.SessionDir, qwenSessionFile)
	stored, _ := readStoredSession(sessionPath)

	args := []string{"-o", "stream-json"}
	if model := q.model(); model != "" {
		args = append(args, "-m", model)
	}
	resuming := false
	if spec.Resume {
		if stored == "" {
			// A resume was requested but this host holds no stored session
			// id — report it honestly instead of starting fresh (§74/§88).
			events <- TurnEvent{Type: EventSessionLost, Error: "resume requested but no stored qwen session id"}
			return nil
		}
		args = append(args, "-r", stored)
		resuming = true
	}

	// Inject the MCP bridge as an inline --mcp-config (merges with the
	// user's own MCP servers, writes no file into the workspace). A
	// failure here is visible — the turn does not run silently without
	// its network tools.
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
	cmd.Env = ChildEnv(q.Env, spec.Env)
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
		return fmt.Errorf("spawn qwen: %w", err)
	}
	q.track.track(spec.InstanceID, cmd)
	defer q.track.release(spec.InstanceID, cmd)

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
		var ev qwenEvent
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
					Error: "qwen resume started a different session (wanted " + stored + ", got " + sid + ")"}
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
			if ev.IsError {
				// A reported failure: classify the text directly. (stderrBuf
				// is owned by the copy goroutine until cmd.Wait below —
				// reading it here would be a data race; ev.Result carries
				// the message.)
				kind, retryAt := ClassifyProviderError(trunc(ev.Result), trunc(lastText))
				emit(TurnEvent{Type: EventTurnFailed, FailureKind: kind,
					Error: trunc(firstNonEmpty(ev.Result, lastText)), RetryAt: retryAt})
				break
			}
			// Providers can surface a 429/quota error inside a
			// "successful" result (is_error=false). Only text with a
			// strong provider-error signature counts as a failure —
			// ordinary task results must not be (Phase I).
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
	if resuming && strings.Contains(stderrBuf.String(), "No saved session found") {
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

// Stop kills the running process for an instance.
func (q *Qwen) Stop(instanceID string) error { return q.track.stop(instanceID) }

func (q *Qwen) PID(instanceID string) *int { return q.track.pid(instanceID) }

// InteractiveCmd builds the interactive qwen REPL (the PTY terminal,
// addendum §7/§8): the default interactive mode (no -o stream-json), with
// the same model override, session resume, and inline --mcp-config bridge
// as a turn. Not started: the daemon runs it under a PTY and owns its
// lifecycle.
func (q *Qwen) InteractiveCmd(spec TurnSpec) (*exec.Cmd, error) {
	bin, err := q.binary()
	if err != nil {
		return nil, err
	}
	if spec.Workspace == "" {
		return nil, fmt.Errorf("qwen adapter requires a workspace (qwen sessions are CWD-scoped)")
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	var args []string
	if model := q.model(); model != "" {
		args = append(args, "-m", model)
	}
	if spec.Resume {
		stored, _ := readStoredSession(filepath.Join(spec.SessionDir, qwenSessionFile))
		if stored != "" {
			args = append(args, "-r", stored)
		}
	}
	// Same MCP bridge injection as a turn: the interactive CLI gets its
	// network tools from the daemon's pagnet-mcp bridge.
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
	cmd.Env = ChildEnv(q.Env, spec.Env)
	return cmd, nil
}

// --- qwen stream-json wire shapes --------------------------------------------

type qwenEvent struct {
	Type      string      `json:"type"`
	Subtype   string      `json:"subtype"`
	SessionID string      `json:"session_id"`
	Model     string      `json:"model"`
	IsError   bool        `json:"is_error"`
	Result    string      `json:"result"`
	Usage     qwenUsage   `json:"usage"`
	Message   qwenMessage `json:"message"`
}

type qwenUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	CacheRead    int `json:"cache_read_input_tokens"`
}

type qwenMessage struct {
	Model   string        `json:"model"`
	Content []qwenContent `json:"content"`
}

type qwenContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// --- session persistence -------------------------------------------------------

// readStoredSession loads the last captured qwen session id, "" if none.
func readStoredSession(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var s struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", err
	}
	return strings.TrimSpace(s.SessionID), nil
}

func writeStoredSession(path, id string) error {
	b, _ := json.Marshal(struct {
		SessionID string `json:"sessionId"`
	}{SessionID: id})
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// --- small helpers ---------------------------------------------------------------

func intPtr(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "runtime exited without output"
}
