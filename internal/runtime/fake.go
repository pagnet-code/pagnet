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

	"pagnet/internal/domain"
)

// Fake is the MVP runtime adapter. It is a REAL process-per-turn runtime:
// each turn spawns the `pagnet-fake-runtime` helper as a subprocess that
// speaks a JSONL protocol over stdio and persists a session file. Resume
// genuinely re-reads that file; rate-limit and resume-failure behaviors are
// simulated by the helper so the full availability model (retry_at,
// unknown recovery, session-lost) can be exercised end-to-end.
//
// It is the reference implementation that the real Qwen/Claude adapters
// (Phases 8/9) replace, one-for-one, behind the same Adapter contract.
type Fake struct {
	// Binary is the path to the pagnet-fake-runtime helper. When empty it
	// is resolved from PATH / next to the current executable.
	Binary string
	// Env is appended to the inherited environment for spawned runtime
	// processes (E2E simulation knobs, e.g. PAGNET_FAKE_RATELIMIT).
	Env []string

	track procTracker
}

func NewFake(binary string) *Fake {
	return &Fake{Binary: binary, track: procTracker{procs: map[string]*exec.Cmd{}}}
}

func (f *Fake) Name() domain.RuntimeName { return domain.RuntimeFake }

func (f *Fake) Available() bool {
	_, err := f.binary()
	return err == nil
}

func (f *Fake) binary() (string, error) {
	if f.Binary != "" {
		if _, err := os.Stat(f.Binary); err == nil {
			return f.Binary, nil
		}
	}
	if p, err := exec.LookPath("pagnet-fake-runtime"); err == nil {
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), "pagnet-fake-runtime")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", fmt.Errorf("pagnet-fake-runtime binary not found")
}

// StartTurn runs one fake turn.
func (f *Fake) StartTurn(ctx context.Context, spec TurnSpec, events chan TurnEvent) error {
	defer close(events)
	bin, err := f.binary()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return err
	}

	cmd := exec.CommandContext(ctx, bin)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(f.Env, spec.Env)
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
		return fmt.Errorf("spawn fake runtime: %w", err)
	}
	f.track.track(spec.InstanceID, cmd)
	defer f.track.release(spec.InstanceID, cmd)

	// Send the turn spec.
	specWire := map[string]any{
		"instanceId": spec.InstanceID,
		"sessionDir": spec.SessionDir,
		"resume":     spec.Resume,
		"input":      spec.Input,
		"inputKind":  spec.InputKind,
		"wakeReason": spec.WakeReason,
	}
	if spec.Metadata != nil {
		specWire["metadata"] = spec.Metadata
	}
	if err := json.NewEncoder(stdin).Encode(specWire); err != nil {
		return err
	}
	_ = stdin.Close()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var ev wireEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		norm := normalize(ev)
		select {
		case events <- norm:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return ctx.Err()
		}
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		// Surface a crash as a process_error turn failure.
		events <- TurnEvent{
			Type:        EventTurnFailed,
			FailureKind: domain.RuntimeFailureProcessError,
			Error:       fmt.Sprintf("fake runtime exited: %v (%s)", err, stderrBuf.String()),
		}
	}
	return nil
}

// Stop kills the running process for an instance.
func (f *Fake) Stop(instanceID string) error { return f.track.stop(instanceID) }

func (f *Fake) PID(instanceID string) *int { return f.track.pid(instanceID) }

// InteractiveCmd builds the fake runtime's interactive PTY mode: a
// deterministic, scriptable stand-in for a real runtime's interactive UI
// (prompt, echo, SIGWINCH line, ANSI/Unicode output, exit/crash commands,
// two selectable UI variants) so the whole terminal stack is E2E-testable
// without a real CLI (addendum §68: "fake PTY fixtures that emulate
// differing runtime UIs").
func (f *Fake) InteractiveCmd(spec TurnSpec) (*exec.Cmd, error) {
	bin, err := f.binary()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(spec.SessionDir, 0o700); err != nil { // SEC-415: runtime state
		return nil, err
	}
	args := []string{"--pty", "--instance-id", spec.InstanceID, "--session-dir", spec.SessionDir}
	if spec.Resume {
		stored, _ := readStoredSession(filepath.Join(spec.SessionDir, "session.json"))
		if stored != "" {
			args = append(args, "--resume", stored)
		}
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = spec.Workspace
	cmd.Env = ChildEnv(f.Env, spec.Env)
	return cmd, nil
}

// wireEvent is the fake-runtime helper's stdout event (already normalized).
type wireEvent struct {
	Event        string  `json:"event"`
	SessionID    string  `json:"sessionId,omitempty"`
	Output       string  `json:"output,omitempty"`
	Model        string  `json:"model,omitempty"`
	InputTokens  *int    `json:"inputTokens,omitempty"`
	OutputTokens *int    `json:"outputTokens,omitempty"`
	CachedTokens *int    `json:"cachedTokens,omitempty"`
	Kind         string  `json:"kind,omitempty"`
	Error        string  `json:"error,omitempty"`
	RetryAt      *string `json:"retryAt,omitempty"`
}

// normalize maps a wire event to the adapter's TurnEvent vocabulary.
func normalize(ev wireEvent) TurnEvent {
	out := TurnEvent{
		Type:         ev.Event,
		SessionID:    ev.SessionID,
		Output:       ev.Output,
		Model:        ev.Model,
		InputTokens:  ev.InputTokens,
		OutputTokens: ev.OutputTokens,
		CachedTokens: ev.CachedTokens,
		Error:        ev.Error,
		RetryAt:      ev.RetryAt,
	}
	switch ev.Event {
	case EventSessionStarted, EventSessionResumed, EventTurnStarted,
		EventTurnOutput, EventTurnCompleted, EventTurnFailed, EventSessionLost:
		// pass through
	default:
		// Unknown event names from the helper are surfaced as output so
		// nothing is silently dropped.
		out.Type = EventTurnOutput
	}
	if out.Type == EventTurnFailed {
		out.FailureKind = domain.RuntimeFailureKind(ev.Kind)
		if out.FailureKind == "" {
			out.FailureKind = domain.RuntimeFailureUnknown
		}
	}
	return out
}
