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

	life lifecycleState
}

func NewFake(binary string) *Fake {
	return &Fake{Binary: binary}
}

// SetLifecycle implements LifecycleSetter (the daemon injects its central
// process supervisor; standalone use falls back to a private one).
func (f *Fake) SetLifecycle(l proc.Lifecycle) { f.life.SetLifecycle(l) }

func (f *Fake) Name() domain.RuntimeName { return domain.RuntimeFake }

// --- native-interaction capability model (plan §8.3) ------------------------
//
// The fake is the reference observing adapter: it CAN observe interactions
// (its helper is scriptable to emit them) and it has a native interactive
// UI (its PTY mode). Whether a pending interaction may be deferred (turn
// exits, instance hibernates) or resolved remotely is a per-deployment knob
// driven by the SAME env pairs that script the helper subprocess, so the
// reported capability and the simulated behavior always agree:
//
//	PAGNET_FAKE_DEFER=1            -> SupportsDeferredInteraction = true
//	PAGNET_FAKE_REMOTE_RESOLVE=1   -> SupportsRemoteResolve = true
//
// Both default to false (the conservative "cannot defer / cannot
// remote-resolve" posture), matching a runtime with no official defer or
// remote-answer mechanism.

func (f *Fake) ObserveInteractions() bool { return true }

func (f *Fake) NativeInteractiveUI() bool { return true }

func (f *Fake) SupportsDeferredInteraction(kind string) bool {
	return f.envValue("PAGNET_FAKE_DEFER") == "1"
}

func (f *Fake) SupportsRemoteResolve(kind string) bool {
	return f.envValue("PAGNET_FAKE_REMOTE_RESOLVE") == "1"
}

// envValue reads a KEY=VALUE pair from the adapter's Env (the same pairs
// handed to the spawned helper), "" when absent.
func (f *Fake) envValue(key string) string {
	for _, kv := range f.Env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func (f *Fake) Available() bool {
	_, err := f.binary()
	return err == nil
}

func (f *Fake) BinaryPath() (string, bool) {
	p, err := f.binary()
	return p, err == nil
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

	cmd := exec.Command(bin)
	cmd.Dir = spec.Workspace
	cmd.Env = EnsureTurnMarker(ChildEnv(f.Env, spec.Env), spec.TurnID)
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
	// launch guards, and the lifecycle. The ctx is handed to it (its
	// watcher terminates the whole group on cancellation — never just
	// the direct child).
	h, err := f.life.get().Launch(ctx, proc.LaunchRequest{
		InstanceID: spec.InstanceID,
		TurnID:     spec.TurnID,
		Runtime:    string(f.Name()),
		Class:      proc.ClassTurn,
		Cmd:        cmd,
		Marker:     "PAGNET_TURN_ID=" + spec.TurnID,
	})
	if err != nil {
		return err
	}
	// defer-safe finalizer: if the owner returns without reaping (early
	// return, panic), Close aborts the group and reaps. After a normal
	// h.Wait it is a no-op.
	defer h.Close()

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
	terminal := false
	for scanner.Scan() {
		var ev wireEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		norm := normalize(ev)
		select {
		case events <- norm:
		case <-ctx.Done():
			// The supervisor's ctx watcher terminates the whole group;
			// the owner just stops reading. defer h.Close() reaps.
			return ctx.Err()
		}
		if isTerminalEvent(norm.Type) {
			// The turn is over: stop scanning. A descendant that
			// outlived the runtime and holds the stdout pipe would
			// otherwise block this read until the turn's context
			// expires (the 2026-09-15 pipe-hold hazard).
			terminal = true
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
		events <- TurnEvent{
			Type:        EventTurnFailed,
			FailureKind: domain.RuntimeFailureProcessError,
			Error:       fmt.Sprintf("fake runtime stream error: %v", scanErr),
		}
		return nil
	}
	// The turn reported a terminal event, but a descendant may still be
	// alive holding the stdout/stderr pipes. Terminate the group so the
	// Wait below reaps promptly instead of blocking on the held pipe.
	if terminal && proc.GroupAlive(h.PGID()) {
		h.Terminate("turn_ended")
	}
	// Owner's reap (single Wait): after all stdout is drained. Also
	// reclaims any descendants that outlived the runtime (§19/§24).
	if err := h.Wait(); err != nil && ctx.Err() == nil {
		// Surface a crash as a process_error turn failure.
		events <- TurnEvent{
			Type:        EventTurnFailed,
			FailureKind: domain.RuntimeFailureProcessError,
			Error:       fmt.Sprintf("fake runtime exited: %v (%s)", err, stderrBuf.String()),
		}
	}
	return nil
}

// Stop terminates the instance's active turn process group (no-op if
// none). Delegates to the process supervisor.
func (f *Fake) Stop(instanceID string) error { return f.life.get().Stop(instanceID) }

func (f *Fake) PID(instanceID string) *int { return f.life.get().PID(instanceID) }

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
	// Native-interaction fields (EventInteractionStarted / Resolved). The
	// daemon mints the pagnet-side interaction id (idempotency); the helper
	// only supplies the runtime-native id + the normalized fields.
	NativeInteractionID string          `json:"nativeInteractionId,omitempty"`
	InteractionKind     string          `json:"interactionKind,omitempty"`
	Summary             string          `json:"summary,omitempty"`
	NativePayload       json.RawMessage `json:"nativePayload,omitempty"`
	Decision            string          `json:"decision,omitempty"`
	Answer              string          `json:"answer,omitempty"`
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
	case EventInteractionStarted, EventInteractionResolved:
		// Native interaction observed: normalize into the generic
		// InteractionEvent (the vendor payload stays opaque). The daemon
		// mints the pagnet-side id + correlation; the native id links the
		// started/resolved pair.
		out.Interaction = &InteractionEvent{
			Runtime:             domain.RuntimeFake,
			SessionID:           ev.SessionID,
			NativeInteractionID: ev.NativeInteractionID,
			Kind:                ev.InteractionKind,
			Summary:             ev.Summary,
			NativePayload:       ev.NativePayload,
			Resolved:            ev.Event == EventInteractionResolved,
			Decision:            ev.Decision,
			Answer:              ev.Answer,
		}
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
