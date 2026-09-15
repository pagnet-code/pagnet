//go:build linux

// Session-persistence regression (abuse addendum Part B §40): killing the
// OS runtime process must NOT delete the runtime session. The process-per-
// turn architecture persists the resumable session to disk; the next turn
// resumes it. The process-containment fix (group kill on turn end) must not
// destroy this — the session file outlives the process.
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// drainEvents reads all buffered events. The adapter CLOSES the channel
// when StartTurn returns (the daemon consumes it with `for ev := range
// events`), so the drain must stop at the close: a closed channel is
// always ready to receive (zero values), so a select with a default
// would otherwise loop forever appending zero-value events (the
// 2026-09-15 memory-explosion incident: this exact loop grew the heap
// to ~52 GB and OOM-killed the host).
func drainEvents(ch chan TurnEvent) []TurnEvent {
	var out []TurnEvent
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		default:
			return out
		}
	}
}

func sessionIDOf(evs []TurnEvent, types ...string) string {
	for _, ev := range evs {
		for _, ty := range types {
			if ev.Type == ty {
				return ev.SessionID
			}
		}
	}
	return ""
}

// hasEvent reports whether an event of the given type is present. Use it
// for existence checks: sessionIDOf returns "" both when the event is
// absent AND when the event carries no session id (a session_lost for a
// resume with no stored session legitimately has an empty SessionID —
// the same shape the qwen/claude/opencode adapters emit when no stored
// session id exists).
func hasEvent(evs []TurnEvent, ty string) bool {
	for _, ev := range evs {
		if ev.Type == ty {
			return true
		}
	}
	return false
}

// TestSessionPersistsAcrossProcessTermination drives a cold-start turn, lets
// its process terminate, then a resume turn. The resumed session id must be
// the SAME as the cold start's — the session identity survived the process
// death (it is stored on disk, not in the process).
func TestSessionPersistsAcrossProcessTermination(t *testing.T) {
	bin := p0FakeBinary(t)
	adapter := NewFake(bin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")

	// Turn 1: cold start. The fake runtime mints a session and persists it.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 60*time.Second)
	events1 := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx1, TurnSpec{
		TurnID: "turn-1", InstanceID: "inst-sess",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "first turn", InputKind: "task",
	}, events1); err != nil {
		cancel1()
		t.Fatalf("turn 1: %v", err)
	}
	cancel1()
	evs1 := drainEvents(events1)
	session1 := sessionIDOf(evs1, EventSessionStarted)
	if session1 == "" {
		t.Fatalf("turn 1 did not start a session: %+v", evs1)
	}

	// The process is dead (turn 1 completed), but the session file persists.
	sessionFile := filepath.Join(sessionDir, "session.json")
	if _, err := os.Stat(sessionFile); err != nil {
		t.Fatalf("session file not persisted after process termination: %v", err)
	}

	// Turn 2: resume the stored session.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	events2 := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx2, TurnSpec{
		TurnID: "turn-2", InstanceID: "inst-sess",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "second turn", InputKind: "task", Resume: true,
	}, events2); err != nil {
		cancel2()
		t.Fatalf("turn 2: %v", err)
	}
	cancel2()
	evs2 := drainEvents(events2)
	session2 := sessionIDOf(evs2, EventSessionResumed)
	if session2 == "" {
		t.Fatalf("turn 2 did not resume a session: %+v", evs2)
	}
	if session2 != session1 {
		t.Fatalf("session identity did NOT survive process termination: turn1=%q turn2=%q",
			session1, session2)
	}
	t.Logf("session %q persisted across process termination and resumed", session1)
}

// TestSessionLostIsNotSilentColdStart: a resume with no usable session must
// report session_lost (NOT silently start a different session, §40/§74).
func TestSessionLostIsNotSilentColdStart(t *testing.T) {
	bin := p0FakeBinary(t)
	adapter := NewFake(bin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session") // empty: no stored session

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	events := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx, TurnSpec{
		TurnID: "turn-1", InstanceID: "inst-sess",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "resume with nothing", InputKind: "task", Resume: true,
	}, events); err != nil {
		t.Fatalf("turn: %v", err)
	}
	evs := drainEvents(events)
	if !hasEvent(evs, EventSessionLost) {
		t.Fatalf("expected session_lost for a resume with no session, got %+v", evs)
	}
	if hasEvent(evs, EventSessionStarted) {
		t.Fatalf("a lost resume must NOT silently cold-start a new session: %+v", evs)
	}
}
