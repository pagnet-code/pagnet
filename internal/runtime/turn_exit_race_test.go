//go:build linux

// Turn-lifecycle exit-window race regression (2026-09-16 e2e cascade).
//
// The race: the fake runtime emits its terminal event (turn.completed)
// and then takes time to actually exit. The adapter reads the terminal
// event, sees the process group still alive, sends its own post-
// completion cleanup TERM (reason=turn_ended), and the TERM lands in the
// helper's exit window — cmd.Wait returns "signal: terminated".
//
// Pre-fix, the adapter turned that Wait error into a SPURIOUS
// process_error turn failure AFTER the terminal event it had already
// observed. The daemon's taxonomy (a reported failure beats a
// completion) then marked the instance "failed" instead of settling it
// — the cascade behind every failing CI e2e test since 2026-09-16
// ("message never marked delivered", "instance never reached
// idle/hibernated/blocked", "instance never started").
//
// The rule under test: a turn's outcome is decided by its OBSERVED
// terminal event, never by the Wait result of a process the daemon
// itself TERMed as cleanup. A self-inflicted cleanup TERM is a normal
// exit, not a process error (the qwen/claude/opencode adapters already
// applied this rule; the fake adapter now matches them).
//
// PAGNET_FAKE_EXIT_DELAY makes the race DETERMINISTIC: the helper stays
// alive 500ms after its last event, so the cleanup TERM is guaranteed to
// land in the exit window (the helper cannot have exited before the
// adapter has even read the terminal line).
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// TestTurnCompletedCleanupTermIsNotProcessError: a completed turn whose
// cleanup TERM lands in the exit window is classified completed — the
// events carry the completion and NO turn failure.
func TestTurnCompletedCleanupTermIsNotProcessError(t *testing.T) {
	bin := p0FakeBinary(t)
	adapter := NewFake(bin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx, TurnSpec{
		TurnID: "turn-exit-race", InstanceID: "inst-exit-race",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "exit window race", InputKind: "task",
		Env: []string{"PAGNET_FAKE_EXIT_DELAY=500ms"},
	}, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	evs := drainEvents(events)

	if !hasEvent(evs, EventTurnCompleted) {
		t.Fatalf("turn did not complete: %+v", evs)
	}
	if sessionIDOf(evs, EventTurnCompleted) == "" {
		t.Fatalf("completion event carries no session id: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Type == EventTurnFailed {
			t.Fatalf("completed turn classified as failed (%s: %s) — the cleanup TERM landed in the exit window and must not be a process error: %+v",
				ev.FailureKind, ev.Error, evs)
		}
	}
	// The turn genuinely ran: the session was persisted for a resume.
	if _, err := os.Stat(filepath.Join(sessionDir, "session.json")); err != nil {
		t.Fatalf("session file not persisted: %v", err)
	}
}

// TestTurnFailedCleanupTermKeepsReportedKind: a turn that FAILED at the
// runtime level (rate_limited) whose cleanup TERM lands in the exit
// window keeps its reported kind — the spurious process_error must not
// overwrite the runtime-reported failure (in the daemon the last
// EventTurnFailed wins, so a trailing process_error would have turned a
// rate_limited instance into a failed one).
func TestTurnFailedCleanupTermKeepsReportedKind(t *testing.T) {
	bin := p0FakeBinary(t)
	adapter := NewFake(bin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx, TurnSpec{
		TurnID: "turn-exit-race-fail", InstanceID: "inst-exit-race-fail",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "exit window race (failure)", InputKind: "task",
		Env: []string{
			"PAGNET_FAKE_RATELIMIT=1m",
			"PAGNET_FAKE_EXIT_DELAY=500ms",
		},
	}, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	evs := drainEvents(events)

	var failed *TurnEvent
	for i := range evs {
		if evs[i].Type == EventTurnFailed {
			failed = &evs[i] // the daemon applies the LAST failure event
		}
	}
	if failed == nil {
		t.Fatalf("turn did not fail: %+v", evs)
	}
	if failed.FailureKind != domain.RuntimeFailureRateLimited {
		t.Fatalf("failure kind = %s, want rate_limited (the cleanup TERM must not overwrite the reported kind): %+v",
			failed.FailureKind, evs)
	}
}

// TestTurnCrashWithoutTerminalEventIsProcessError: a process that dies
// WITHOUT emitting any terminal event is a GENUINE process error — the
// fix must not over-suppress. Only a turn whose terminal event was
// OBSERVED is immune to the Wait result; a crash before the first event
// still surfaces as process_error (the daemon then keeps the work queued
// or fails the command, as before).
func TestTurnCrashWithoutTerminalEventIsProcessError(t *testing.T) {
	// A stand-in runtime that crashes without emitting any event (the
	// real fake helper always emits a terminal event in turn mode, so it
	// cannot script this path).
	crashBin := filepath.Join(t.TempDir(), "crash-runtime")
	if err := os.WriteFile(crashBin, []byte("#!/bin/sh\nexit 139\n"), 0o755); err != nil {
		t.Fatalf("write crash script: %v", err)
	}
	adapter := NewFake(crashBin)
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan TurnEvent, 16)
	if err := adapter.StartTurn(ctx, TurnSpec{
		TurnID: "turn-crash", InstanceID: "inst-crash",
		Workspace: workspace, SessionDir: sessionDir,
		Input: "crash before any event", InputKind: "task",
	}, events); err != nil {
		t.Fatalf("StartTurn: %v", err)
	}
	evs := drainEvents(events)

	var failed *TurnEvent
	for i := range evs {
		if evs[i].Type == EventTurnFailed {
			failed = &evs[i]
		}
	}
	if failed == nil {
		t.Fatalf("crashed turn did not report a failure: %+v", evs)
	}
	if failed.FailureKind != domain.RuntimeFailureProcessError {
		t.Fatalf("failure kind = %s, want process_error (a crash before any event is a genuine process error): %+v",
			failed.FailureKind, evs)
	}
	if hasEvent(evs, EventTurnCompleted) {
		t.Fatalf("crashed turn must not be completed: %+v", evs)
	}
}
