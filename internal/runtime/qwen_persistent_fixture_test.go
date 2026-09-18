package runtime

// Qwen Dual Output state-machine fixture tests (runtime-lifecycle refactor,
// Phase 4 / B4).
//
// These tests feed scripted JSONL event sequences (the exact wire format,
// doc §3) to the qwenTurnState state machine and assert the normalized
// session.SessionEvent stream. They need NO model and NO process — they
// are CI-safe and deterministic (the clock is injected for the watchdog
// tests).
//
// They cover: the handshake gate (pass / fail), cold start, resume, resume
// mismatch, the turn lifecycle (submit-accepted → deltas → message_stop →
// assistant finalize), the tool_result user boundary, continue_turn_failed
// (generic + provider-error classified), retry / model_fallback notes,
// provider-error classification at turn end (rate_limited + retry time,
// auth_required, and the ordinary-text guard), interactions (started /
// resolved, dedup, ask_user_question kind), the submit correlation
// deadline, the in-flight stall warning, and unknown-event tolerance.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

// --- helpers ----------------------------------------------------------------

// validSupportedEvents is the superset the handshake gate requires.
var validSupportedEvents = []string{
	"system", "user", "assistant", "stream_event", "control_request", "control_response",
}

// fakeClock is an injectable clock for the watchdog tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newFixtureState builds a state machine with an injected clock.
func newFixtureState(resuming bool, resumeID string) (*qwenTurnState, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_000_000, 0)}
	return newQwenTurnState(resuming, resumeID, c.now), c
}

// feedLines feeds scripted event lines to the state machine and returns the
// normalized events (in order).
func feedLines(t *testing.T, s *qwenTurnState, lines ...string) []session.SessionEvent {
	t.Helper()
	var out []session.SessionEvent
	for _, line := range lines {
		out = append(out, s.processLine([]byte(line))...)
	}
	return out
}

// marshalLine marshals a qwenDOEvent to a JSONL line.
func marshalLine(t *testing.T, ev qwenDOEvent) string {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(b)
}

// sessionStartLine builds a session_start (handshake) line.
func sessionStartLine(t *testing.T, sid, cwd, version string, protocolVersion int, supported []string) string {
	t.Helper()
	hs := qwenDOHandshake{
		SessionID:       sid,
		CWD:             cwd,
		ProtocolVersion: protocolVersion,
		Version:         version,
		SupportedEvents: supported,
	}
	data, _ := json.Marshal(hs)
	return marshalLine(t, qwenDOEvent{
		Type: "system", Subtype: "session_start", SessionID: sid, Data: data,
	})
}

// validHandshakeLine is a passing session_start.
func validHandshakeLine(t *testing.T, sid, cwd string) string {
	return sessionStartLine(t, sid, cwd, "0.23.4", 2, validSupportedEvents)
}

// userTextLine builds a user event with a text content block (a submit).
func userTextLine(t *testing.T, sid, text string) string {
	t.Helper()
	msg := qwenDOMessage{
		Role:    "user",
		Content: []qwenDOContent{{Type: "text", Text: text}},
	}
	m, _ := json.Marshal(msg)
	return marshalLine(t, qwenDOEvent{Type: "user", SessionID: sid, Message: m})
}

// userToolResultLine builds a user event with a tool_result content block
// (a tool boundary, not a submit).
func userToolResultLine(t *testing.T, sid string) string {
	t.Helper()
	msg := qwenDOMessage{
		Role:    "user",
		Content: []qwenDOContent{{Type: "tool_result", Text: "tool output"}},
	}
	m, _ := json.Marshal(msg)
	return marshalLine(t, qwenDOEvent{Type: "user", SessionID: sid, Message: m})
}

// streamDeltaLine builds a content_block_delta (text_delta) line.
func streamDeltaLine(t *testing.T, sid, text string) string {
	t.Helper()
	se := qwenDOStreamEvent{
		Type:  "content_block_delta",
		Delta: qwenDOStreamDelta{Type: "text_delta", Text: text},
	}
	m, _ := json.Marshal(se)
	return marshalLine(t, qwenDOEvent{Type: "stream_event", SessionID: sid, Event: m})
}

// messageStopLine builds a message_stop line.
func messageStopLine(t *testing.T, sid string) string {
	t.Helper()
	se := qwenDOStreamEvent{Type: "message_stop"}
	m, _ := json.Marshal(se)
	return marshalLine(t, qwenDOEvent{Type: "stream_event", SessionID: sid, Event: m})
}

// messageStartLine builds a message_start line (a model step begins).
func messageStartLine(t *testing.T, sid string) string {
	t.Helper()
	se := qwenDOStreamEvent{Type: "message_start"}
	m, _ := json.Marshal(se)
	return marshalLine(t, qwenDOEvent{Type: "stream_event", SessionID: sid, Event: m})
}

// assistantLine builds an assistant (finalized message) line.
func assistantLine(t *testing.T, sid, model string, in, out, cached int) string {
	t.Helper()
	msg := qwenDOMessage{
		Role:    "assistant",
		Content: []qwenDOContent{{Type: "text", Text: "response"}},
		Usage:   qwenDOUsage{InputTokens: in, OutputTokens: out, CacheRead: cached},
		Model:   model,
	}
	m, _ := json.Marshal(msg)
	return marshalLine(t, qwenDOEvent{Type: "assistant", SessionID: sid, Message: m})
}

// assistantToolUseLine builds an assistant (finalized message) line whose
// content is a tool_use block (a mid-turn message: the tool result + the
// next model message follow).
func assistantToolUseLine(t *testing.T, sid, model string, in, out, cached int) string {
	t.Helper()
	msg := qwenDOMessage{
		Role:    "assistant",
		Content: []qwenDOContent{{Type: "tool_use", Text: "run_shell_command"}},
		Usage:   qwenDOUsage{InputTokens: in, OutputTokens: out, CacheRead: cached},
		Model:   model,
	}
	m, _ := json.Marshal(msg)
	return marshalLine(t, qwenDOEvent{Type: "assistant", SessionID: sid, Message: m})
}

// assistantTextLine builds an assistant (finalized message) line with an
// explicit final-answer text (assistantLine's text is the neutral
// "response").
func assistantTextLine(t *testing.T, sid, model, text string, in, out, cached int) string {
	t.Helper()
	msg := qwenDOMessage{
		Role:    "assistant",
		Content: []qwenDOContent{{Type: "text", Text: text}},
		Usage:   qwenDOUsage{InputTokens: in, OutputTokens: out, CacheRead: cached},
		Model:   model,
	}
	m, _ := json.Marshal(msg)
	return marshalLine(t, qwenDOEvent{Type: "assistant", SessionID: sid, Message: m})
}

// systemSubtypeLine builds a system event with a given subtype (no data).
func systemSubtypeLine(t *testing.T, sid, subtype string) string {
	return marshalLine(t, qwenDOEvent{Type: "system", Subtype: subtype, SessionID: sid})
}

// controlRequestLine builds a can_use_tool control_request line.
func controlRequestLine(t *testing.T, sid, rid, toolName string) string {
	t.Helper()
	req := qwenDOControlRequest{
		Subtype:   "can_use_tool",
		ToolName:  toolName,
		ToolUseID: "toolu_123",
		Input:     json.RawMessage(`{}`),
	}
	m, _ := json.Marshal(req)
	return marshalLine(t, qwenDOEvent{
		Type: "control_request", SessionID: sid, RequestID: rid, Request: m,
	})
}

// controlResponseLine builds a control_response line.
func controlResponseLine(t *testing.T, sid, rid string, allowed bool) string {
	t.Helper()
	inner := qwenDOControlResponseInner{Allowed: allowed}
	innerJSON, _ := json.Marshal(inner)
	resp := qwenDOControlResponse{
		Subtype:   "success",
		RequestID: rid,
		Response:  innerJSON,
	}
	m, _ := json.Marshal(resp)
	return marshalLine(t, qwenDOEvent{Type: "control_response", SessionID: sid, Response: m})
}

// eventTypes extracts the event types (for assertions).
func eventTypes(evs []session.SessionEvent) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Type
	}
	return out
}

// assertEventTypes asserts the normalized events have exactly the given types.
func assertEventTypes(t *testing.T, got []session.SessionEvent, want ...string) {
	t.Helper()
	gotTypes := eventTypes(got)
	if len(gotTypes) != len(want) {
		t.Fatalf("event types = %v (len %d), want %v (len %d)", gotTypes, len(gotTypes), want, len(want))
	}
	for i := range want {
		if gotTypes[i] != want[i] {
			t.Fatalf("event types = %v, want %v", gotTypes, want)
		}
	}
}

const (
	fixtureSID = "11111111-aaaa-bbbb-cccc-111111111111"
	fixtureCWD = "/workspace"
)

// --- handshake gate ----------------------------------------------------------

func TestQwenDO_HandshakeGatePass(t *testing.T) {
	s, _ := newFixtureState(false, "")
	evs := feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	assertEventTypes(t, evs, session.EventSessionStarted)
	if evs[0].SessionID != fixtureSID {
		t.Fatalf("session id = %q, want %q", evs[0].SessionID, fixtureSID)
	}
	if !s.isActivated() {
		t.Fatal("state not activated after a passing handshake")
	}
	if s.nativeVersion() != "0.23.4" {
		t.Fatalf("version = %q, want 0.23.4 (read from the handshake ONLY)", s.nativeVersion())
	}
	if s.nativeCWD() != fixtureCWD {
		t.Fatalf("cwd = %q, want %q", s.nativeCWD(), fixtureCWD)
	}
}

func TestQwenDO_HandshakeGateFailNoVersion(t *testing.T) {
	s, _ := newFixtureState(false, "")
	line := sessionStartLine(t, fixtureSID, fixtureCWD, "", 2, validSupportedEvents)
	evs := feedLines(t, s, line)
	assertEventTypes(t, evs, session.EventSessionLost)
	if s.handshakeGateErr() == "" {
		t.Fatal("gate error not recorded")
	}
}

func TestQwenDO_HandshakeGateFailProtocolVersion(t *testing.T) {
	s, _ := newFixtureState(false, "")
	line := sessionStartLine(t, fixtureSID, fixtureCWD, "0.23.4", 1, validSupportedEvents)
	evs := feedLines(t, s, line)
	assertEventTypes(t, evs, session.EventSessionLost)
}

func TestQwenDO_HandshakeGateFailMissingSupportedEvent(t *testing.T) {
	s, _ := newFixtureState(false, "")
	// Missing control_request.
	supported := []string{"system", "user", "assistant", "stream_event", "control_response"}
	line := sessionStartLine(t, fixtureSID, fixtureCWD, "0.23.4", 2, supported)
	evs := feedLines(t, s, line)
	assertEventTypes(t, evs, session.EventSessionLost)
}

// --- cold start / resume -----------------------------------------------------

func TestQwenDO_ColdStart(t *testing.T) {
	s, _ := newFixtureState(false, "")
	evs := feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	assertEventTypes(t, evs, session.EventSessionStarted)
}

func TestQwenDO_ResumeSuccess(t *testing.T) {
	s, _ := newFixtureState(true, fixtureSID)
	evs := feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	assertEventTypes(t, evs, session.EventSessionResumed)
	if evs[0].SessionID != fixtureSID {
		t.Fatalf("session id = %q, want %q", evs[0].SessionID, fixtureSID)
	}
}

func TestQwenDO_ResumeMismatchIsLost(t *testing.T) {
	// A requested resume that re-bases onto a different session is a lost
	// session, not a silent fresh one (B3).
	other := "22222222-aaaa-bbbb-cccc-222222222222"
	s, _ := newFixtureState(true, fixtureSID)
	evs := feedLines(t, s, validHandshakeLine(t, other, fixtureCWD))
	assertEventTypes(t, evs, session.EventSessionLost)
	// The lost event carries the REQUESTED id (the one the user expected).
	if evs[0].SessionID != fixtureSID {
		t.Fatalf("lost session id = %q, want the requested %q", evs[0].SessionID, fixtureSID)
	}
}

// --- turn lifecycle ----------------------------------------------------------

func TestQwenDO_TurnLifecycle(t *testing.T) {
	s, _ := newFixtureState(false, "")
	// Activation.
	evs := feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	assertEventTypes(t, evs, session.EventSessionStarted)

	// Machine submit: the `user` event for the submitted text is the
	// submit-accepted signal (turn start).
	s.beginMachineTurn("turn-1", "hello")
	evs = feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	assertEventTypes(t, evs, session.EventTurnStarted)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}

	// Deltas (transcript chunks).
	evs = feedLines(t, s, streamDeltaLine(t, fixtureSID, "chunk1"))
	assertEventTypes(t, evs, session.EventTurnOutput)
	if evs[0].Output != "chunk1" {
		t.Fatalf("output = %q, want chunk1", evs[0].Output)
	}
	evs = feedLines(t, s, streamDeltaLine(t, fixtureSID, "chunk2"))
	assertEventTypes(t, evs, session.EventTurnOutput)
	if evs[0].Output != "chunk2" {
		t.Fatalf("output = %q, want chunk2", evs[0].Output)
	}

	// message_stop (no event; the turn completes at the assistant finalize).
	evs = feedLines(t, s, messageStopLine(t, fixtureSID))
	assertEventTypes(t, evs)

	// assistant finalize (turn end + usage).
	evs = feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 10, 20, 5))
	assertEventTypes(t, evs, session.EventTurnCompleted)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].Model != "test-model" {
		t.Fatalf("model = %q, want test-model", evs[0].Model)
	}
	if evs[0].InputTokens == nil || *evs[0].InputTokens != 10 {
		t.Fatalf("input tokens = %v, want 10", evs[0].InputTokens)
	}
	if evs[0].OutputTokens == nil || *evs[0].OutputTokens != 20 {
		t.Fatalf("output tokens = %v, want 20", evs[0].OutputTokens)
	}
	if evs[0].CachedTokens == nil || *evs[0].CachedTokens != 5 {
		t.Fatalf("cached tokens = %v, want 5", evs[0].CachedTokens)
	}
}

// TestQwenDO_TurnEndAssistantBeforeMessageStop is the ordering observed
// against the REAL 0.24.0 build: the assistant finalize PRECEDES the
// message_stop stream event. The turn must complete at the finalize
// (the order of the two is not guaranteed), and the late message_stop is
// a no-op.
func TestQwenDO_TurnEndAssistantBeforeMessageStop(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	feedLines(t, s, streamDeltaLine(t, fixtureSID, "chunk"))
	// The observed order: the finalize arrives BEFORE message_stop.
	evs := feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 10, 20, 5))
	assertEventTypes(t, evs, session.EventTurnCompleted)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	// The late message_stop is a no-op (the turn is already settled).
	evs = feedLines(t, s, messageStopLine(t, fixtureSID))
	assertEventTypes(t, evs)
}

// TestQwenDO_ToolUseAssistantDoesNotEndTurn: an assistant message that
// carries a tool_use block is mid-turn (the tool result + the next model
// message follow). The turn completes at the FINAL assistant message —
// the one without a tool_use block.
func TestQwenDO_ToolUseAssistantDoesNotEndTurn(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// Model message 1: a tool call (mid-turn — the turn does NOT end).
	evs := feedLines(t, s, assistantToolUseLine(t, fixtureSID, "test-model", 10, 5, 0))
	assertEventTypes(t, evs)
	// The tool result (a tool boundary, not a submit).
	evs = feedLines(t, s, userToolResultLine(t, fixtureSID))
	assertEventTypes(t, evs)
	// Model message 2: the final reply (the turn ends here; usage is
	// accumulated across BOTH model messages).
	evs = feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 12, 7, 0))
	assertEventTypes(t, evs, session.EventTurnCompleted)
	if evs[0].InputTokens == nil || *evs[0].InputTokens != 22 {
		t.Fatalf("input tokens = %v, want 22 (accumulated across both messages)", evs[0].InputTokens)
	}
	if evs[0].OutputTokens == nil || *evs[0].OutputTokens != 12 {
		t.Fatalf("output tokens = %v, want 12 (accumulated across both messages)", evs[0].OutputTokens)
	}
}

// TestQwenDO_MultiBlockStepTextThenToolUseDoesNotEndTurn is the sequence
// captured against the REAL 0.24.0 build (2026-09-17, ask_user_question
// prompt): the model emits its intro text as an assistant finalize, then
// a tool_use block as a SECOND assistant finalize of the SAME model step
// (different message.id), then message_stop, then the ask_user_question
// control_request. The turn must NOT end at the intro-text finalize —
// the pre-fix rule (a text-only finalize ends the turn) ended it early,
// orphaned the interaction (the tool the model actually called never
// surfaced), and the next machine submit was then written to a TUI parked
// on the unanswered question (never acknowledged). The turn stays in
// flight (parked on the human interaction) until the human answers in
// the PTY: the answer is a tool_result user event, and the final
// text-only step completes the turn.
func TestQwenDO_MultiBlockStepTextThenToolUseDoesNotEndTurn(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "ask me a question")
	feedLines(t, s, userTextLine(t, fixtureSID, "ask me a question"))

	// Model step: the intro-text block group finalizes. With the step
	// still OPEN (message_stop not seen), this must NOT end the turn.
	feedLines(t, s, messageStartLine(t, fixtureSID))
	feedLines(t, s, streamDeltaLine(t, fixtureSID, "I'll ask"))
	evs := feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 10, 5, 0))
	assertEventTypes(t, evs)

	// The tool_use block group (a separate assistant event, same step).
	evs = feedLines(t, s, assistantToolUseLine(t, fixtureSID, "test-model", 12, 3, 0))
	assertEventTypes(t, evs)
	// The step closes: the turn still does not end (the step carried a
	// tool_use).
	evs = feedLines(t, s, messageStopLine(t, fixtureSID))
	assertEventTypes(t, evs)

	// The model's ask_user_question: a HUMAN-ONLY interaction on the
	// machine stream (the turn is still in flight — exactly what the
	// early-turn-end bug broke).
	evs = feedLines(t, s, controlRequestLine(t, fixtureSID, "req-q", "ask_user_question"))
	assertEventTypes(t, evs, session.EventInteractionStarted)
	if evs[0].Interaction == nil || evs[0].Interaction.Kind != "question" {
		t.Fatalf("interaction = %+v, want kind question", evs[0].Interaction)
	}
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("interaction turn = %q, want turn-1", evs[0].TurnID)
	}

	// The human answers in the PTY: the answer arrives as a tool_result
	// user event, and the final text-only step completes the turn (usage
	// accumulated across the whole turn).
	feedLines(t, s, userToolResultLine(t, fixtureSID))
	feedLines(t, s, messageStartLine(t, fixtureSID))
	feedLines(t, s, streamDeltaLine(t, fixtureSID, "Thanks"))
	feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 15, 2, 0))
	evs = feedLines(t, s, messageStopLine(t, fixtureSID))
	assertEventTypes(t, evs, session.EventTurnCompleted)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].InputTokens == nil || *evs[0].InputTokens != 37 {
		t.Fatalf("input tokens = %v, want 37 (accumulated across the turn)", evs[0].InputTokens)
	}
	if evs[0].OutputTokens == nil || *evs[0].OutputTokens != 10 {
		t.Fatalf("output tokens = %v, want 10 (accumulated across the turn)", evs[0].OutputTokens)
	}
}

func TestQwenDO_ToolResultUserEventIsBoundary(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// A user event with a tool_result is a tool boundary (the model
	// receiving a tool result), not a submit: no normalized event.
	evs := feedLines(t, s, userToolResultLine(t, fixtureSID))
	assertEventTypes(t, evs)
}

func TestQwenDO_ContinueTurnFailed(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// continue_turn_failed is a terminal failure for the in-flight machine
	// turn.
	evs := feedLines(t, s, systemSubtypeLine(t, fixtureSID, "continue_turn_failed"))
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
}

func TestQwenDO_RetryAndModelFallbackNotes(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// retry / model_fallback are non-terminal: surfaced as a visible note
	// on the in-flight machine turn (the turn continues).
	evs := feedLines(t, s, systemSubtypeLine(t, fixtureSID, "retry"))
	assertEventTypes(t, evs, session.EventTurnOutput)
	if evs[0].Output != "[qwen] retry" {
		t.Fatalf("output = %q, want [qwen] retry", evs[0].Output)
	}
	evs = feedLines(t, s, systemSubtypeLine(t, fixtureSID, "model_fallback"))
	assertEventTypes(t, evs, session.EventTurnOutput)
	if evs[0].Output != "[qwen] model_fallback" {
		t.Fatalf("output = %q, want [qwen] model_fallback", evs[0].Output)
	}
}

// --- provider-error classification (Phase I) ---------------------------------

// TestQwenDO_FinalTextRateLimitedIsTurnFailed: the provider can return a
// 429 as the model's "final answer" (the error text IS the response). The
// machine turn must end as a CLASSIFIED failure (rate_limited + the
// provider-supplied retry time), not a completion. This sequence is the
// observed 0.24.0 order: the finalize PRECEDES message_stop, so the turn
// completes at the message_stop case.
func TestQwenDO_FinalTextRateLimitedIsTurnFailed(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	feedLines(t, s, messageStartLine(t, fixtureSID))
	feedLines(t, s, streamDeltaLine(t, fixtureSID, "Error: 429"))
	const providerErr = "Error: 429 Too Many Requests. retry after: 120 seconds"
	// The finalize does not end the turn (the step is still open).
	evs := feedLines(t, s, assistantTextLine(t, fixtureSID, "test-model", providerErr, 10, 20, 5))
	assertEventTypes(t, evs)
	// The step closes: the turn ends — as a classified provider failure.
	evs = feedLines(t, s, messageStopLine(t, fixtureSID))
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].FailureKind != "rate_limited" {
		t.Fatalf("failure kind = %q, want rate_limited", evs[0].FailureKind)
	}
	if evs[0].Error != providerErr {
		t.Fatalf("failure error = %q, want the provider text", evs[0].Error)
	}
	if evs[0].RetryAt == nil {
		t.Fatal("retryAt is nil, want the provider-supplied retry time")
	}
	ts, err := time.Parse(time.RFC3339, *evs[0].RetryAt)
	if err != nil {
		t.Fatalf("retryAt %q does not parse as RFC3339: %v", *evs[0].RetryAt, err)
	}
	// The provider said 120 seconds; the classifier anchors it to the
	// wall clock. Assert a sane window, not an exact timestamp.
	delta := time.Until(ts)
	if delta < 60*time.Second || delta > 300*time.Second {
		t.Fatalf("retryAt = %s (%s from now), want ≈120s in the future", *evs[0].RetryAt, delta)
	}
}

// TestQwenDO_FinalTextAuthErrorIsTurnFailed: an auth failure signature
// from the strict list (invalid_api_key) in the final text is a CLASSIFIED
// failure (auth_required). The text carries no retry time → RetryAt nil
// (the control plane never invents one). This sequence is the
// stop-before-finalize order: the turn completes at the assistant finalize
// (the !messageOpen path).
func TestQwenDO_FinalTextAuthErrorIsTurnFailed(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	feedLines(t, s, messageStartLine(t, fixtureSID))
	feedLines(t, s, messageStopLine(t, fixtureSID))
	const providerErr = "Error: invalid_api_key — the API key was not recognized"
	evs := feedLines(t, s, assistantTextLine(t, fixtureSID, "test-model", providerErr, 10, 20, 5))
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].FailureKind != "auth_required" {
		t.Fatalf("failure kind = %q, want auth_required", evs[0].FailureKind)
	}
	if evs[0].RetryAt != nil {
		t.Fatalf("retryAt = %v, want nil (no retry time in the text)", *evs[0].RetryAt)
	}
}

// TestQwenDO_OrdinaryFinalTextIsNotMisclassified: a plain task result —
// including text with LOOSE provider-ish phrases ("authentication",
// "connection refused") that the strict classifier deliberately excludes —
// must STILL complete the turn. Ordinary output is never classified as a
// failure (Phase I). The sequence reuses the shape of the happy-path
// finalize test (stop before the finalize).
func TestQwenDO_OrdinaryFinalTextIsNotMisclassified(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	feedLines(t, s, messageStopLine(t, fixtureSID))
	const answer = "Done: I fixed the authentication bug and the connection refused case in the test suite."
	evs := feedLines(t, s, assistantTextLine(t, fixtureSID, "test-model", answer, 10, 20, 5))
	assertEventTypes(t, evs, session.EventTurnCompleted)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].InputTokens == nil || *evs[0].InputTokens != 10 {
		t.Fatalf("input tokens = %v, want 10", evs[0].InputTokens)
	}
	if evs[0].OutputTokens == nil || *evs[0].OutputTokens != 20 {
		t.Fatalf("output tokens = %v, want 20", evs[0].OutputTokens)
	}
}

// TestQwenDO_ContinueTurnFailedProviderErrorIsClassified: the
// continue_turn_failed data carries the provider error that killed the
// continuation (a 429 with a retry time) — the terminal failure is
// CLASSIFIED (rate_limited + the provider-supplied retry time), not a
// generic process_error.
func TestQwenDO_ContinueTurnFailedProviderErrorIsClassified(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	line := marshalLine(t, qwenDOEvent{
		Type: "system", Subtype: "continue_turn_failed", SessionID: fixtureSID,
		Data: json.RawMessage(`{"error":"429 Too Many Requests. retry after: 60 seconds"}`),
	})
	evs := feedLines(t, s, line)
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].FailureKind != "rate_limited" {
		t.Fatalf("failure kind = %q, want rate_limited", evs[0].FailureKind)
	}
	if evs[0].RetryAt == nil {
		t.Fatal("retryAt is nil, want the provider-supplied retry time")
	}
	ts, err := time.Parse(time.RFC3339, *evs[0].RetryAt)
	if err != nil {
		t.Fatalf("retryAt %q does not parse as RFC3339: %v", *evs[0].RetryAt, err)
	}
	delta := time.Until(ts)
	if delta < 30*time.Second || delta > 180*time.Second {
		t.Fatalf("retryAt = %s (%s from now), want ≈60s in the future", *evs[0].RetryAt, delta)
	}
}

// TestQwenDO_ContinueTurnFailedNonProviderTextStaysProcessError: data that
// is NOT a provider error (no strict signature) keeps today's generic
// process_error with the same error string.
func TestQwenDO_ContinueTurnFailedNonProviderTextStaysProcessError(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	line := marshalLine(t, qwenDOEvent{
		Type: "system", Subtype: "continue_turn_failed", SessionID: fixtureSID,
		Data: json.RawMessage(`{"error":"internal bridge fault"}`),
	})
	evs := feedLines(t, s, line)
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].FailureKind != "process_error" {
		t.Fatalf("failure kind = %q, want process_error", evs[0].FailureKind)
	}
	if evs[0].Error != "qwen continue_turn_failed" {
		t.Fatalf("error = %q, want the generic string", evs[0].Error)
	}
	if evs[0].RetryAt != nil {
		t.Fatalf("retryAt = %v, want nil", *evs[0].RetryAt)
	}
}

// --- interactions ------------------------------------------------------------

func TestQwenDO_InteractionPermission(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// A can_use_tool control_request (a permission) on the machine stream.
	evs := feedLines(t, s, controlRequestLine(t, fixtureSID, "req-1", "bash"))
	assertEventTypes(t, evs, session.EventInteractionStarted)
	if evs[0].Interaction == nil {
		t.Fatal("interaction is nil")
	}
	if evs[0].Interaction.Kind != "permission" {
		t.Fatalf("kind = %q, want permission", evs[0].Interaction.Kind)
	}
	if evs[0].Interaction.NativeInteractionID != "req-1" {
		t.Fatalf("native id = %q, want req-1", evs[0].Interaction.NativeInteractionID)
	}
	if evs[0].Interaction.Resolved {
		t.Fatal("started event must not be resolved")
	}
	// The resolution (allowed = proceed_once).
	evs = feedLines(t, s, controlResponseLine(t, fixtureSID, "req-1", true))
	assertEventTypes(t, evs, session.EventInteractionResolved)
	if evs[0].Interaction.Decision != "resolved" {
		t.Fatalf("decision = %q, want resolved", evs[0].Interaction.Decision)
	}
	if !evs[0].Interaction.Resolved {
		t.Fatal("resolved event must be resolved")
	}
}

func TestQwenDO_InteractionCancelled(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	feedLines(t, s, controlRequestLine(t, fixtureSID, "req-1", "bash"))
	// The resolution (not allowed = cancel).
	evs := feedLines(t, s, controlResponseLine(t, fixtureSID, "req-1", false))
	assertEventTypes(t, evs, session.EventInteractionResolved)
	if evs[0].Interaction.Decision != "cancelled" {
		t.Fatalf("decision = %q, want cancelled", evs[0].Interaction.Decision)
	}
}

func TestQwenDO_InteractionAskUserQuestionIsHumanOnly(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// ask_user_question is HUMAN-ONLY (doc §6.3 / R3): kind = question.
	evs := feedLines(t, s, controlRequestLine(t, fixtureSID, "req-2", "ask_user_question"))
	assertEventTypes(t, evs, session.EventInteractionStarted)
	if evs[0].Interaction.Kind != "question" {
		t.Fatalf("kind = %q, want question (ask_user_question is human-only)", evs[0].Interaction.Kind)
	}
}

func TestQwenDO_InteractionDedup(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// The first control_request for a request_id is observed.
	evs := feedLines(t, s, controlRequestLine(t, fixtureSID, "req-1", "bash"))
	assertEventTypes(t, evs, session.EventInteractionStarted)
	// A duplicate control_request (same request_id) is ignored (dedup).
	evs = feedLines(t, s, controlRequestLine(t, fixtureSID, "req-1", "bash"))
	assertEventTypes(t, evs)
	// The first control_response resolves the interaction.
	evs = feedLines(t, s, controlResponseLine(t, fixtureSID, "req-1", true))
	assertEventTypes(t, evs, session.EventInteractionResolved)
	// A second control_response (the loser of a race) is ignored (dedup).
	evs = feedLines(t, s, controlResponseLine(t, fixtureSID, "req-1", false))
	assertEventTypes(t, evs)
}

// --- watchdogs ---------------------------------------------------------------

func TestQwenDO_SubmitCorrelationDeadline(t *testing.T) {
	s, c := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	// A machine submit that is not acknowledged (no `user` event) within
	// the deadline, while the TUI is idle, is a FAILED submit.
	s.beginMachineTurn("turn-1", "hello")
	c.advance(6 * time.Second) // > the 5s correlation deadline
	evs := s.tick()
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].FailureKind != "process_error" {
		t.Fatalf("failure kind = %q, want process_error", evs[0].FailureKind)
	}
}

func TestQwenDO_SubmitAcknowledgedBeforeDeadline(t *testing.T) {
	s, c := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	c.advance(1 * time.Second) // within the deadline
	// The `user` event for the submitted text acknowledges the submit.
	evs := feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	assertEventTypes(t, evs, session.EventTurnStarted)
	// No deadline failure (the submit was acknowledged).
	c.advance(6 * time.Second)
	evs = s.tick()
	assertEventTypes(t, evs)
}

// TestQwenDO_SubmitEchoTrailingWhitespaceMissesCorrelation is the contract
// hazard that the driver's Submit normalization exists to prevent
// (observed against the REAL 0.24.0 build): the input channel is a line
// protocol and the TUI submit strips trailing whitespace from the
// submitted text, so the echoed `user` event can differ from what was
// written by exactly the trailing "\n". The B6 correlation is an EXACT
// match, so a missed echo misclassifies the machine turn as a human
// turn: no turn.started / turn.completed on the machine stream (the
// daemon's turn never completes), and once the misclassified turn ends,
// tick()'s correlation deadline (checked only while the TUI is idle)
// surfaces the phantom "submit not acknowledged" failure. The driver
// therefore never writes trailing whitespace (strings.TrimRight at the
// channel boundary — see Submit); the state machine stays strict on
// purpose.
func TestQwenDO_SubmitEchoTrailingWhitespaceMissesCorrelation(t *testing.T) {
	s, c := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	// The UN-normalized payload: the daemon's delivery appends the
	// contract text with a trailing newline, and the TUI submit strips
	// it on the way in.
	s.beginMachineTurn("turn-1", "hello\n")
	// The receiver's echo (trailing whitespace stripped) does not match
	// the submitted text: the turn is classified HUMAN — no machine-stream
	// event.
	evs := feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	assertEventTypes(t, evs)
	// The model runs the whole turn (a complete step) — none of it is on
	// the machine stream (the deltas, the stop, the finalize: no events).
	feedLines(t, s, messageStartLine(t, fixtureSID))
	evs = feedLines(t, s, streamDeltaLine(t, fixtureSID, "chunk"))
	assertEventTypes(t, evs)
	feedLines(t, s, messageStopLine(t, fixtureSID))
	evs = feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 1, 1, 0))
	assertEventTypes(t, evs)
	// The machine turn never completed: the correlation deadline (the
	// turn is over, the TUI is idle) fires the phantom failure for the
	// still-pending machine submit.
	c.advance(6 * time.Second) // > the 5s correlation deadline
	evs = s.tick()
	assertEventTypes(t, evs, session.EventTurnFailed)
	if evs[0].TurnID != "turn-1" {
		t.Fatalf("turn id = %q, want turn-1", evs[0].TurnID)
	}
	if evs[0].FailureKind != "process_error" {
		t.Fatalf("failure kind = %q, want process_error", evs[0].FailureKind)
	}
}

func TestQwenDO_InFlightStallWarning(t *testing.T) {
	s, c := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello")) // turn in flight
	// No events for the stall window (and no pending interaction): an
	// ALERTABLE condition, surfaced (not a kill).
	c.advance(61 * time.Second) // > the 60s stall window
	evs := s.tick()
	assertEventTypes(t, evs, session.EventTurnOutput)
	if evs[0].Output != "[qwen] turn stalled: no events for 1m0s" {
		t.Fatalf("output = %q, want the stall warning", evs[0].Output)
	}
	// The warning is emitted once (stallWarned).
	evs = s.tick()
	assertEventTypes(t, evs)
}

func TestQwenDO_StallSuppressedWhileInteractionPending(t *testing.T) {
	s, c := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	s.beginMachineTurn("turn-1", "hello")
	feedLines(t, s, userTextLine(t, fixtureSID, "hello"))
	// A pending interaction is an expected pause, not a stall.
	feedLines(t, s, controlRequestLine(t, fixtureSID, "req-1", "bash"))
	c.advance(61 * time.Second)
	evs := s.tick()
	assertEventTypes(t, evs)
}

// --- unknown-event tolerance -------------------------------------------------

func TestQwenDO_UnknownEventTolerance(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	// An unknown event type is forward-compatible noise: ignored.
	evs := feedLines(t, s, marshalLine(t, qwenDOEvent{Type: "foo", SessionID: fixtureSID}))
	assertEventTypes(t, evs)
	// A `result` event is NOT emitted in dual-output mode (doc §3.3): if
	// one ever appears, it is forward-compatible noise: ignored.
	evs = feedLines(t, s, marshalLine(t, qwenDOEvent{Type: "result", SessionID: fixtureSID}))
	assertEventTypes(t, evs)
	// An unknown stream_event subtype is opaque: ignored.
	se := qwenDOStreamEvent{Type: "some_new_subtype"}
	m, _ := json.Marshal(se)
	evs = feedLines(t, s, marshalLine(t, qwenDOEvent{Type: "stream_event", SessionID: fixtureSID, Event: m}))
	assertEventTypes(t, evs)
	// An unparseable line is skipped (the qwen watcher skips them too).
	evs = feedLines(t, s, "{not json")
	assertEventTypes(t, evs)
}

// --- human turns -------------------------------------------------------------

func TestQwenDO_HumanTurnNotOnMachineStream(t *testing.T) {
	s, _ := newFixtureState(false, "")
	feedLines(t, s, validHandshakeLine(t, fixtureSID, fixtureCWD))
	// A human submit (no machine turn registered): a human turn begins.
	// Its events are NOT part of the machine stream (no normalized events).
	evs := feedLines(t, s, userTextLine(t, fixtureSID, "human input"))
	assertEventTypes(t, evs)
	// A human turn's deltas are not on the machine stream.
	evs = feedLines(t, s, streamDeltaLine(t, fixtureSID, "human output"))
	assertEventTypes(t, evs)
	// A human turn's finalize is not on the machine stream.
	feedLines(t, s, messageStopLine(t, fixtureSID))
	evs = feedLines(t, s, assistantLine(t, fixtureSID, "test-model", 1, 1, 0))
	assertEventTypes(t, evs)
}
