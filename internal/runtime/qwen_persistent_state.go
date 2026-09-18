package runtime

// Qwen Dual Output event-stream state machine (runtime-lifecycle refactor,
// Phase 4 / B4).
//
// qwenTurnState is the per-endpoint turn/interaction state machine for the
// Qwen Dual Output structured event stream (doc §3). It is driven one JSONL
// line at a time (processLine) and is directly testable: the fixture harness
// feeds scripted event sequences and asserts the normalized
// session.SessionEvent stream (no model needed, CI-safe).
//
// There is NO `result` event in dual-output mode (doc §3.3: emitResult count
// = 0 in the interactive wiring; it is advertised in supported_events — do
// NOT code against it). The state machine derives turn boundaries:
//
//   - turn start: the `user` event for the submitted text (a machine
//     submit — the submit-accepted signal, doc §4.2) or a `message_start`
//     (a human turn).
//   - turn end: the CLOSE of a model step (message_start..message_stop)
//     on a text-only final answer. Qwen Code emits ONE `assistant` event
//     PER content block group of a step (each with its own message.id),
//     so a text-only finalize does NOT end the turn — the model emits
//     intro text and a tool_use call as separate assistant events of the
//     SAME step (observed against the real 0.24.0 build). A step that
//     carried a tool_use continues (the tool result + the next step
//     follow); a step parked on a human interaction (ask_user_question)
//     stays in flight until the human answers (the answer is a
//     tool_result user event starting the next step). The order of the
//     step's final text-only finalize relative to message_stop is NOT
//     guaranteed (observed: the finalize can PRECEDE message_stop), so
//     completion keys on both: the step closes on a text-only final
//     answer, whether the stop or the finalize arrives first. Usage is
//     accumulated from assistant.message.usage (per turn; there is no
//     result.usage / duration_ms).
//
// Provider errors can be dressed as success (Phase I): the provider can
// return a 429/quota/auth failure as the model's "final answer" (the
// error text IS the response). At machine-turn completion the step's
// final text-only answer text is scanned with the strict classifier
// (LooksLikeProviderError) — a match ends the turn as a CLASSIFIED
// turn.failed (kind + provider-supplied retry time), not a completion.
// Ordinary task output (even text mentioning "authentication" or
// "connection refused") never matches the strict list. Human turns are
// not classified (not on the machine stream — the same condition the B6
// submit correlation uses).
//
// It is robust to unknown content_block/delta types (thinking blocks, etc.)
// — they are opaque and never a failure (B4).
//
// Concurrency: the state machine is owned by one endpoint. processLine is
// called from the endpoint's readLoop goroutine; beginMachineTurn /
// clearMachineTurn / tick are called from the driver's Submit / watchdog
// goroutines. All access is under s.mu.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// Watchdog windows (B6 / B7).
const (
	// submitCorrelationDeadline bounds how long a machine submit waits for
	// its `user` event (the submit-accepted signal) while the TUI is idle
	// (B6: ~5s = 2× the 500ms input poll + margin). A submit not
	// acknowledged within the deadline (with no turn in flight) is a
	// FAILED submit — surfaced, never blind-retried (a retry risks a
	// genuine duplicate; the input channel has no idempotency, doc §4.3).
	submitCorrelationDeadline = 5 * time.Second
	// inFlightStallWindow is the in-flight stall watchdog window (B7: 60s;
	// the model can think — this is an ALERTABLE condition, surfaced to the
	// instance, NOT an automatic kill; the daemon's turn deadline remains
	// the kill switch). It is the only defense against the bridge's silent
	// self-disable (doc §7.2: EPIPE / 1MiB backpressure / any emit
	// exception disables the bridge while the TUI keeps running with no
	// observability).
	inFlightStallWindow = 60 * time.Second
)

// qwenTurnState is the per-endpoint turn/interaction state machine.
type qwenTurnState struct {
	mu sync.Mutex

	// session (from the handshake — the version is read from the
	// handshake ONLY; the symlinked package version lies, doc §1.1).
	sessionID string
	version   string
	cwd       string
	activated bool
	gateErr   string // a handshake gate failure ("" = passed)
	resuming  bool
	resumeID  string

	// turn
	turnActive    bool
	turnIsMachine bool
	stallWarned   bool // the in-flight stall warning was emitted this turn

	// model-step tracking (turn-end detection, B4): one model step is a
	// message_start..message_stop window. Qwen Code emits ONE assistant
	// event PER content block of the step (each with its own message.id —
	// a text block and a tool_use block of the SAME step are DIFFERENT
	// assistant events), so a text-only finalize does NOT end the step:
	// a tool_use block may follow it. The turn ends only when a step
	// CLOSES (message_stop) on a text-only final answer (stepTextFinalize
	// && !stepToolUse). A step that carried a tool_use continues (the tool
	// result + the next step follow); a step parked on a human
	// interaction (ask_user_question) stays in flight until the human
	// answers (the answer is a tool_result user event starting the next
	// step).
	messageOpen      bool   // inside message_start..message_stop
	stepTextFinalize bool   // a text-only assistant finalize in this step
	stepToolUse      bool   // a tool_use assistant finalize in this step
	stepFinalText    string // the step's accumulated final text-only answer text

	// machine submit correlation (B6)
	machineTurnID   string
	submittedText   string
	submitDelivered bool
	submitAt        time.Time

	// usage accumulation for the in-flight turn (per turn; no result.usage)
	inInput, inOutput, inCached int
	inModel                     string

	// interactions (request_id → info); dedup on request_id (doc §6.2)
	interactions map[string]*qwenInteraction

	// watchdog clock (injectable for tests)
	now func() time.Time
	// lastEventAt is the time of the last processed event (the stall
	// watchdog anchor).
	lastEventAt time.Time
}

// qwenInteraction is one observed native interaction (a can_use_tool
// control_request) awaiting (or having had) a resolution.
type qwenInteraction struct {
	requestID       string
	kind            string // question (human-only) | permission (remote)
	toolName        string
	summary         string
	payload         json.RawMessage
	onMachineStream bool // the started event was emitted on the machine stream
}

func newQwenTurnState(resuming bool, resumeID string, now func() time.Time) *qwenTurnState {
	if now == nil {
		now = time.Now
	}
	return &qwenTurnState{
		resuming:     resuming,
		resumeID:     resumeID,
		interactions: map[string]*qwenInteraction{},
		now:          now,
		lastEventAt:  now(),
	}
}

// processLine parses one JSONL line from the event file and returns the
// normalized events to emit (in order). It mutates the state. An
// unparseable line is skipped (the qwen watcher skips them too — doc §4.1).
func (s *qwenTurnState) processLine(line []byte) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastEventAt = s.now()
	var ev qwenDOEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil
	}
	switch ev.Type {
	case "system":
		return s.processSystem(ev)
	case "user":
		return s.processUser(ev)
	case "assistant":
		return s.processAssistant(ev)
	case "stream_event":
		return s.processStreamEvent(ev)
	case "control_request":
		return s.processControlRequest(ev)
	case "control_response":
		return s.processControlResponse(ev)
	case "result":
		// NOT emitted in dual-output mode (doc §3.3) — do not code against
		// it. If one ever appears, it is forward-compatible noise: ignore.
		return nil
	default:
		// Unknown event type: forward-compatible noise. Ignore.
		return nil
	}
}

// beginMachineTurn registers the in-flight machine turn (its logical id and
// the submitted text to correlate). Called by the driver's Submit before
// writing the submit to the input file.
func (s *qwenTurnState) beginMachineTurn(turnID, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.machineTurnID = turnID
	s.submittedText = text
	s.submitDelivered = false
	s.submitAt = s.now()
	s.stallWarned = false
}

// clearMachineTurn clears the in-flight machine turn (on a submit
// completion, failure, or ctx cancel). It does not touch the turn-active
// state (the readLoop's terminal-event path ends the turn).
func (s *qwenTurnState) clearMachineTurn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearMachineTurnLocked()
}

func (s *qwenTurnState) clearMachineTurnLocked() {
	s.machineTurnID = ""
	s.submittedText = ""
	s.submitDelivered = false
	s.submitAt = time.Time{}
}

// tick checks the time-based conditions (submit correlation deadline,
// in-flight stall) and returns any events to emit. The watchdog goroutine
// calls it periodically.
func (s *qwenTurnState) tick() []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Submit correlation deadline (B6): a machine submit that was not
	// acknowledged (no `user` event for its text) within the deadline,
	// while the TUI is idle (no turn in flight), is a FAILED submit —
	// surfaced, never blind-retried.
	if s.machineTurnID != "" && !s.submitDelivered && !s.turnActive &&
		!s.submitAt.IsZero() && now.Sub(s.submitAt) > submitCorrelationDeadline {
		turnID := s.machineTurnID
		sid := s.sessionID
		s.clearMachineTurnLocked()
		return []session.SessionEvent{{
			Type:        session.EventTurnFailed,
			SessionID:   sid,
			TurnID:      turnID,
			FailureKind: string(domain.RuntimeFailureProcessError),
			Error:       "qwen submit not acknowledged (no user event within the correlation deadline)",
		}}
	}
	// In-flight stall (B7): a turn in flight with no events for the stall
	// window (and no pending interaction — a turn parked on an interaction
	// is an expected pause, not a stall) is an ALERTABLE condition:
	// surfaced, not an automatic kill.
	if s.turnActive && s.turnIsMachine && !s.stallWarned &&
		len(s.interactions) == 0 && now.Sub(s.lastEventAt) > inFlightStallWindow {
		s.stallWarned = true
		return []session.SessionEvent{{
			Type:      session.EventTurnOutput,
			SessionID: s.sessionID,
			TurnID:    s.machineTurnID,
			Output:    "[qwen] turn stalled: no events for " + inFlightStallWindow.String(),
		}}
	}
	return nil
}

// --- accessors (for the driver and the fixture tests) ----------------------
// (The accessor names avoid colliding with the same-named struct fields.)

func (s *qwenTurnState) nativeSessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

func (s *qwenTurnState) nativeVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

func (s *qwenTurnState) nativeCWD() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cwd
}

func (s *qwenTurnState) isActivated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activated
}

func (s *qwenTurnState) handshakeGateErr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gateErr
}

func (s *qwenTurnState) isSubmitDelivered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submitDelivered
}

// --- system events ----------------------------------------------------------

func (s *qwenTurnState) processSystem(ev qwenDOEvent) []session.SessionEvent {
	switch ev.Subtype {
	case "session_start":
		return s.processSessionStart(ev)
	case "session_end":
		// Clean shutdown: no normalized event (the process exit is handled
		// by the readLoop's EOF path).
		return nil
	case "session_recording_degraded":
		// Resume silently stops working after this (doc §3.2) — surface it.
		// If a machine turn is in flight, emit it as a visible note;
		// otherwise there is no turn to attach it to (the readLoop logs).
		if s.turnActive && s.turnIsMachine {
			return []session.SessionEvent{{
				Type:      session.EventTurnOutput,
				SessionID: s.sessionID,
				TurnID:    s.machineTurnID,
				Output:    "[qwen] session recording degraded: resume may stop working",
			}}
		}
		return nil
	case "continue_turn_failed":
		// The turn's continuation failed — a terminal failure for the
		// in-flight machine turn (B4). The event's data may carry the
		// failure text (the provider error that killed the
		// continuation): when it carries a strong provider-error
		// signature, classify it (kind + provider-supplied retry time);
		// otherwise it is a process-level failure (the text is not
		// established as a provider error — keep the generic kind and
		// the same error string).
		if s.turnActive && s.turnIsMachine {
			turnID := s.machineTurnID
			sid := s.sessionID
			s.endTurnLocked()
			if text := qwenSystemErrorText(ev.Data); text != "" && LooksLikeProviderError(text) {
				kind, retryAt := ClassifyProviderError(text)
				return []session.SessionEvent{{
					Type:        session.EventTurnFailed,
					SessionID:   sid,
					TurnID:      turnID,
					FailureKind: string(kind),
					Error:       trunc(text),
					RetryAt:     retryAt,
				}}
			}
			return []session.SessionEvent{{
				Type:        session.EventTurnFailed,
				SessionID:   sid,
				TurnID:      turnID,
				FailureKind: string(domain.RuntimeFailureProcessError),
				Error:       "qwen continue_turn_failed",
			}}
		}
		return nil
	case "retry", "model_fallback":
		// Non-terminal: the model is retrying / falling back. Surface as a
		// visible note on the in-flight machine turn (the turn continues).
		if s.turnActive && s.turnIsMachine {
			return []session.SessionEvent{{
				Type:      session.EventTurnOutput,
				SessionID: s.sessionID,
				TurnID:    s.machineTurnID,
				Output:    "[qwen] " + ev.Subtype,
			}}
		}
		return nil
	default:
		// Unknown system subtype: forward-compatible noise. Ignore.
		return nil
	}
}

// processSessionStart handles the handshake (always the first event, doc
// §5.1). It sets the session identity, enforces the version gate (B2 / R1 /
// R8), and emits session.started / session.resumed / session.lost.
func (s *qwenTurnState) processSessionStart(ev qwenDOEvent) []session.SessionEvent {
	var hs qwenDOHandshake
	_ = json.Unmarshal(ev.Data, &hs)
	sid := hs.SessionID
	if sid == "" {
		sid = ev.SessionID // fall back to the top-level invariant
	}
	s.sessionID = sid
	s.version = hs.Version
	s.cwd = hs.CWD
	s.activated = true

	// Handshake gate (B2 / R1 / R8): require data.version present,
	// protocol_version >= 2, supported_events a superset of the events the
	// adapter codes against. The version is read from the handshake ONLY.
	if err := gateQwenHandshake(hs); err != nil {
		s.gateErr = err.Error()
		return []session.SessionEvent{{
			Type:      session.EventSessionLost,
			SessionID: sid,
			Error:     "qwen handshake gate failed: " + err.Error(),
		}}
	}

	// Resume mismatch (B3): a requested resume that re-bases onto a
	// different session is a lost session, not a silent fresh one.
	if s.resuming && s.resumeID != "" && sid != s.resumeID {
		return []session.SessionEvent{{
			Type:      session.EventSessionLost,
			SessionID: s.resumeID,
			Error:     fmt.Sprintf("qwen resume started a different session (wanted %s, got %s)", s.resumeID, sid),
		}}
	}

	if s.resuming {
		return []session.SessionEvent{{
			Type:      session.EventSessionResumed,
			SessionID: sid,
		}}
	}
	return []session.SessionEvent{{
		Type:      session.EventSessionStarted,
		SessionID: sid,
	}}
}

// gateQwenHandshake enforces the version gate (B2 / R1 / R8).
func gateQwenHandshake(hs qwenDOHandshake) error {
	if hs.Version == "" {
		return errors.New("handshake carries no data.version")
	}
	if hs.ProtocolVersion < 2 {
		return fmt.Errorf("protocol_version %d < 2", hs.ProtocolVersion)
	}
	required := []string{"system", "user", "assistant", "stream_event",
		"control_request", "control_response"}
	supported := make(map[string]bool, len(hs.SupportedEvents))
	for _, e := range hs.SupportedEvents {
		supported[e] = true
	}
	for _, r := range required {
		if !supported[r] {
			return fmt.Errorf("supported_events missing %q", r)
		}
	}
	return nil
}

// qwenSystemErrorText extracts the failure text a system event's data
// carries (the continue_turn_failed data shape is not part of the
// versioned protocol — the bridge reports the failure message under a
// text field). A bare JSON string is accepted as the text itself; an
// object is probed for the usual text fields. It returns "" when the
// data is absent, unparseable, or carries no recognizable text field —
// the caller then keeps the generic failure (never a guess).
func qwenSystemErrorText(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return ""
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err == nil {
			return strings.TrimSpace(s)
		}
		return ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "text", "reason"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			if t := strings.TrimSpace(s); t != "" {
				return t
			}
		}
	}
	return ""
}

// --- user / assistant / stream events ---------------------------------------

func (s *qwenTurnState) processUser(ev qwenDOEvent) []session.SessionEvent {
	var msg qwenDOMessage
	if err := json.Unmarshal(ev.Message, &msg); err != nil {
		return nil
	}
	// A user event with a tool_result is a tool boundary (the model
	// receiving a tool result), not a submit (doc §4.2: a remote submit
	// produces one `user` event — except toolResult/goal kinds). The turn
	// continues; no normalized event. The boundary also ends the previous
	// step's tool-use context (its message_start..message_stop window is
	// over): the next step's final answer must not be shadowed by the
	// previous step's tool_use or its intro text (the step's own
	// message_start normally resets the flags; this covers streams that
	// omit it).
	for _, c := range msg.Content {
		if c.Type == "tool_result" {
			s.stepToolUse = false
			s.stepFinalText = ""
			return nil
		}
	}
	// A user event with text is a submit (machine or human).
	text := ""
	for _, c := range msg.Content {
		if c.Type == "text" {
			text = c.Text
			break
		}
	}
	if text == "" {
		return nil
	}
	// Correlate with the pending machine submit (B6): the `user` event for
	// the submitted text is the submit-accepted signal.
	if s.machineTurnID != "" && !s.submitDelivered && text == s.submittedText {
		s.submitDelivered = true
		if !s.turnActive {
			// The machine turn begins.
			s.turnActive = true
			s.turnIsMachine = true
			return []session.SessionEvent{{
				Type:      session.EventTurnStarted,
				SessionID: s.sessionID,
				TurnID:    s.machineTurnID,
			}}
		}
		return nil
	}
	// A human submit (no machine turn registered, or the text does not
	// match): a human turn begins. Its events are NOT part of the machine
	// stream (the human plane renders them in the TUI).
	if !s.turnActive {
		s.turnActive = true
		s.turnIsMachine = false
	}
	return nil
}

func (s *qwenTurnState) processStreamEvent(ev qwenDOEvent) []session.SessionEvent {
	var se qwenDOStreamEvent
	if err := json.Unmarshal(ev.Event, &se); err != nil {
		return nil
	}
	switch se.Type {
	case "message_start":
		// The model begins responding. If a turn is not yet active, begin
		// one (a machine turn when the submit was delivered but its user
		// event was missed; otherwise a human turn). A new step begins:
		// reset the per-step finalize flags.
		if !s.turnActive {
			s.turnActive = true
			s.turnIsMachine = s.machineTurnID != "" && s.submitDelivered
		}
		s.messageOpen = true
		s.stepTextFinalize = false
		s.stepToolUse = false
		s.stepFinalText = ""
		return nil
	case "content_block_delta":
		// Only text_delta is a transcript chunk. Other delta types
		// (thinking, etc.) are opaque — never a failure (B4).
		if se.Delta.Type == "text_delta" && se.Delta.Text != "" &&
			s.turnActive && s.turnIsMachine {
			return []session.SessionEvent{{
				Type:      session.EventTurnOutput,
				SessionID: s.sessionID,
				TurnID:    s.machineTurnID,
				Output:    se.Delta.Text,
			}}
		}
		return nil
	case "message_stop":
		// The model step is complete. The turn ends when a step CLOSES on
		// a text-only final answer (stepTextFinalize && !stepToolUse). A
		// step that carried a tool_use continues (the tool result + the
		// next step follow); a step parked on a human interaction stays in
		// flight. If the step's text-only finalize arrives AFTER this
		// event (the order is not guaranteed — observed: the finalize can
		// precede message_stop), processAssistant completes the turn on
		// the !messageOpen path instead.
		s.messageOpen = false
		if s.stepTextFinalize && !s.stepToolUse {
			return s.completeStepLocked()
		}
		s.stepTextFinalize = false
		s.stepToolUse = false
		return nil
	default:
		// content_block_start / content_block_stop / tool_progress /
		// goal_state / active_goal / unknown: opaque or non-transcript.
		// Ignore (robust to unknown types — B4).
		return nil
	}
}

func (s *qwenTurnState) processAssistant(ev qwenDOEvent) []session.SessionEvent {
	var msg qwenDOMessage
	if err := json.Unmarshal(ev.Message, &msg); err != nil {
		return nil
	}
	if !s.turnActive {
		return nil
	}
	// Accumulate usage (per turn; there is no result.usage — doc §3.3).
	// Only while a turn is active: usage is the in-flight turn's, and an
	// assistant message outside a turn (a protocol anomaly) must not leak
	// into the next turn's counters.
	s.inInput += msg.Usage.InputTokens
	s.inOutput += msg.Usage.OutputTokens
	s.inCached += msg.Usage.CacheRead
	if msg.Model != "" {
		s.inModel = msg.Model
	}
	// Step tracking (B4): this assistant event is ONE content block group
	// of the current model step — the model emits intro text and a
	// tool_use call as SEPARATE assistant events of the SAME step
	// (observed against the real 0.24.0 build). A tool_use block group is
	// mid-turn (the tool result + the next step follow). A text-only
	// block group is the step's final answer ONLY if the step closes
	// without any tool_use: the turn completes at message_stop
	// (processStreamEvent) or — when the finalize arrives AFTER the stop
	// (the order of the two is not guaranteed) — here, on the !messageOpen
	// path.
	hasToolUse := false
	for _, c := range msg.Content {
		if c.Type == "tool_use" {
			hasToolUse = true
			break
		}
	}
	if hasToolUse {
		s.stepToolUse = true
		return nil
	}
	s.stepTextFinalize = true
	// Accumulate the step's final text-only answer text (provider-error
	// classification at turn end scans it — see completeStepLocked). A
	// step's text-only block groups are its final answer; a step that
	// later carries a tool_use does not complete (its text is dropped at
	// the next step boundary).
	for _, c := range msg.Content {
		if c.Type == "text" && c.Text != "" {
			if s.stepFinalText == "" {
				s.stepFinalText = c.Text
			} else {
				s.stepFinalText += " " + c.Text
			}
		}
	}
	if !s.messageOpen && !s.stepToolUse {
		return s.completeStepLocked()
	}
	return nil
}

// completeStepLocked completes the in-flight turn on a step that closed
// with a text-only final answer (the caller holds s.mu and has
// established stepTextFinalize && !stepToolUse). A machine turn emits
// turn.completed with the accumulated usage — UNLESS the step's final
// text-only answer text carries a strong provider-error signature
// (Phase I: a 429/quota/auth failure dressed as the model's "final
// answer"), in which case the turn ends as a CLASSIFIED turn.failed
// (kind + provider-supplied retry time). A human turn ends without a
// normalized event (not part of the machine stream — human turns are
// never classified).
func (s *qwenTurnState) completeStepLocked() []session.SessionEvent {
	s.messageOpen = false
	s.stepTextFinalize = false
	s.stepToolUse = false
	finalText := s.stepFinalText
	s.stepFinalText = ""
	if !s.turnActive {
		return nil
	}
	if s.turnIsMachine {
		turnID := s.machineTurnID
		sid := s.sessionID
		model := s.inModel
		in, out, cached := s.inInput, s.inOutput, s.inCached
		s.endTurnLocked()
		// Providers can surface a 429/quota/auth error inside a
		// "successful" turn (the error text IS the final answer). Only
		// text with a strong provider-error signature counts as a
		// failure — ordinary task results must not be (Phase I).
		if LooksLikeProviderError(finalText) {
			kind, retryAt := ClassifyProviderError(finalText)
			return []session.SessionEvent{{
				Type:        session.EventTurnFailed,
				SessionID:   sid,
				TurnID:      turnID,
				FailureKind: string(kind),
				Error:       trunc(finalText),
				RetryAt:     retryAt,
			}}
		}
		return []session.SessionEvent{{
			Type:         session.EventTurnCompleted,
			SessionID:    sid,
			TurnID:       turnID,
			Model:        model,
			InputTokens:  intPtr(in),
			OutputTokens: intPtr(out),
			CachedTokens: intPtr(cached),
		}}
	}
	// A human turn completed: no normalized event (not part of the
	// machine stream).
	s.endTurnLocked()
	return nil
}

// endTurnLocked resets the in-flight turn state (the caller holds s.mu).
func (s *qwenTurnState) endTurnLocked() {
	s.turnActive = false
	s.turnIsMachine = false
	s.stallWarned = false
	s.inInput, s.inOutput, s.inCached = 0, 0, 0
	s.inModel = ""
	s.stepFinalText = ""
}

// --- interaction / permission protocol (doc §6) -----------------------------

func (s *qwenTurnState) processControlRequest(ev qwenDOEvent) []session.SessionEvent {
	if ev.RequestID == "" {
		return nil
	}
	// Dedup: a request_id is emitted once per callId (doc §6.1). If we
	// already have an interaction for this request_id, ignore.
	if _, ok := s.interactions[ev.RequestID]; ok {
		return nil
	}
	var req qwenDOControlRequest
	_ = json.Unmarshal(ev.Request, &req)
	if req.Subtype != "can_use_tool" {
		// Not a tool-approval request: forward-compatible noise. Ignore.
		return nil
	}
	// Kind: ask_user_question is HUMAN-ONLY (doc §6.3 / R3) — the daemon
	// MUST never auto-resolve it (a generic allowed:true yields a phantom
	// "No valid answers were provided." answer — worse than a hang).
	// Everything else is a remotely-resolvable permission (the only two
	// expressible outcomes are proceed_once / cancel — R10).
	kind := "permission"
	if req.ToolName == "ask_user_question" {
		kind = "question"
	}
	summary := fmt.Sprintf("qwen %s: %s", kind, req.ToolName)
	onMachineStream := s.turnActive && s.turnIsMachine
	s.interactions[ev.RequestID] = &qwenInteraction{
		requestID:       ev.RequestID,
		kind:            kind,
		toolName:        req.ToolName,
		summary:         summary,
		payload:         ev.Request,
		onMachineStream: onMachineStream,
	}
	if !onMachineStream {
		// A human turn's interaction is handled in the TUI (the human
		// plane), not the machine stream: record it (so the resolution is
		// observed) but emit no started event.
		return nil
	}
	return []session.SessionEvent{{
		Type:      session.EventInteractionStarted,
		SessionID: s.sessionID,
		TurnID:    s.machineTurnID,
		Interaction: &session.InteractionEvent{
			NativeInteractionID: ev.RequestID,
			Kind:                kind,
			Summary:             summary,
			NativePayload:       ev.Request,
			Resolved:            false,
		},
	}}
}

func (s *qwenTurnState) processControlResponse(ev qwenDOEvent) []session.SessionEvent {
	var resp qwenDOControlResponse
	if err := json.Unmarshal(ev.Response, &resp); err != nil {
		return nil
	}
	requestID := resp.RequestID
	if requestID == "" {
		return nil
	}
	inte, ok := s.interactions[requestID]
	if !ok {
		// We did not observe the request (or it was already resolved):
		// ignore (dedup — the loser of a race is expected noise, doc §6.2;
		// subtype:"error" is not a fault).
		return nil
	}
	// The FIRST control_response for a request_id resolves the
	// interaction; subsequent ones are ignored (dedup on request_id).
	delete(s.interactions, requestID)
	var allowed bool
	if resp.Subtype == "success" {
		var inner qwenDOControlResponseInner
		_ = json.Unmarshal(resp.Response, &inner)
		allowed = inner.Allowed
	}
	decision := "cancelled"
	if allowed {
		decision = "resolved"
	}
	if !inte.onMachineStream {
		return nil
	}
	return []session.SessionEvent{{
		Type:      session.EventInteractionResolved,
		SessionID: s.sessionID,
		TurnID:    s.machineTurnID,
		Interaction: &session.InteractionEvent{
			NativeInteractionID: requestID,
			Kind:                inte.kind,
			Summary:             inte.summary,
			NativePayload:       inte.payload,
			Resolved:            true,
			Decision:            decision,
		},
	}}
}

// --- wire shapes (doc §3 / §6) ----------------------------------------------

// qwenDOEvent is the top-level Dual Output event envelope (doc §3.1).
// session_id is top-level on every event (the invariant).
type qwenDOEvent struct {
	Type      string          `json:"type"`
	Subtype   string          `json:"subtype"`
	UUID      string          `json:"uuid"`
	SessionID string          `json:"session_id"`
	ParentID  string          `json:"parent_tool_use_id"`
	Data      json.RawMessage `json:"data"`       // system events
	Event     json.RawMessage `json:"event"`      // stream_event inner
	Message   json.RawMessage `json:"message"`    // user / assistant
	RequestID string          `json:"request_id"` // control_request
	Request   json.RawMessage `json:"request"`    // control_request inner
	Response  json.RawMessage `json:"response"`   // control_response inner
}

// qwenDOHandshake is the session_start data object (doc §5.1).
type qwenDOHandshake struct {
	SessionID       string   `json:"session_id"`
	CWD             string   `json:"cwd"`
	ProtocolVersion int      `json:"protocol_version"`
	Version         string   `json:"version"`
	SupportedEvents []string `json:"supported_events"`
}

// qwenDOMessage is the user / assistant message object (doc §3.4).
type qwenDOMessage struct {
	Role    string          `json:"role"`
	Content []qwenDOContent `json:"content"`
	Usage   qwenDOUsage     `json:"usage"`
	Model   string          `json:"model"`
}

// qwenDOContent is one content block. Type is text | tool_use | tool_result
// | thinking | ... — unknown types are opaque (B4).
type qwenDOContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// qwenDOUsage is the per-message usage (doc §3.4).
type qwenDOUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	CacheRead    int `json:"cache_read_input_tokens"`
}

// qwenDOStreamEvent is the stream_event inner object (doc §3.2).
type qwenDOStreamEvent struct {
	Type  string            `json:"type"`
	Delta qwenDOStreamDelta `json:"delta"`
}

// qwenDOStreamDelta is a content_block_delta's delta (doc §3.4).
type qwenDOStreamDelta struct {
	Type string `json:"type"` // text_delta | ...
	Text string `json:"text"`
}

// qwenDOControlRequest is the control_request inner object (doc §6.1).
type qwenDOControlRequest struct {
	Subtype     string          `json:"subtype"` // can_use_tool
	ToolName    string          `json:"tool_name"`
	ToolUseID   string          `json:"tool_use_id"`
	Input       json.RawMessage `json:"input"`
	Suggestions json.RawMessage `json:"permission_suggestions"`
	BlockedPath json.RawMessage `json:"blocked_path"`
}

// qwenDOControlResponse is the control_response inner object (doc §6.2).
type qwenDOControlResponse struct {
	Subtype   string          `json:"subtype"` // success | error
	RequestID string          `json:"request_id"`
	Response  json.RawMessage `json:"response"` // { allowed: bool }
	Error     string          `json:"error"`
}

// qwenDOControlResponseInner is the control_response.response object.
type qwenDOControlResponseInner struct {
	Allowed bool `json:"allowed"`
}
