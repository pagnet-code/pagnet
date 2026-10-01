package runtime

// Codex app-server event-stream state machine (runtime-lifecycle
// rework, Wave 4).
//
// codexTurnState is the per-endpoint turn/interaction state machine for
// the Codex app-server JSON-RPC stream (`codex app-server --stdio`). It
// is driven by the endpoint's reader loop (one JSON-RPC message at a
// time) and is directly testable: the fixture harness feeds scripted
// notifications / server requests and asserts the normalized
// session.SessionEvent stream (no model needed, CI-safe).
//
// The wire is JSON-RPC 2.0 over stdio (one object per line). Three
// message classes reach the state machine:
//
//   - NOTIFICATIONS (server → client, no id): the turn's streaming
//     events. turn/started (the turn-accepted signal),
//     item/agentMessage/delta (assistant text deltas), item/started /
//     item/completed (tool-call lifecycle: commandExecution, fileChange,
//     mcpToolCall, ...), thread/tokenUsage/updated (per-turn usage), and
//     turn/completed (the TERMINAL event: turn.status is completed /
//     failed / interrupted).
//   - SERVER REQUESTS (server → client, WITH id): the runtime's native
//     interactions — approval and input requests the client must answer
//     (item/commandExecution/requestApproval, item/fileChange/
//     requestApproval, item/permissions/requestApproval, item/tool/
//     requestUserInput, mcpServer/elicitation/request, openai/form).
//     They are surfaced as generic interaction.started events; pagnet
//     NEVER auto-approves (the resolution travels back as the JSON-RPC
//     response when the daemon resolves the interaction).
//   - RESPONSES (server → client, with id, matching a client request):
//     correlated by the driver (initialize, thread/start, thread/resume,
//     turn/start) — not routed through this state machine, except that a
//     successful turn/start response marks the turn accepted.
//
// Turn boundaries: a machine turn begins at the turn/started notification
// (or the turn/start response — whichever the reader observes first) and
// ends at the turn/completed notification. There is no separate
// "message done" event: turn/completed IS the terminal event, and its
// turn.status decides the outcome (completed → turn.completed, failed →
// turn.failed with the classified error, interrupted → turn.failed
// kind=interrupted).
//
// Concurrency: the state machine is owned by one endpoint.
// processNotification / processServerRequest are called from the
// endpoint's reader goroutine; beginMachineTurn / clearMachineTurn /
// markTurnAccepted / resolveInteraction are called from the driver's
// Submit path. All access is under s.mu.

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// codexTurnState is the per-endpoint turn/interaction state machine.
type codexTurnState struct {
	mu sync.Mutex

	// session (from thread/start or thread/resume — the driver calls
	// setThread with the response's thread).
	threadID  string
	model     string
	activated bool
	resuming  bool
	resumeID  string

	// turn
	turnActive    bool
	materialised  bool
	turnIsMachine bool
	nativeActive  bool // thread/status/changed positive activity, independent of machine turn
	machineTurnID string
	nativeTurnID  string // the codex turn id (from turn/started)
	turnAccepted  bool   // the acceptance signal (turn/started or turn/start response)

	// per-turn usage (from thread/tokenUsage/updated; "last" is the
	// per-turn breakdown, "total" is the thread cumulative — the turn
	// event carries the per-turn numbers).
	inInput, inOutput, inCached int

	// interactions: JSON-RPC request id (the native interaction id) →
	// info; dedup on the request id (a server request is answered once).
	interactions map[string]*codexInteraction
}

// codexInteraction is one observed native interaction (a server request)
// awaiting (or having had) a resolution.
type codexInteraction struct {
	rpcID           string
	method          string // the server request method (drives the response shape)
	kind            string // question | permission
	summary         string
	payload         json.RawMessage
	onMachineStream bool // the started event was emitted on the machine stream
}

func newCodexTurnState(resuming bool, resumeID string) *codexTurnState {
	return &codexTurnState{
		resuming:     resuming,
		resumeID:     resumeID,
		interactions: map[string]*codexInteraction{},
	}
}

// setThread records the thread identity from a successful thread/start or
// thread/resume response and emits the activation event. A resume that
// re-bases onto a different thread is a lost session, never a silent
// fresh one (the invariant the whole persistent model rests on).
func (s *codexTurnState) setThread(threadID, model string) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if threadID == "" {
		return []session.SessionEvent{{
			Type:  session.EventSessionLost,
			Error: "codex thread start/resume returned no thread id",
		}}
	}
	if s.resuming && s.resumeID != "" && threadID != s.resumeID {
		return []session.SessionEvent{{
			Type:      session.EventSessionLost,
			SessionID: s.resumeID,
			Error:     fmt.Sprintf("codex resume started a different thread (wanted %s, got %s)", s.resumeID, threadID),
		}}
	}
	s.threadID = threadID
	s.model = model
	s.activated = true
	if s.resuming {
		return []session.SessionEvent{{
			Type:      session.EventSessionResumed,
			SessionID: threadID,
		}}
	}
	return []session.SessionEvent{{
		Type:      session.EventSessionStarted,
		SessionID: threadID,
	}}
}

// beginMachineTurn registers the in-flight machine turn (its logical id).
// Called by the driver's Submit before sending turn/start.
func (s *codexTurnState) beginMachineTurn(turnID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.machineTurnID = turnID
	s.nativeTurnID = ""
	s.turnAccepted = false
	s.inInput, s.inOutput, s.inCached = 0, 0, 0
}

// clearMachineTurn clears the in-flight machine turn (on a submit
// failure or ctx cancel). It does not touch the turn-active state (the
// reader's terminal-event path ends the turn).
func (s *codexTurnState) clearMachineTurn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.machineTurnID = ""
	s.nativeTurnID = ""
	s.turnAccepted = false
	s.inInput, s.inOutput, s.inCached = 0, 0, 0
}

// markTurnAccepted records the turn/start response as the acceptance
// signal: from this moment the runtime is working on the submit, so a
// mid-turn endpoint death is an INTERRUPTION (partially applied outcome),
// not an unaccepted endpoint death. The turn/started notification also
// sets it (whichever arrives first wins; both are acceptance).
func (s *codexTurnState) markTurnAccepted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.turnAccepted = true
}

// --- accessors (for the driver and the fixture tests) -----------------------

func (s *codexTurnState) nativeThreadID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.threadID
}

func (s *codexTurnState) nativeModel() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model
}

func (s *codexTurnState) isActivated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activated
}

// isTurnAccepted reports whether the runtime accepted the in-flight
// machine turn (the crash-contract classifier: accepted →
// ErrTurnInterrupted, not accepted → ErrEndpointGone).
func (s *codexTurnState) isTurnAccepted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turnAccepted
}

// --- notifications ------------------------------------------------------------

// processNotification handles one server notification and returns the
// normalized events to emit (in order). It mutates the state.
func (s *codexTurnState) processNotification(method string, params json.RawMessage) []session.SessionEvent {
	switch method {
	case "thread/status/changed":
		var p struct {
			ThreadID string `json:"threadId"`
			Status   struct {
				Type string `json:"type"`
			} `json:"status"`
		}
		if json.Unmarshal(params, &p) != nil {
			return nil
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if p.ThreadID == "" || p.ThreadID != s.threadID {
			return nil
		}
		switch p.Status.Type {
		case "active":
			s.nativeActive = true
		case "idle", "notLoaded":
			s.nativeActive = false
		}
		return nil
	case "turn/plan/updated":
		if len(params) > session.MaxPlanBytes {
			return nil
		}
		var p struct {
			TurnID string `json:"turnId"`
			Plan   []struct {
				Step   string `json:"step"`
				Status string `json:"status"`
			} `json:"plan"`
		}
		if json.Unmarshal(params, &p) != nil || p.Plan == nil {
			return nil
		}
		plan := &session.PlanSnapshot{Source: "codex", NativeTurnID: p.TurnID, Entries: make([]session.PlanEntry, 0, len(p.Plan))}
		for _, entry := range p.Plan {
			status := entry.Status
			if status == "inProgress" {
				status = "in_progress"
			}
			plan.Entries = append(plan.Entries, session.PlanEntry{Text: entry.Step, Status: status})
		}
		if session.ValidatePlan(plan) != nil {
			return nil
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.activated || !s.turnActive || !s.turnIsMachine || s.machineTurnID == "" || s.nativeTurnID == "" || p.TurnID != s.nativeTurnID {
			return nil
		}
		return []session.SessionEvent{{Type: session.EventPlanUpdated, SessionID: s.threadID, TurnID: s.machineTurnID, Plan: plan}}
	case "turn/started":
		var p struct {
			ThreadID string    `json:"threadId"`
			Turn     codexTurn `json:"turn"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processTurnStarted(p.ThreadID, p.Turn)
	case "turn/completed":
		var p struct {
			ThreadID string    `json:"threadId"`
			Turn     codexTurn `json:"turn"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processTurnCompleted(p.ThreadID, p.Turn)
	case "item/agentMessage/delta":
		var p struct {
			TurnID string `json:"turnId"`
			Delta  string `json:"delta"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processAgentMessageDelta(p.TurnID, p.Delta)
	case "item/started":
		var p struct {
			TurnID string    `json:"turnId"`
			Item   codexItem `json:"item"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processItemEvent(p.TurnID, p.Item, true)
	case "item/completed":
		var p struct {
			TurnID string    `json:"turnId"`
			Item   codexItem `json:"item"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processItemEvent(p.TurnID, p.Item, false)
	case "thread/tokenUsage/updated":
		var p struct {
			TurnID     string             `json:"turnId"`
			TokenUsage codexTokenUsageAgg `json:"tokenUsage"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil
		}
		return s.processTokenUsage(p.TurnID, p.TokenUsage)
	default:
		// Unknown notification: forward-compatible noise. Ignore.
		return nil
	}
}

// processTurnStarted handles the turn-accepted signal. A machine turn
// begins here (EventTurnStarted on the machine stream); a turn with no
// registered machine submit (an external/human turn) is not part of the
// machine stream.
func (s *codexTurnState) processTurnStarted(threadID string, turn codexTurn) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.activated || (threadID != "" && threadID != s.threadID) {
		return nil // a different thread's turn: not ours
	}
	s.turnAccepted = true
	if s.machineTurnID == "" {
		// Human/external work must still protect the endpoint from hibernation.
		s.turnActive = true
		s.turnIsMachine = false
		s.nativeTurnID = turn.ID
		return nil
	}
	s.turnActive = true
	s.turnIsMachine = true
	s.nativeTurnID = turn.ID
	return []session.SessionEvent{{
		Type:      session.EventTurnStarted,
		SessionID: s.threadID,
		TurnID:    s.machineTurnID,
	}}
}

// processAgentMessageDelta handles an assistant text delta (a transcript
// chunk on the machine stream).
func (s *codexTurnState) processAgentMessageDelta(turnID, delta string) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.turnActive || !s.turnIsMachine || delta == "" {
		return nil
	}
	if turnID != "" && s.nativeTurnID != "" && turnID != s.nativeTurnID {
		return nil // a different turn's delta: not ours
	}
	return []session.SessionEvent{{
		Type:      session.EventTurnOutput,
		SessionID: s.threadID,
		TurnID:    s.machineTurnID,
		Output:    delta,
	}}
}

// processItemEvent handles the tool-call lifecycle (item/started /
// item/completed). Tool calls are surfaced as visible notes on the
// machine stream (the console renders progress); agentMessage items
// carry no note (the deltas already streamed the text).
func (s *codexTurnState) processItemEvent(turnID string, item codexItem, started bool) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.turnActive || !s.turnIsMachine {
		return nil
	}
	if turnID != "" && s.nativeTurnID != "" && turnID != s.nativeTurnID {
		return nil
	}
	var note string
	switch item.Type {
	case "commandExecution":
		switch {
		case started:
			note = "[codex] command: " + item.Command
		case item.Status == "failed" || (item.ExitCode != nil && *item.ExitCode != 0):
			note = "[codex] command failed: " + item.Command
		default:
			note = "[codex] command completed: " + item.Command
		}
	case "fileChange":
		if started {
			note = "[codex] file change in progress"
		} else {
			note = "[codex] file change applied"
		}
	case "mcpToolCall":
		name := item.Server + "." + item.Tool
		if started {
			note = "[codex] mcp tool: " + name
		} else if item.Status == "failed" {
			note = "[codex] mcp tool failed: " + name
		} else {
			note = "[codex] mcp tool completed: " + name
		}
	default:
		// agentMessage / reasoning / plan / ...: no note (the deltas
		// carry the text; the rest is opaque).
		return nil
	}
	if note == "" {
		return nil
	}
	return []session.SessionEvent{{
		Type:      session.EventTurnOutput,
		SessionID: s.threadID,
		TurnID:    s.machineTurnID,
		Output:    note,
	}}
}

// processTokenUsage accumulates the per-turn usage (the "last"
// breakdown is the current turn's; "total" is the thread cumulative and
// is not the turn's).
func (s *codexTurnState) processTokenUsage(turnID string, agg codexTokenUsageAgg) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.turnActive || !s.turnIsMachine {
		return nil
	}
	if turnID != "" && s.nativeTurnID != "" && turnID != s.nativeTurnID {
		return nil
	}
	u := agg.Last
	s.inInput += int(u.InputTokens)
	s.inOutput += int(u.OutputTokens)
	s.inCached += int(u.CachedInputTokens)
	return nil
}

// processTurnCompleted handles the TERMINAL turn event. turn.status
// decides the outcome:
//
//   - completed → turn.completed (with the accumulated usage + model).
//   - failed → turn.failed (the error is classified: codexErrorInfo
//     carries the machine error code, the message the text).
//   - interrupted → turn.failed kind=interrupted (the turn was cut off
//     — e.g. an approval "cancel" — without completing).
func (s *codexTurnState) processTurnCompleted(threadID string, turn codexTurn) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if threadID != "" && s.threadID != "" && threadID != s.threadID {
		return nil
	}
	if !s.turnActive {
		return nil
	}
	if s.nativeTurnID != "" && turn.ID != "" && turn.ID != s.nativeTurnID {
		return nil
	}
	s.materialised = true
	if !s.turnIsMachine {
		s.endTurnLocked()
		return nil
	}
	turnID := s.machineTurnID
	sid := s.threadID
	model := s.model
	in, out, cached := s.inInput, s.inOutput, s.inCached
	s.endTurnLocked()
	switch turn.Status {
	case "completed":
		return []session.SessionEvent{{
			Type:         session.EventTurnCompleted,
			SessionID:    sid,
			TurnID:       turnID,
			Model:        model,
			InputTokens:  intPtr(in),
			OutputTokens: intPtr(out),
			CachedTokens: intPtr(cached),
		}}
	case "failed":
		msg := "codex turn failed"
		var kind domain.RuntimeFailureKind = domain.RuntimeFailureUnknown
		var retryAt *string
		if turn.Error != nil {
			if turn.Error.Message != "" {
				msg = turn.Error.Message
			}
			kind, retryAt = classifyCodexError(turn.Error)
		}
		return []session.SessionEvent{{
			Type:        session.EventTurnFailed,
			SessionID:   sid,
			TurnID:      turnID,
			FailureKind: string(kind),
			Error:       trunc(msg),
			RetryAt:     retryAt,
		}}
	case "interrupted":
		return []session.SessionEvent{{
			Type:        session.EventTurnFailed,
			SessionID:   sid,
			TurnID:      turnID,
			FailureKind: string(domain.RuntimeFailureInterrupted),
			Error:       "codex turn interrupted",
		}}
	default:
		// Unknown status: forward-compatible, but a turn that ended
		// without "completed" must not be reported as a completion.
		return []session.SessionEvent{{
			Type:        session.EventTurnFailed,
			SessionID:   sid,
			TurnID:      turnID,
			FailureKind: string(domain.RuntimeFailureUnknown),
			Error:       "codex turn ended with unknown status " + turn.Status,
		}}
	}
}

// endTurnLocked resets the in-flight turn state (the caller holds s.mu).
func (s *codexTurnState) endTurnLocked() {
	s.turnActive = false
	s.turnIsMachine = false
	s.machineTurnID = ""
	s.nativeTurnID = ""
	s.turnAccepted = false
	s.inInput, s.inOutput, s.inCached = 0, 0, 0
}

// classifyCodexError maps a turn error to a failure kind. The
// codexErrorInfo machine code is the authoritative classifier (rate
// limits, auth, context window, ...); the message text is the fallback
// (the generic provider classifier).
func classifyCodexError(err *codexTurnError) (domain.RuntimeFailureKind, *string) {
	if err == nil {
		return domain.RuntimeFailureUnknown, nil
	}
	if len(err.CodexErrorInfo) > 0 {
		var code string
		if json.Unmarshal(err.CodexErrorInfo, &code) == nil {
			switch code {
			case "rateLimitExceeded", "usageLimitExceeded", "serverOverloaded":
				return domain.RuntimeFailureRateLimited, nil
			case "unauthorized":
				return domain.RuntimeFailureAuthRequired, nil
			case "contextWindowExceeded":
				return domain.RuntimeFailureContextLimit, nil
			}
		}
	}
	return ClassifyProviderError(err.Message)
}

// --- server requests (interactions) ------------------------------------------

// processServerRequest handles one server-initiated request (a native
// interaction). It records the interaction (dedup on the request id) and
// emits interaction.started on the machine stream. pagnet NEVER
// auto-approves: the request stays pending until the daemon resolves it
// (resolveInteraction sends the JSON-RPC response).
func (s *codexTurnState) processServerRequest(rpcID, method string, params json.RawMessage) []session.SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rpcID == "" {
		return nil
	}
	// Dedup: a request id is answered once.
	if _, ok := s.interactions[rpcID]; ok {
		return nil
	}
	kind, summary := classifyCodexServerRequest(method, params)
	onMachineStream := s.turnActive && s.turnIsMachine
	s.interactions[rpcID] = &codexInteraction{
		rpcID:           rpcID,
		method:          method,
		kind:            kind,
		summary:         summary,
		payload:         params,
		onMachineStream: onMachineStream,
	}
	if !onMachineStream {
		// A request outside a machine turn (an external turn): record it
		// (so the resolution is observed) but emit no started event.
		return nil
	}
	return []session.SessionEvent{{
		Type:      session.EventInteractionStarted,
		SessionID: s.threadID,
		TurnID:    s.machineTurnID,
		Interaction: &session.InteractionEvent{
			NativeInteractionID: rpcID,
			Options:             codexApprovalOptions(method, params),
			Kind:                kind,
			Summary:             summary,
			NativePayload:       params,
			Resolved:            false,
		},
	}}
}

// classifyCodexServerRequest maps a server request method to the
// generic interaction kind + a public-safe summary.
func classifyCodexServerRequest(method string, params json.RawMessage) (string, string) {
	switch method {
	case "item/commandExecution/requestApproval", "item/fileChange/requestApproval", "item/permissions/requestApproval":
		return "permission", "Native tool approval"
	case "item/tool/requestUserInput", "mcpServer/elicitation/request", "openai/form":
		return "question", "Native input request"
	default:
		return "other", "Native interaction"
	}
}

// Only documented string decisions are supported. An explicit vendor list is
// an allowlist; unknown policy-amendment objects cannot widen it.
func codexApprovalOptions(method string, params json.RawMessage) []domain.RuntimeInteractionOption {
	if method != "item/commandExecution/requestApproval" && method != "item/fileChange/requestApproval" {
		return nil
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(params, &request) != nil {
		return nil
	}
	decisions := []string{"accept", "acceptForSession", "decline", "cancel"}
	if raw, exists := request["availableDecisions"]; exists {
		var entries []json.RawMessage
		if json.Unmarshal(raw, &entries) != nil {
			return nil
		}
		decisions = nil
		for _, entry := range entries {
			var decision string
			if json.Unmarshal(entry, &decision) == nil {
				decisions = append(decisions, decision)
			}
		}
	}
	out := []domain.RuntimeInteractionOption{}
	seen := map[string]bool{}
	for _, decision := range decisions {
		if seen[decision] {
			continue
		}
		seen[decision] = true
		kind := ""
		switch decision {
		case "accept":
			kind = "allow_once"
		case "acceptForSession":
			kind = "allow_always"
		case "decline", "cancel":
			kind = "reject_once"
		}
		if kind != "" {
			out = append(out, domain.RuntimeInteractionOption{ID: decision, Kind: kind})
		}
	}
	return out
}

// resolveInteraction builds the JSON-RPC response for a pending server
// request and returns the interaction.resolved event. decision is the
// daemon's resolution outcome (resolved | declined | cancelled); answer
// is the (opaque) answer for question kinds. found=false when the
// interaction is unknown or already resolved (dedup) — nothing to
// answer. result is nil when the decision cannot be expressed for the
// request kind (the caller answers with a JSON-RPC error — never a
// guessed approval); the resolved event is still emitted (the daemon's
// decision is observed on the stream either way).
func (s *codexTurnState) resolveInteraction(rpcID, decision, answer string) (result json.RawMessage, ev []session.SessionEvent, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inte, ok := s.interactions[rpcID]
	if !ok {
		return nil, nil, false
	}
	res := s.buildInteractionResponseLocked(inte, decision, answer)
	if res == nil && (inte.method == "item/commandExecution/requestApproval" || inte.method == "item/fileChange/requestApproval") {
		return nil, nil, false
	}
	// The first valid choice wins. Invalid input must not consume the prompt.
	delete(s.interactions, rpcID)
	if answer == "decline" {
		decision = "declined"
	}
	if answer == "cancel" {
		decision = "cancelled"
	}
	return res, s.resolvedEventsLocked(inte, decision), true
}

// resolvedEventsLocked builds the interaction.resolved event (the caller
// holds s.mu).
func (s *codexTurnState) resolvedEventsLocked(inte *codexInteraction, decision string) []session.SessionEvent {
	if !inte.onMachineStream {
		return nil
	}
	return []session.SessionEvent{{
		Type:      session.EventInteractionResolved,
		SessionID: s.threadID,
		TurnID:    s.machineTurnID,
		Interaction: &session.InteractionEvent{
			NativeInteractionID: inte.rpcID,
			Kind:                inte.kind,
			Summary:             inte.summary,
			NativePayload:       inte.payload,
			Resolved:            true,
			Decision:            decision,
		},
	}}
}

// buildInteractionResponseLocked maps the daemon's generic decision to
// the protocol response for the request kind (the caller holds s.mu).
// It returns nil when the decision cannot be expressed (the caller
// answers with a JSON-RPC error). The mapping is deliberately
// conservative: "resolved" maps to the narrowest approval (accept for
// this instance only — never acceptForSession, never a persistent
// policy amendment), and "declined" / "cancelled" map to the protocol's
// refusal.
func (s *codexTurnState) buildInteractionResponseLocked(inte *codexInteraction, decision, answer string) json.RawMessage {
	switch inte.method {
	case "item/commandExecution/requestApproval", "item/fileChange/requestApproval":
		selected := answer
		if selected == "" {
			switch decision {
			case "resolved":
				selected = "accept"
			case "declined":
				selected = "decline"
			case "cancelled":
				selected = "cancel"
			}
		}
		for _, option := range codexApprovalOptions(inte.method, inte.payload) {
			if option.ID == selected {
				raw, _ := json.Marshal(map[string]string{"decision": selected})
				return raw
			}
		}
		return nil
	case "item/permissions/requestApproval":
		// Granting: an empty profile with turn scope — the narrowest
		// expressible grant (the requested extra permissions are NOT
		// widened; the turn proceeds with what it already has).
		// Refusing: the same empty grant (no extra permissions).
		return json.RawMessage(`{"permissions":{},"scope":"turn"}`)
	case "item/tool/requestUserInput":
		if decision != "resolved" || answer == "" {
			// A refused or empty answer cannot be expressed as an
			// answer: the caller answers with a JSON-RPC error.
			return nil
		}
		// The answer is opaque (the daemon's generic answer string). Map
		// it onto the request's questions: every question gets the answer
		// (the single-answer generic model; the questions the summary
		// surfaced are the request's own).
		var p struct {
			Questions []struct {
				ID string `json:"id"`
			} `json:"questions"`
		}
		if err := json.Unmarshal(inte.payload, &p); err != nil || len(p.Questions) == 0 {
			return nil
		}
		answers := map[string]any{}
		for _, q := range p.Questions {
			answers[q.ID] = map[string]any{"answers": []string{answer}}
		}
		b, err := json.Marshal(map[string]any{"answers": answers})
		if err != nil {
			return nil
		}
		return b
	case "mcpServer/elicitation/request", "openai/form":
		switch decision {
		case "resolved":
			return json.RawMessage(`{"action":"accept"}`)
		case "cancelled":
			return json.RawMessage(`{"action":"cancel"}`)
		case "declined":
			return json.RawMessage(`{"action":"decline"}`)
		}
	}
	return nil
}

// --- wire shapes ---------------------------------------------------------------

// codexTurn is the Turn object (turn/started, turn/completed, the
// turn/start response).
type codexTurn struct {
	ID     string          `json:"id"`
	Status string          `json:"status"`
	Error  *codexTurnError `json:"error"`
}

// codexTurnError is the Turn's error (status=failed). codexErrorInfo is
// a JSON string enum in the protocol (rateLimitExceeded, unauthorized,
// ...; an object for the http-failure variants) — kept raw and
// classified in classifyCodexError.
type codexTurnError struct {
	Message        string          `json:"message"`
	CodexErrorInfo json.RawMessage `json:"codexErrorInfo"`
}

// codexTokenUsageAgg is the thread/tokenUsage/updated payload's
// tokenUsage object ("last" = the current turn's breakdown, "total" =
// the thread cumulative).
type codexTokenUsageAgg struct {
	Last  codexTokenUsage `json:"last"`
	Total codexTokenUsage `json:"total"`
}

// codexTokenUsage is one token-usage breakdown.
type codexTokenUsage struct {
	CachedInputTokens     int64 `json:"cachedInputTokens"`
	InputTokens           int64 `json:"inputTokens"`
	OutputTokens          int64 `json:"outputTokens"`
	ReasoningOutputTokens int64 `json:"reasoningOutputTokens"`
}

// codexItem is one ThreadItem (item/started, item/completed). Only the
// fields the event mapper reads are decoded; the rest is opaque.
type codexItem struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Command  string `json:"command"`
	Server   string `json:"server"`
	Tool     string `json:"tool"`
	Status   string `json:"status"`
	ExitCode *int   `json:"exitCode"`
}

// codexThreadStartResponse is the thread/start / thread/resume response.
type codexThreadStartResponse struct {
	Thread struct {
		ID    string `json:"id"`
		Model string `json:"model"`
	} `json:"thread"`
}

// codexTurnStartResponse is the turn/start response.
type codexTurnStartResponse struct {
	Turn codexTurn `json:"turn"`
}

func (s *codexTurnState) activeWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.turnActive || s.nativeActive || len(s.interactions) > 0
}
