package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/internal/session"
	"time"
)

// Capture in the single native protocol reader BEFORE managed queue filtering.
// This includes session-scoped idle updates. A logical managed turn is attached
// only during that owned prompt; no native ordinal or TUI event is fabricated.
func (e *acpEndpoint) captureNativeMessage(message *acpMessage) error {
	e.resolutionGate.RLock()
	defer e.resolutionGate.RUnlock()
	if e.retired {
		return session.ErrEndpointGone
	}
	e.mu.Lock()
	native, turn := e.nativeID, e.turn
	e.mu.Unlock()
	if native == "" {
		return nil
	}
	var events []session.SessionEvent
	if message.Method == "session/update" && len(message.ID) == 0 {
		var data struct {
			SessionID string `json:"sessionId"`
			Update    struct {
				Kind    string                      `json:"sessionUpdate"`
				Content struct{ Type, Text string } `json:"content"`
				ToolID  string                      `json:"toolCallId"`
				Status  string                      `json:"status"`
			} `json:"update"`
		}
		if json.Unmarshal(message.Params, &data) != nil {
			return errors.New("ACP invalid native update")
		}
		if data.SessionID != native {
			return nil
		}
		if data.Update.Kind == "tool_call" || data.Update.Kind == "tool_call_update" {
			if data.Update.ToolID == "" || len(data.Update.ToolID) > 512 {
				return errors.New("ACP invalid native tool identity")
			}
			e.mu.Lock()
			if data.Update.Status == "completed" || data.Update.Status == "failed" {
				delete(e.tools, data.Update.ToolID)
			} else {
				if len(e.tools) >= 64 && !e.tools[data.Update.ToolID] {
					e.mu.Unlock()
					return errors.New("ACP native tool bound exceeded")
				}
				e.tools[data.Update.ToolID] = true
			}
			busy := e.busy || len(e.tools) > 0 || len(e.permissions) > 0
			e.mu.Unlock()
			kind := session.EventBusy
			if !busy {
				kind = session.EventIdle
			}
			events = append(events, session.SessionEvent{Type: kind})
		}
		if data.Update.Kind == "agent_message_chunk" && data.Update.Content.Type == "text" {
			events = append(events, session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, Output: data.Update.Content.Text})
		}
		if data.Update.Kind == "plan" && len(message.Params) <= session.MaxPlanBytes {
			var bounded struct {
				Update struct {
					Entries []struct{ Content, Status, Priority string } `json:"entries"`
				} `json:"update"`
			}
			if json.Unmarshal(message.Params, &bounded) != nil || bounded.Update.Entries == nil {
				return nil
			}
			plan := &session.PlanSnapshot{Source: e.planSource, Entries: []session.PlanEntry{}}
			for _, entry := range bounded.Update.Entries {
				plan.Entries = append(plan.Entries, session.PlanEntry{Text: entry.Content, Status: entry.Status, Priority: entry.Priority})
			}
			if session.ValidatePlan(plan) == nil {
				events = append(events, session.SessionEvent{Type: session.EventPlanUpdated, Plan: plan})
			}
		}
	} else if message.Method == "session/request_permission" && len(message.ID) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		interaction, err := e.permission(ctx, *message)
		if err != nil {
			return err
		}
		message.nativePermission = interaction
		if interaction != nil {
			events = append(events, session.SessionEvent{Type: session.EventInteractionStarted, Interaction: interaction})
		}
	} else if message.Method == "" && message.replyMethod == "session/prompt" && turn != "" {
		if message.Error != nil {
			events = append(events, session.SessionEvent{Type: session.EventTurnFailed, FailureKind: "runtime_error", Error: message.Error.Error()})
		} else {
			var result struct {
				StopReason string `json:"stopReason"`
			}
			if json.Unmarshal(message.Result, &result) != nil {
				return errors.New("ACP invalid native terminal result")
			}
			switch result.StopReason {
			case "end_turn":
				events = append(events, session.SessionEvent{Type: session.EventTurnCompleted})
			case "cancelled":
				return nil
			case "max_tokens", "max_turn_requests", "refusal":
				events = append(events, session.SessionEvent{Type: session.EventTurnFailed, FailureKind: "runtime_error", Error: "Native ACP turn stopped: " + result.StopReason})
			default:
				return errors.New("ACP invalid native terminal reason")
			}
		}
	}
	if e.observer == nil {
		return nil
	}
	observe := e.observer
	if e.nativeBatcher != nil {
		observe = e.nativeBatcher.push
	}
	for _, event := range events {
		event.SessionID = native
		event.TurnID = turn
		e.mu.Lock()
		first := turn != "" && !e.observedStart
		e.observedStart = e.observedStart || first
		e.mu.Unlock()
		if first {
			if err := observe(session.SessionEvent{Type: session.EventTurnStarted, SessionID: native, TurnID: turn}); err != nil {
				return err
			}
		}
		if err := observe(event); err != nil {
			return err
		}
	}
	return nil
}
