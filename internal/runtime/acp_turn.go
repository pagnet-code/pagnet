package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

func (d *ACPDriver) Submit(ctx context.Context, s *session.RuntimeSession, req session.SubmitRequest, ch chan<- session.SessionEvent) error {
	if err := session.ValidateSubmitRequest(req); err != nil {
		return err
	}
	e := d.get(s.InstanceID)
	if e == nil || !e.live() {
		return session.ErrEndpointGone
	}
	if req.Kind == session.SubmitInteraction {
		return e.resolve(ctx, req)
	}
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return session.ErrBusy
	}
	e.busy = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.busy = false; e.permissions = map[string]acpPermission{}; e.mu.Unlock() }()
	call, err := e.conn.begin(ctx, "session/prompt", map[string]any{"sessionId": e.nativeID, "prompt": []map[string]string{{"type": "text", "text": req.Input}}})
	if err != nil {
		if errors.Is(err, errACPDeliveryUncertain) {
			e.handle.Abort("ACP prompt delivery uncertain")
			return session.ErrTurnInterrupted
		}
		return session.ErrEndpointGone
	}
	defer e.conn.finish(call)
	emit := func(kind, output string, interaction *session.InteractionEvent) bool {
		return acpEmit(ctx, ch, session.SessionEvent{Type: kind, SessionID: e.nativeID, TurnID: req.TurnID, Output: output, Interaction: interaction})
	}
	if !emit(session.EventTurnStarted, "", nil) {
		e.cancel()
		return session.ErrTurnInterrupted
	}
	handleMessage := func(message acpMessage) error {
		if message.Method == "session/update" && len(message.ID) == 0 {
			var update struct {
				SessionID string `json:"sessionId"`
				Update    struct {
					Kind    string                      `json:"sessionUpdate"`
					Content struct{ Type, Text string } `json:"content"`
				} `json:"update"`
			}
			if json.Unmarshal(message.Params, &update) != nil {
				e.handle.Abort("ACP invalid session update")
				return session.ErrTurnInterrupted
			}
			if update.SessionID == e.nativeID && update.Update.Kind == "agent_message_chunk" && update.Update.Content.Type == "text" {
				if !emit(session.EventTurnOutput, update.Update.Content.Text, nil) {
					e.cancel()
					return session.ErrTurnInterrupted
				}
			}
		} else if message.Method == "session/request_permission" && len(message.ID) > 0 {
			interaction, err := e.permission(ctx, message)
			if err != nil {
				e.handle.Abort("ACP invalid permission request")
				return session.ErrTurnInterrupted
			}
			if interaction != nil && !emit(session.EventInteractionStarted, "", interaction) {
				e.cancel()
				return session.ErrTurnInterrupted
			}
		} else if len(message.ID) > 0 {
			if err = e.conn.reject(ctx, message.ID, -32601); err != nil {
				return session.ErrTurnInterrupted
			}
		}
		return nil
	}
	drain := func() error {
		for {
			select {
			case message := <-e.conn.messages:
				if err := handleMessage(message); err != nil {
					return err
				}
			case resolution := <-e.resolutions:
				if !emit(session.EventInteractionResolved, "", resolution) {
					return session.ErrTurnInterrupted
				}
			default:
				return nil
			}
		}
	}

	for {
		select {
		case response := <-call.response:
			if err := drain(); err != nil {
				return err
			}
			if response.Error != nil {
				acpEmit(ctx, ch, session.SessionEvent{Type: session.EventTurnFailed, SessionID: e.nativeID, TurnID: req.TurnID, FailureKind: "runtime_error", Error: response.Error.Error()})
				return nil
			}
			var result struct {
				StopReason string `json:"stopReason"`
			}
			if json.Unmarshal(response.Result, &result) != nil {
				e.handle.Abort("ACP invalid terminal result")
				return session.ErrTurnInterrupted
			}
			if result.StopReason == "end_turn" {
				emit(session.EventTurnCompleted, "", nil)
				return nil
			}
			if result.StopReason == "cancelled" {
				return session.ErrTurnInterrupted
			}
			if result.StopReason != "max_tokens" && result.StopReason != "max_turn_requests" && result.StopReason != "refusal" {
				e.handle.Abort("ACP invalid terminal result")
				return session.ErrTurnInterrupted
			}
			acpEmit(ctx, ch, session.SessionEvent{Type: session.EventTurnFailed, SessionID: e.nativeID, TurnID: req.TurnID, FailureKind: "runtime_error", Error: "Native ACP turn stopped: " + result.StopReason})
			return nil
		case message := <-e.conn.messages:
			if err := handleMessage(message); err != nil {
				return err
			}
		case resolution := <-e.resolutions:
			if !emit(session.EventInteractionResolved, "", resolution) {
				e.cancel()
				return session.ErrTurnInterrupted
			}
		case <-ctx.Done():
			e.cancel()
			return session.ErrTurnInterrupted
		case <-e.conn.done:
			// Prefer an already received terminal response over a subsequent clean EOF.
			select {
			case response := <-call.response:
				if err := drain(); err != nil {
					return err
				}
				var result struct {
					StopReason string `json:"stopReason"`
				}
				if response.Error == nil && json.Unmarshal(response.Result, &result) == nil && result.StopReason == "end_turn" {
					emit(session.EventTurnCompleted, "", nil)
					return nil
				}
			default:
			}
			return session.ErrTurnInterrupted
		}
	}
}
func (e *acpEndpoint) cancel() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Cancellation is a native notification, never a replacement prompt.
	_ = e.conn.notify(ctx, "session/cancel", map[string]string{"sessionId": e.nativeID})
	e.mu.Lock()
	pending := e.permissions
	e.permissions = map[string]acpPermission{}
	e.mu.Unlock()
	for _, p := range pending {
		_ = e.conn.respond(ctx, p.id, map[string]any{"outcome": map[string]string{"outcome": "cancelled"}})
	}
	// A cancelled logical turn must not leave a native turn running invisibly.
	e.conn.close(context.Canceled)
	e.handle.Abort("ACP managed turn cancelled")
}
func (e *acpEndpoint) permission(ctx context.Context, message acpMessage) (*session.InteractionEvent, error) {
	var request struct {
		SessionID string `json:"sessionId"`
		Options   []struct {
			ID   string `json:"optionId"`
			Kind string `json:"kind"`
		} `json:"options"`
	}
	if json.Unmarshal(message.Params, &request) != nil || request.SessionID == "" {
		return nil, errors.New("invalid ACP permission")
	}
	if request.SessionID != e.nativeID {
		return nil, e.conn.respond(ctx, message.ID, map[string]any{"outcome": map[string]string{"outcome": "cancelled"}})
	}
	if len(request.Options) == 0 || len(request.Options) > 64 {
		return nil, errors.New("invalid ACP permission options")
	}
	options := map[string]string{}
	publicOptions := []domain.RuntimeInteractionOption{}
	for _, o := range request.Options {
		if o.ID == "" || len(o.ID) > 1024 || options[o.ID] != "" {
			return nil, errors.New("invalid ACP permission option")
		}
		switch o.Kind {
		case "allow_once", "allow_always", "reject_once", "reject_always":
		default:
			return nil, errors.New("unknown ACP permission option")
		}
		options[o.ID] = o.Kind
		publicOptions = append(publicOptions, domain.RuntimeInteractionOption{ID: o.ID, Kind: o.Kind})
	}
	id := fmt.Sprintf("%s:%x", e.id, sha256.Sum256(message.ID))
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.permissions) >= 64 {
		return nil, errors.New("ACP permission limit exceeded")
	}
	if _, exists := e.permissions[id]; exists {
		return nil, errors.New("duplicate ACP permission")
	}
	e.permissions[id] = acpPermission{id: append(json.RawMessage{}, message.ID...), options: options}
	return &session.InteractionEvent{NativeInteractionID: id, Kind: "permission", Summary: "Native tool approval", Options: publicOptions, NativePayload: append(json.RawMessage{}, message.Params...)}, nil
}
func (e *acpEndpoint) resolve(ctx context.Context, req session.SubmitRequest) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.permissions[req.InteractionID]
	if !ok {
		return errors.New("native ACP permission no longer pending")
	}
	outcome := map[string]string{"outcome": "cancelled"}
	if req.Decision != "cancel" {
		option := req.Answer
		if option == "" {
			option = req.Decision
		}
		if p.options[option] == "" {
			return errors.New("select an explicit native ACP permission optionId")
		}
		outcome = map[string]string{"outcome": "selected", "optionId": option}
	}
	if len(e.resolutions) == cap(e.resolutions) {
		return errors.New("native ACP permission resolution queue full")
	}
	if err := e.conn.respond(ctx, p.id, map[string]any{"outcome": outcome}); err != nil {
		return err
	}
	delete(e.permissions, req.InteractionID)
	decision := "resolved"
	if req.Decision == "cancel" {
		decision = "cancelled"
	} else if p.options[req.Answer] == "reject_once" || p.options[req.Answer] == "reject_always" {
		decision = "declined"
	}
	e.resolutions <- &session.InteractionEvent{NativeInteractionID: req.InteractionID, Kind: "permission", Resolved: true, Decision: decision, Answer: req.Answer}
	return nil
}
