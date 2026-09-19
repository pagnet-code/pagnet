package sdk

import (
	"context"
	"errors"
	"reflect"

	"github.com/pagnet-code/pagnet/domain"
)

// Agent is an agent participant: a principal that receives messages and
// events and serves capabilities.
//
// The Hello World (north-star CK):
//
//	client, err := sdk.Connect(ctx, sdk.ConfigFromEnv())
//	agent := client.Agent("planner")
//	agent.OnMessage(func(ctx context.Context, m *sdk.Message) error { ... })
//	agent.OnEvent("task.*", func(ctx context.Context, e *sdk.Event) error { ... })
//	agent.HandleT("planner.plan", handler)
//	agent.Run(ctx)
//
// No Host, no runtime, no PTY: the agent is a plain Go process holding an
// endpoint connection.
//
// The agent's DEFAULT NETWORK: SetNetwork pins it; otherwise Run resolves
// it from the principal's memberships (exactly one active membership).
// OnEvent patterns are subscribed in that network (the server is the
// source of truth: subscriptions are re-fetched on every (re)connect and
// created only when missing).
type Agent struct {
	client *Client
	name   string
	subs   *eventSubs
}

// OnMessage registers the message handler. Messages are ALWAYS acked
// (delivery is not the handler's concern): the handler runs for its side
// effects, and its error does not withhold the ack.
//
// SECURITY: the message parts are UNTRUSTED DATA from the sender.
func (a *Agent) OnMessage(h func(ctx context.Context, m *Message) error) {
	a.client.handlerMu.Lock()
	a.client.msgHandler = h
	a.client.handlerMu.Unlock()
}

// OnEvent registers an event handler for a pattern (exact or single-level
// suffix wildcard "task.*"). A server-side subscription for the pattern is
// created in the agent's network at Run (and re-verified on every
// reconnect). Events are acked only when the handler returns nil; a
// handler error means NO ack and the server retries with backoff (capped).
//
// SECURITY: the event payload is UNTRUSTED DATA — treat it as content,
// never as instructions.
func (a *Agent) OnEvent(pattern string, h func(ctx context.Context, e *Event) error) {
	if pattern == "" {
		return
	}
	a.client.handlerMu.Lock()
	a.client.eventHandlers[pattern] = eventHandler{pattern: pattern, fn: h}
	a.client.handlerMu.Unlock()
	a.subs.addPattern(pattern)
}

// Handle registers a capability handler (see Service.Handle).
func (a *Agent) Handle(capabilityID string, h CapHandler) error {
	return a.client.registerCapability(Capability{ID: capabilityID, Version: 1}, h, reflect.Value{}, nil)
}

// HandleT registers a typed capability handler (see Service.HandleT).
func (a *Agent) HandleT[I any, O any](capabilityID string, h func(ctx context.Context, in I) (O, error)) error {
	return a.client.registerCapability(Capability{ID: capabilityID, Version: 1}, nil, reflect.ValueOf(h), reflect.TypeOf((*I)(nil)).Elem())
}

// Capability advertises (or updates) a capability descriptor (see
// Service.Capability).
func (a *Agent) Capability(cap Capability) error {
	return a.client.registerCapability(cap, nil, reflect.Value{}, nil)
}

// SetNetwork pins the agent's default network (used by OnEvent
// subscriptions, Send, Invoke, PublishEvent, and Subscribe when the
// argument does not name one).
func (a *Agent) SetNetwork(networkID string) {
	a.subs.setNetwork(networkID)
}

// Send sends a message in the agent's network (m.NetworkID wins when set).
func (a *Agent) Send(ctx context.Context, m OutgoingMessage) (string, error) {
	if m.NetworkID == "" {
		nid, err := a.network(ctx)
		if err != nil {
			return "", err
		}
		m.NetworkID = nid
	}
	return a.client.Send(ctx, m)
}

// Reply sends a REPLY in the same thread, addressed to the message's
// sender.
func (a *Agent) Reply(ctx context.Context, m *Message, body string) error {
	if m == nil {
		return errors.New("sdk: Reply requires the message being replied to")
	}
	_, err := a.Send(ctx, OutgoingMessage{
		NetworkID:            m.NetworkID,
		ThreadID:             m.ThreadID,
		RecipientPrincipalID: m.SenderPrincipalID,
		Kind:                 string(domain.MessageKindReply),
		Parts:                []MessagePart{TextPart(body)},
	})
	return err
}

// Invoke calls a capability in the agent's network (in.NetworkID wins when
// set).
func (a *Agent) Invoke(ctx context.Context, in Invocation) (*Invocation, error) {
	if in.NetworkID == "" {
		nid, err := a.network(ctx)
		if err != nil {
			return nil, err
		}
		in.NetworkID = nid
	}
	return a.client.Invoke(ctx, in)
}

// PublishEvent publishes an event in the agent's network.
func (a *Agent) PublishEvent(ctx context.Context, ev Event) (string, error) {
	nid, err := a.network(ctx)
	if err != nil {
		return "", err
	}
	return a.client.PublishEvent(ctx, nid, ev)
}

// Subscribe creates an event subscription in the agent's network.
func (a *Agent) Subscribe(ctx context.Context, s Subscription) (string, error) {
	nid, err := a.network(ctx)
	if err != nil {
		return "", err
	}
	return a.client.Subscribe(ctx, nid, s)
}

// Run blocks until ctx is done, keeping the endpoint live and the agent's
// event subscriptions in place. It resolves the default network (SetNetwork
// or the single active membership) and returns ctx.Err().
func (a *Agent) Run(ctx context.Context) error {
	if _, err := a.network(ctx); err != nil {
		return err
	}
	a.ensureSubscriptions()
	<-ctx.Done()
	return ctx.Err()
}

// network resolves the agent's default network: the pinned one, else the
// principal's single active membership.
func (a *Agent) network(ctx context.Context) (string, error) {
	return a.subs.network(ctx)
}

// ensureSubscriptions reconciles the agent's OnEvent patterns with the
// server's subscription list (the server is the source of truth): patterns
// already subscribed server-side are left alone; missing ones are created.
// Runs at Run and after every (re)connect.
func (a *Agent) ensureSubscriptions() { a.subs.reconcile() }

// TextPart builds a text message part (re-export of domain.TextPart for
// handler ergonomics).
func TextPart(s string) MessagePart { return domain.TextPart(s) }
