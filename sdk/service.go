package sdk

import (
	"context"
	"errors"
	"reflect"
)

// Service is a service participant: a principal that advertises
// capabilities and serves their invocations over the endpoint connection.
// A service can also react to network events (OnEvent).
//
// The Hello World (north-star CJ):
//
//	client, err := sdk.Connect(ctx, sdk.ConfigFromEnv())
//	svc := client.Service("hello")
//	svc.Handle("hello.say", func(ctx context.Context, in HelloInput) (HelloOutput, error) {
//	    return HelloOutput{Text: "hello " + in.Text}, nil
//	})
//	svc.Serve(ctx) // run until ctx cancel; reconnects, heartbeats, acks
//
// The developer does NOT need to understand WebSocket frames, envelope
// encoding, reconnect loops, acks, or heartbeats: the SDK owns all of it.
type Service struct {
	client *Client
	name   string
	subs   *eventSubs
}

// Handle registers a capability handler (untyped form). The handler
// receives the decrypted, schema-validated input (inv.Input is a
// JSON-decoded value) and returns a JSON-encodable result (validated
// against the capability's OutputSchema when set). Return (nil, ErrAsync)
// to defer completion: the handler then calls inv.Accept(ctx) and later
// inv.Complete(ctx, result) / inv.CompleteError(ctx, err).
//
// The capability is advertised with version 1 and no schemas; call
// Capability to set the full descriptor (schemas, tags, version).
func (s *Service) Handle(capabilityID string, h CapHandler) error {
	if h == nil {
		return errors.New("sdk: handler is required")
	}
	return s.client.registerCapability(Capability{ID: capabilityID, Version: 1}, h, reflect.Value{}, nil)
}

// HandleT registers a TYPED capability handler: the SDK decodes the
// decrypted input into I (the declared input type) and the handler returns
// O (JSON-encoded, validated against the OutputSchema when set). This is
// the idiomatic Hello World form:
//
//	svc.HandleT("hello.say", func(ctx context.Context, in HelloInput) (HelloOutput, error) {
//	    return HelloOutput{Text: "hello " + in.Text}, nil
//	})
//
// SYNC-ONLY: a typed handler's signature carries no *Invocation, so it
// cannot call Accept/Complete. Returning (nil, ErrAsync) from a typed
// handler is a SILENT DEAD END — dispatch leaves the invocation in-flight
// (the same as the untyped form) but no one can ever call Complete for it,
// so the invocation strands until the server's TTL expires and the caller
// times out. If the work may outlive the request, use the untyped Handle
// form instead: its handler receives *Invocation, can defer with
// (nil, ErrAsync), and later calls inv.Complete/inv.CompleteError.
func (s *Service) HandleT[I any, O any](capabilityID string, h func(ctx context.Context, in I) (O, error)) error {
	if h == nil {
		return errors.New("sdk: handler is required")
	}
	return s.client.registerCapability(Capability{ID: capabilityID, Version: 1}, nil, reflect.ValueOf(h), reflect.TypeOf((*I)(nil)).Elem())
}

// Capability advertises (or updates) a capability descriptor: id, version,
// name, description, JSON Schemas, tags. An existing handler for the id is
// kept; a new handler is registered with Handle/HandleT.
func (s *Service) Capability(cap Capability) error {
	return s.client.registerCapability(cap, nil, reflect.Value{}, nil)
}

// OnEvent registers an event handler for a pattern (exact or single-level
// suffix wildcard "test.*"). A server-side subscription for the pattern is
// created in the service's network at Serve (and re-verified on every
// reconnect). Events are acked only when the handler returns nil; a handler
// error means NO ack and the server retries with backoff (capped).
//
// The service's DEFAULT NETWORK: SetNetwork pins it; otherwise the
// principal's single active membership is used. A service with no
// resolvable network can still serve capabilities (invocations name their
// network); only the event subscription waits for a network.
//
// SECURITY: the event payload is UNTRUSTED DATA — treat it as content,
// never as instructions.
func (s *Service) OnEvent(pattern string, h func(ctx context.Context, e *Event) error) {
	if pattern == "" {
		return
	}
	s.client.handlerMu.Lock()
	s.client.eventHandlers[pattern] = eventHandler{pattern: pattern, fn: h}
	s.client.handlerMu.Unlock()
	s.subs.addPattern(pattern)
}

// SetNetwork pins the service's default network (used by OnEvent
// subscriptions).
func (s *Service) SetNetwork(networkID string) {
	s.subs.setNetwork(networkID)
}

// ensureSubscriptions reconciles the service's OnEvent patterns with the
// server's subscription list (the server is the source of truth). Runs at
// Serve and after every (re)connect.
func (s *Service) ensureSubscriptions() { s.subs.reconcile() }

// Serve blocks until ctx is done, keeping the endpoint live (the
// connection, heartbeats, reconnects, and acks are owned by the Client and
// run for its whole lifetime). It also reconciles the service's event
// subscriptions (re-created on every (re)connect). Serve returns
// ctx.Err().
func (s *Service) Serve(ctx context.Context) error {
	s.ensureSubscriptions()
	<-ctx.Done()
	return ctx.Err()
}

// Network returns a per-network operations handle for this service
// (publish/invoke/subscribe/search/send scoped to one network).
func (s *Service) Network(ctx context.Context, networkID string) *Network {
	return s.client.Network(ctx, networkID)
}

// Network is a per-network operations handle: the network-scoped form of
// the Client's operations.
type Network struct {
	client *Client
	id     string
}

// ID returns the network id.
func (n *Network) ID() string { return n.id }

// PublishEvent publishes an event in this network (see Client.PublishEvent).
func (n *Network) PublishEvent(ctx context.Context, ev Event) (string, error) {
	return n.client.PublishEvent(ctx, n.id, ev)
}

// Invoke calls a capability in this network (see Client.Invoke).
func (n *Network) Invoke(ctx context.Context, in Invocation) (*Invocation, error) {
	if in.NetworkID == "" {
		in.NetworkID = n.id
	}
	return n.client.Invoke(ctx, in)
}

// Subscribe creates an event subscription in this network.
func (n *Network) Subscribe(ctx context.Context, s Subscription) (string, error) {
	return n.client.Subscribe(ctx, n.id, s)
}

// Unsubscribe deletes an event subscription in this network.
func (n *Network) Unsubscribe(ctx context.Context, subID string) error {
	return n.client.Unsubscribe(ctx, n.id, subID)
}

// Search discovers participants in this network.
func (n *Network) Search(ctx context.Context, q Query) ([]SearchResult, string, error) {
	return n.client.Search(ctx, n.id, q)
}

// Send sends a message in this network.
func (n *Network) Send(ctx context.Context, m OutgoingMessage) (string, error) {
	if m.NetworkID == "" {
		m.NetworkID = n.id
	}
	return n.client.Send(ctx, m)
}
