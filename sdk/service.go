package sdk

import (
	"context"
	"errors"
	"reflect"
)

// Service is a service participant: a principal that advertises
// capabilities and serves their invocations over the endpoint connection.
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

// Serve blocks until ctx is done, keeping the endpoint live (the
// connection, heartbeats, reconnects, and acks are owned by the Client and
// run for its whole lifetime). Serve returns ctx.Err().
func (s *Service) Serve(ctx context.Context) error {
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
