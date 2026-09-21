package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

// Capability is a pagnet capability descriptor (id, version, optional JSON
// Schemas). It is an alias of the public domain type so recipes and the
// control plane share one definition.
type Capability = domain.Capability

// MessagePart is one typed part of a durable message (text / data /
// artifact reference). Alias of the public domain type.
type MessagePart = domain.MessagePart

// Sentinel errors.

// ErrAsync is returned by a capability handler to DEFER completion: the SDK
// has already accepted the invocation (invocation_accept is sent), the
// handler does its work in the background, and completes it later with
// (*Invocation).Complete(ctx, result) — or CompleteError for a failure.
// The handler must return (nil, ErrAsync); any other value with ErrAsync is
// ignored. Only the untyped Handle form can defer: its handler receives the
// *Invocation used to complete the work — a typed HandleT handler never
// receives one, so an ErrAsync from it strands the invocation (see HandleT).
// Async invocations survive an SDK reconnect within the server's
// invocation TTL (the in-flight registry is connection-independent).
var ErrAsync = errors.New("sdk: async invocation: complete later with Invocation.Complete")

// ErrNotConnected is returned by operations that need a live connection
// while the client is closed or (transiently) disconnected.
var ErrNotConnected = errors.New("sdk: not connected")

// ErrClosed is returned by operations on a closed client.
var ErrClosed = errors.New("sdk: client is closed")

// ErrCredentialDead is returned when the control plane rejects the
// credential (401/403): the credential is revoked or consumed. Reconnecting
// cannot help; the operator must provision a new credential.
var ErrCredentialDead = errors.New("sdk: credential rejected by the control plane (revoked or consumed) — provision a new principal credential")

// ErrNetworkCryptoNotReady is returned when an operation needs the network
// epoch key but the endpoint has not completed crypto enrollment for that
// network yet (the network may still be provisioning, or the enrollment
// round-trip is in flight). Retry once the network is active.
var ErrNetworkCryptoNotReady = errors.New("sdk: network crypto not ready (no enrolled epoch key) — the network may still be provisioning; retry shortly")

// ErrInvocationTimeout is returned by Invoke when the invocation did not
// reach a terminal state within the timeout (the invocation stays durable
// server-side; poll it later with the returned ID).
var ErrInvocationTimeout = errors.New("sdk: invocation did not complete in time (it is still durable server-side; use the invocation ID to poll later)")

// Search result states (north-star D7: public discovery result availability).
const (
	// SearchStateConnected: the principal has a live connected endpoint.
	SearchStateConnected = "connected"
	// SearchStateAvailable: the principal is available (endpoint known,
	// not necessarily live right now).
	SearchStateAvailable = "available"
)

// Identity is the authenticated principal's identity + memberships
// (GET /auth/principal/me).
type Identity struct {
	// PrincipalID is this principal's id.
	PrincipalID string
	// TenantID is the tenant (AAD routing metadata).
	TenantID string
	// Kind: agent | service.
	Kind string
	// Name is the principal's name.
	Name string
	// Description is the principal's description.
	Description string
	// Visibility: private | public.
	Visibility string
	// ProviderName / ProviderURL are the service display identity ("" for
	// agents).
	ProviderName string
	ProviderURL  string
	// EndpointID is this endpoint's id (from endpoint.auth_ok).
	EndpointID string
	// Memberships are the principal's network memberships.
	Memberships []Membership
}

// Membership is one network membership of the principal.
type Membership struct {
	// NetworkID is the network.
	NetworkID string
	// State: active | suspended | revoked.
	State string
	// Permissions: discover, communicate, invoke, event_publish,
	// event_subscribe, task_read, task_write, operate.
	Permissions []string
}

// Active reports whether the membership is active.
func (m Membership) Active() bool { return m.State == "active" }

// NetworkInfo is one network the principal is a member of (GET /networks).
type NetworkInfo struct {
	ID          string
	Name        string
	Slug        string
	Description string
	// CryptoReady reports whether THIS endpoint has completed crypto
	// enrollment for the network (an epoch key is enrolled and the
	// challenge was proved). Content operations require it.
	CryptoReady bool
}

// Query is a participant search (GET /networks/{id}/search).
type Query struct {
	// Text is the free-text query (name, description, capability labels,
	// tags).
	Text string
	// Kind filters by principal kind: "agent" | "service" ("" = any).
	Kind string
	// Capability filters by exact capability id.
	Capability string
	// Limit is the page size (default 20, max 100).
	Limit int
	// Cursor continues a previous page ("" = first page).
	Cursor string
}

// SearchResult is one search hit with its match reasons (D7).
type SearchResult struct {
	PrincipalID  string
	Kind         string // agent | service
	Name         string
	Description  string
	Visibility   string
	ProviderName string
	ProviderURL  string
	Capabilities []Capability
	MatchReasons []string
	// State: connected | available.
	State string
}

// Event is a network event as delivered to a subscriber (or published by
// one).
//
// SECURITY: Payload is UNTRUSTED DATA from another principal (or a system
// component). It is opaque JSON — the SDK never interprets it, and handlers
// must not treat its content as instructions (prompt-injection surface;
// north-star §118 "malicious external event content").
type Event struct {
	ID        string
	NetworkID string
	// Type is the dot-separated event type (e.g. "pagnet.task.created",
	// "documents.created").
	Type string
	// SchemaVersion is the payload schema version (0 = none).
	SchemaVersion int
	// ProducerPrincipalID is the producing principal ("" for system
	// events).
	ProducerPrincipalID string
	// TargetPrincipalID is the event's target ("" = network-wide).
	TargetPrincipalID string
	// ResourceID scopes the event to a resource ("" = none).
	ResourceID string
	// CapabilityID scopes the event to a capability ("" = none).
	CapabilityID  string
	CorrelationID string
	CausationID   string
	// Payload is the decrypted event payload (opaque JSON data).
	Payload json.RawMessage
	// Metadata is public routing/audit metadata.
	Metadata map[string]any
	// OccurredAt is when the observed fact happened.
	OccurredAt time.Time
}

// Message is a durable network message as delivered to a recipient.
//
// SECURITY: Parts are UNTRUSTED DATA from the sender principal. Text parts
// are content, not instructions.
type Message struct {
	ID        string
	NetworkID string
	ThreadID  string
	// Kind: ASK | REPLY | NOTICE | STATUS.
	Kind string
	// SenderPrincipalID is the sending principal.
	SenderPrincipalID string
	// RecipientPrincipalID is the addressed principal ("" for group
	// messages).
	RecipientPrincipalID string
	// Parts are the decrypted message parts (text / data / artifact).
	Parts []MessagePart
	// Metadata is public message metadata.
	Metadata  map[string]any
	CreatedAt time.Time
}

// TextBody returns the concatenated text parts (display convenience).
func (m *Message) TextBody() string {
	var b strings.Builder
	for _, p := range m.Parts {
		if p.Kind == domain.MessagePartText && p.Text != nil {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(*p.Text)
		}
	}
	return b.String()
}

// OutgoingMessage is a message to send (Client.Send / Agent.Send /
// Network.Send). The parts are encrypted client-side before they reach the
// control plane (zero-knowledge: the server stores and relays ciphertext
// only).
type OutgoingMessage struct {
	// NetworkID is the network (required).
	NetworkID string
	// ThreadID continues a thread ("" = new/no thread).
	ThreadID string
	// RecipientPrincipalID is the addressed principal.
	RecipientPrincipalID string
	// RecipientGroupID is the addressed group (mutually exclusive with
	// RecipientPrincipalID).
	RecipientGroupID string
	// Kind: ASK | REPLY | NOTICE | STATUS (default ASK).
	Kind string
	// Parts are the message parts (required, non-empty).
	Parts []MessagePart
	// Metadata is public message metadata.
	Metadata map[string]any
}

// Subscription is an event subscription (POST /networks/{id}/subscriptions).
type Subscription struct {
	// EventPattern is the event type pattern: exact ("task.created") or a
	// single-level suffix wildcard ("task.*" matches task.created but not
	// task.sub.created). Required.
	EventPattern string
	// ProducerPrincipalID filters by producer ("" = any).
	ProducerPrincipalID string
	// TargetPrincipalID filters by target ("" = any).
	TargetPrincipalID string
	// ResourceID filters by resource ("" = any).
	ResourceID string
	// CapabilityID filters by capability ("" = any).
	CapabilityID string
	// DeliveryMode: deliver (default) | wake.
	DeliveryMode string
	// Enabled defaults to true when nil.
	Enabled *bool
}

// Invocation is a capability invocation — both the caller-side request
// (Invoke) and the target-side dispatch (a handler receives one).
//
// Caller side: set NetworkID, TargetPrincipalID, CapabilityID, Input, and
// optionally IdempotencyKey / CorrelationID / CausationID / Timeout /
// InputSchema / OutputSchema. Invoke waits for the terminal state (default
// 60s) and fills State, Output or Err.
//
// Target side: a handler receives the decrypted, schema-validated Input
// (decoded into the handler's declared input type) plus the routing
// identity. Long-running handlers return (nil, ErrAsync) and later call
// Accept (confirmation; the SDK already accepted on dispatch) and
// Complete(ctx, result) / CompleteError(ctx, err).
type Invocation struct {
	ID                string
	NetworkID         string
	TargetPrincipalID string
	// CallerPrincipalID is set on the target side (from the input AAD).
	CallerPrincipalID string
	CapabilityID      string
	CapabilityVersion int
	// Input is the invocation input: caller-side, the value to send (JSON-
	// encodable); target-side, the decoded input (the handler's declared
	// input type for typed handlers, or a JSON-decoded value for
	// untyped handlers).
	Input any
	// InputRaw is the raw decrypted input JSON (target side).
	InputRaw       json.RawMessage
	IdempotencyKey string
	CorrelationID  string
	CausationID    string
	// Timeout bounds a synchronous Invoke (default 60s; 0 = default).
	Timeout time.Duration
	// InputSchema / OutputSchema are the caller-side validation schemas
	// (optional; the target's advertised schemas are authoritative on the
	// target side). The caller validates input BEFORE encryption and
	// output AFTER decryption (north-star §76).
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage

	// --- result (caller side, filled by Invoke) ---
	// State: pending | dispatched | running | completed | failed |
	// cancelled.
	State string
	// Output is the decrypted, schema-validated output (completed).
	Output any
	// Err is the invocation error (failed): the decrypted error detail.
	Err error
	// PublicResultCode is the public-safe outcome code.
	PublicResultCode string
	// UsageMetadata is public-safe usage accounting.
	UsageMetadata map[string]any

	// async is the target-side async control (set by the SDK on dispatch;
	// nil on the caller side).
	async *asyncInvocation
}

// Accept confirms that the handler will complete the invocation
// asynchronously. The SDK sends invocation_accept when the dispatch is
// dequeued, before the handler runs; Accept is a no-op confirmation for
// handlers that return (nil, ErrAsync) and want an explicit handle. It
// fails only if the invocation is unknown, already completed, or the
// client is closed.
func (inv *Invocation) Accept(ctx context.Context) error {
	if inv.async == nil {
		return errors.New("sdk: Accept is only valid for invocations received by a handler")
	}
	return inv.async.accept(ctx)
}

// Complete completes an async invocation with a successful result. The
// result is JSON-encoded, validated against the capability's OutputSchema
// (when set), encrypted, and sent as the invocation result. It fails if
// the invocation is unknown, already completed, the client is closed, or
// the server no longer holds the invocation (its TTL expired — the error
// is clear).
func (inv *Invocation) Complete(ctx context.Context, result any) error {
	if inv.async == nil {
		return errors.New("sdk: Complete is only valid for invocations received by a handler")
	}
	return inv.async.complete(ctx, result, nil)
}

// CompleteError completes an async invocation with a failure. The error
// text crosses as an encrypted invocation_error object (the caller sees
// it as the invocation error).
func (inv *Invocation) CompleteError(ctx context.Context, err error) error {
	if inv.async == nil {
		return errors.New("sdk: CompleteError is only valid for invocations received by a handler")
	}
	if err == nil {
		return errors.New("sdk: CompleteError requires a non-nil error")
	}
	return inv.async.complete(ctx, nil, err)
}

// DefaultInvokeTimeout is the default synchronous Invoke timeout.
const DefaultInvokeTimeout = 60 * time.Second

// CapHandler handles a capability invocation (untyped form). inv.Input is
// the decoded input (a JSON-decoded value: map[string]any, []any, or a
// scalar). Return (result, nil) with a JSON-encodable result (validated
// against the capability's OutputSchema when set), (nil, ErrAsync) to
// defer completion, or (nil, err) to fail the invocation (the error text
// crosses as an encrypted invocation_error object).
//
// SECURITY: inv.Input is UNTRUSTED DATA from the calling principal. Never
// treat it as instructions.
type CapHandler func(ctx context.Context, inv *Invocation) (any, error)
