package domain

import (
	"context"
	"encoding/json"
	"time"
)

// Event is an immutable historical observation about something that happened
// in the agent network. Events power monitoring, audit history, the graph
// and the historical timeline.
//
// Events are a DOMAIN feature ("what happened in the agent network"), kept
// deliberately separate from OpenTelemetry infrastructure telemetry.
//
// EventType is dot-separated ("pagnet.task.created", "documents.created"):
// core types carry the "pagnet." prefix, provider events do not. Routing
// metadata (producer/target principal, resource, capability) is
// server-readable; the payload itself is protected on active private
// networks (ProtectedPayload, object type event_payload).
type Event struct {
	ID        ID
	TenantID  ID
	NetworkID *ID // nil for tenant-level events
	// Timestamp is when the event was recorded.
	Timestamp time.Time
	// EventType is the dot-separated event type.
	EventType string
	// SchemaVersion is the payload schema version (0 = core event with no
	// versioned payload).
	SchemaVersion int
	// ProducerPrincipalID is the principal the event is about the actions
	// of (the producing participant; nil for system events).
	ProducerPrincipalID *ID
	// ProducerEndpointID is the endpoint the producer acted through
	// (execution provenance; nil when unknown).
	ProducerEndpointID *ID
	// TargetPrincipalID is the principal the event is directed at (nil =
	// network-wide).
	TargetPrincipalID *ID
	// ResourceID scopes the event to a resource (nil = none).
	ResourceID *ID
	// CapabilityID scopes the event to a capability (nil = none).
	CapabilityID *ID
	// ActorType/ActorID are the audit provenance for human/system events
	// (user | host | agent_instance | system).
	ActorType     string
	ActorID       string
	TargetType    string
	TargetID      string
	TaskID        *ID
	MessageID     *ID
	CorrelationID *ID
	CausationID   *ID
	TraceID       string
	Metadata      map[string]any
	// ProtectedPayload is the E2EE envelope of the event payload on an
	// active private network (object type event_payload); the control
	// plane relays it byte-for-byte and never reads it.
	ProtectedPayload json.RawMessage
	// OccurredAt is when the observed fact happened (may differ from
	// Timestamp, the record time).
	OccurredAt time.Time
}

// NewEvent builds an Event with a fresh ID/timestamp and correlation,
// causation and trace context pulled from ctx where present.
func NewEvent(ctx context.Context, tenantID ID, networkID *ID, eventType, actorType, actorID, targetType, targetID string, metadata map[string]any) Event {
	now := time.Now().UTC()
	ev := Event{
		ID:         NewID(),
		TenantID:   tenantID,
		NetworkID:  networkID,
		Timestamp:  now,
		EventType:  eventType,
		ActorType:  actorType,
		ActorID:    actorID,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metadata,
		OccurredAt: now,
	}
	if metadata == nil {
		ev.Metadata = map[string]any{}
	}
	if id, ok := CorrelationID(ctx); ok {
		ev.CorrelationID = &id
	}
	if id, ok := CausationID(ctx); ok {
		ev.CausationID = &id
	}
	if span := traceSpan(ctx); span.SpanContext().IsValid() {
		ev.TraceID = span.SpanContext().TraceID().String()
	}
	return ev
}
