package domain

import "time"

// EventDeliveryMode selects how a subscribed event reaches the subscriber.
type EventDeliveryMode string

const (
	// DeliveryDeliver: push the event to the subscriber's live endpoint.
	DeliveryDeliver EventDeliveryMode = "deliver"
	// DeliveryWake: wake a hibernated managed agent for the event (one
	// wake, same native session).
	DeliveryWake EventDeliveryMode = "wake"
)

// Valid reports whether m is a known delivery mode.
func (m EventDeliveryMode) Valid() bool {
	return m == DeliveryDeliver || m == DeliveryWake
}

// EventSubscription is a principal's standing interest in a pattern of
// network events. Matching is metadata-only (type pattern, producer,
// target, resource, capability) — never the payload.
type EventSubscription struct {
	ID                    ID
	NetworkID             ID
	SubscriberPrincipalID ID
	// EventPattern is the event type to match: exact ("task.created") or a
	// single-level suffix wildcard ("task.*").
	EventPattern string
	// ProducerPrincipalID restricts to events produced by this principal
	// (nil = any producer).
	ProducerPrincipalID *ID
	// TargetPrincipalID restricts to events targeting this principal
	// (nil = any target).
	TargetPrincipalID *ID
	// ResourceID restricts to events about this resource (nil = any).
	ResourceID *ID
	// CapabilityID restricts to events about this capability (nil = any).
	CapabilityID *string
	DeliveryMode EventDeliveryMode
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// EventDeliveryState is the lifecycle state of one event delivery to one
// subscriber.
type EventDeliveryState string

const (
	DeliveryStatePending      EventDeliveryState = "pending"
	DeliveryStateDispatched   EventDeliveryState = "dispatched"
	DeliveryStateAcknowledged EventDeliveryState = "acknowledged"
	DeliveryStateFailed       EventDeliveryState = "failed"
)

// Valid reports whether s is a known delivery state.
func (s EventDeliveryState) Valid() bool {
	switch s {
	case DeliveryStatePending, DeliveryStateDispatched,
		DeliveryStateAcknowledged, DeliveryStateFailed:
		return true
	}
	return false
}

// EventDelivery is one event's delivery to one subscriber: the durable
// unit that survives disconnects (pending survives; a live push is only an
// optimization on top of it).
type EventDelivery struct {
	ID                    ID
	SubscriptionID        ID
	EventID               ID
	SubscriberPrincipalID ID
	State                 EventDeliveryState
	// Attempt is the dispatch attempt count (0 = not dispatched yet).
	Attempt int
	// AvailableAt is when the next dispatch attempt is allowed (backoff).
	AvailableAt    time.Time
	DispatchedAt   *time.Time
	AcknowledgedAt *time.Time
	// LastError is the last dispatch failure (public-safe detail).
	LastError string
}
