package domain

import (
	"strings"
	"time"
)

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
	// DispatchID identifies this exact server-assigned delivery attempt.
	DispatchID            string `json:"dispatchId,omitempty"`
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

// ValidEventPattern reports whether p is a valid event subscription pattern:
// an exact event type ("task.created") or a single-level suffix wildcard
// ("task.*" matches "task.created" but not "task.sub.created"). Every
// dot-separated segment is non-empty and contains only [a-zA-Z0-9_-];
// patterns are at most 128 characters.
func ValidEventPattern(p string) bool {
	if p == "" || len(p) > 128 {
		return false
	}
	if strings.HasSuffix(p, ".*") {
		p = p[:len(p)-2]
	} else if strings.Contains(p, "*") {
		return false
	}
	if p == "" {
		return false
	}
	for _, segment := range strings.Split(p, ".") {
		if !isPatternSegment(segment) {
			return false
		}
	}
	return true
}

func isPatternSegment(segment string) bool {
	if segment == "" {
		return false
	}
	for _, r := range segment {
		switch {
		case r == '-' || r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
