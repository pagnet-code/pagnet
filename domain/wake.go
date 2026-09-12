package domain

import "time"

// WakeRequestStatus tracks a wake dispatch.
type WakeRequestStatus string

const (
	WakePending    WakeRequestStatus = "pending"
	WakeDispatched WakeRequestStatus = "dispatched"
	WakeDelivered  WakeRequestStatus = "delivered"
	WakeFailed     WakeRequestStatus = "failed"
)

// WakeRequest is a durable, idempotent wake dispatch for an instance.
// Wakes are initiated with an atomic state transition (hibernated →
// waking); concurrent inbound work creates queued work, not duplicate
// wakes.
type WakeRequest struct {
	ID          ID
	InstanceID  ID
	Reason      string // WakeReason*
	Status      WakeRequestStatus
	Error       string
	RequestedAt time.Time
	ResolvedAt  *time.Time
}
