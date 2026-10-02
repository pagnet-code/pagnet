package transport

import (
	"encoding/json"
	"time"
)

const NativeObservationReceiptProtocol = "native-observation-receipt-v1"
const (
	MsgHostSession                  = "host.session"
	MsgNativeOriginRegister         = "host.native_origin_register"
	MsgNativeOriginRegistered       = "host.native_origin_registered"
	MsgNativeOriginRetired          = "host.native_origin_retired"
	MsgNativeOriginSession          = "host.native_origin_session"
	MsgNativeOriginSessionConfirmed = "host.native_origin_session_confirmed"
	MsgNativeObservation            = "host.native_observation"
	MsgNativeObservationReceipt     = "host.native_observation_receipt"
	MsgNativeObservationRejected    = "host.native_observation_rejected"
)

// HostSessionPayload is the authenticated connection's negotiated feature set.
// Transport epoch changes do not manufacture a replacement native origin.
type HostSessionPayload struct {
	NativeAdmissionID string    `json:"nativeAdmissionId"`
	HostID            string    `json:"hostId"`
	RunnerID          string    `json:"runnerId"`
	RunnerEpoch       time.Time `json:"runnerEpoch"`
	BootID            string    `json:"bootId"`
	ProtocolFeatures  []string  `json:"protocolFeatures"`
}

type NativeOriginRegisterPayload struct {
	NativeAdmissionID string `json:"nativeAdmissionId"`
	NativeGeneration  string `json:"nativeGeneration"`
	RequestID         string `json:"requestId"`
	CommandID         string `json:"commandId"`
	InstanceID        string `json:"instanceId"`
	Runtime           string `json:"runtime"`
}

// NativeObservationOrigin is an immutable admission, authorized against the
// actual server command lease. Its ID is public metadata, never a credential.
type NativeObservationOrigin struct {
	NativeAdmissionID string    `json:"nativeAdmissionId"`
	NativeGeneration  string    `json:"nativeGeneration"`
	ID                string    `json:"id"`
	CommandID         string    `json:"commandId"`
	TenantID          string    `json:"tenantId"`
	HostID            string    `json:"hostId"`
	InstanceID        string    `json:"instanceId"`
	Runtime           string    `json:"runtime"`
	RunnerID          string    `json:"runnerId"`
	RunnerEpoch       time.Time `json:"runnerEpoch"`
	BootID            string    `json:"bootId"`
	CreatedAt         time.Time `json:"createdAt"`
	NativeSessionID   string    `json:"nativeSessionId,omitempty"`
}

type NativeOriginRegisteredPayload struct {
	RequestID   string                   `json:"requestId"`
	Origin      *NativeObservationOrigin `json:"origin,omitempty"`
	PublicError string                   `json:"publicError,omitempty"`
	Retryable   bool                     `json:"retryable,omitempty"`
}

// Digest binds the original journal bytes. Retries keep those bytes and their
// IDs; they do not re-encrypt an answer or execute a native choice again.
type NativeObservationPayload struct {
	ObservationID string          `json:"observationId"`
	OriginID      string          `json:"originId"`
	MessageType   string          `json:"messageType"`
	Digest        string          `json:"digest"`
	ObservedAt    time.Time       `json:"observedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	Payload       json.RawMessage `json:"payload"`
}

type NativeObservationReceiptPayload struct {
	ObservationID string `json:"observationId"`
	OriginID      string `json:"originId"`
	Digest        string `json:"digest"`
	Disposition   string `json:"disposition"`
}

// NativeOriginSessionPayload is emitted from a still-owned live driver session,
// never inferred from a journal row or a previous transport connection.
type NativeOriginSessionPayload struct {
	RequestID        string    `json:"requestId,omitempty"`
	NativeGeneration string    `json:"nativeGeneration,omitempty"`
	RunnerID         string    `json:"runnerId,omitempty"`
	RunnerEpoch      time.Time `json:"runnerEpoch,omitempty"`
	BootID           string    `json:"bootId,omitempty"`
	OriginID         string    `json:"originId"`
	InstanceID       string    `json:"instanceId"`
	Runtime          string    `json:"runtime"`
	SessionID        string    `json:"sessionId"`
}

// A session proof is acknowledged after its live transport binding commits.
// The original activation descriptor remains immutable across controller boots.
type NativeOriginSessionConfirmedPayload struct {
	RequestID        string    `json:"requestId"`
	OriginID         string    `json:"originId"`
	NativeGeneration string    `json:"nativeGeneration"`
	SessionID        string    `json:"sessionId"`
	RunnerID         string    `json:"runnerId"`
	RunnerEpoch      time.Time `json:"runnerEpoch"`
	PublicError      string    `json:"publicError,omitempty"`
	Retryable        bool      `json:"retryable,omitempty"`
}
