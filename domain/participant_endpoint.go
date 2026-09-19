package domain

import "time"

// PrincipalEndpointKind classifies how a principal's endpoint connects.
type PrincipalEndpointKind string

const (
	// EndpointKindManagedAgent: an endpoint owned by a pagnet daemon for a
	// managed agent instance (the daemon reports its liveness).
	EndpointKindManagedAgent PrincipalEndpointKind = "managed_agent"
	// EndpointKindSDK: an endpoint run by the principal's own SDK process.
	EndpointKindSDK PrincipalEndpointKind = "sdk"
)

// Valid reports whether k is a known endpoint kind.
func (k PrincipalEndpointKind) Valid() bool {
	return k == EndpointKindManagedAgent || k == EndpointKindSDK
}

// PrincipalEndpointStatus is the observed liveness of an endpoint.
type PrincipalEndpointStatus string

const (
	EndpointStatusOnline  PrincipalEndpointStatus = "online"
	EndpointStatusOffline PrincipalEndpointStatus = "offline"
)

// Valid reports whether s is a known endpoint status.
func (s PrincipalEndpointStatus) Valid() bool {
	return s == EndpointStatusOnline || s == EndpointStatusOffline
}

// PrincipalEndpoint is one live connection of a principal to the network:
// the generic live-presence unit. A principal (especially a service) may
// run many endpoints; delivery and invocation are routed to ONE eligible
// endpoint per operation.
//
// An endpoint is NOT the principal's identity: the principal is durable,
// the endpoint comes and goes (reconnects, restarts, scales).
type PrincipalEndpoint struct {
	ID          ID
	PrincipalID ID
	Kind        PrincipalEndpointKind
	// AgentInstanceID is the managed instance behind the endpoint
	// (managed agents only; nil for SDK endpoints).
	AgentInstanceID *ID
	Region          string
	Status          PrincipalEndpointStatus
	// Inflight is the number of deliveries/invocations the endpoint has
	// accepted but not yet finished (load signal for selection).
	Inflight int
	// SDKVersion is the SDK version of the endpoint ("" for managed
	// agent endpoints).
	SDKVersion string
	// PublicKey is the endpoint's X25519 public key (base64): its crypto
	// identity for network enrollment, rotation-capable.
	PublicKey  string
	LastSeenAt time.Time
	StartedAt  time.Time
	CreatedAt  time.Time
	Metadata   map[string]any
}
