package domain

import "time"

// ServiceJoinPolicy controls how a service principal is admitted to a
// network.
type ServiceJoinPolicy string

const (
	// JoinPolicyAutoAccept: the service joins a network without per-network
	// approval (its capabilities are still subject to the network's
	// permissions).
	JoinPolicyAutoAccept ServiceJoinPolicy = "auto_accept"
	// JoinPolicyApprovalRequired: joining a network requires the network
	// owner's approval.
	JoinPolicyApprovalRequired ServiceJoinPolicy = "approval_required"
)

// Valid reports whether p is a known join policy.
func (p ServiceJoinPolicy) Valid() bool {
	return p == JoinPolicyAutoAccept || p == JoinPolicyApprovalRequired
}

// ServiceDefinition is the service-specific configuration bound to a
// service principal. Canonical identity (name, description, provider
// display) lives on the Principal; the capability surface lives on the
// capability descriptors + endpoints.
//
// It deliberately does NOT encode how the provider is implemented
// (Postgres, Docker, language, framework) — pagnet only sees the
// principal, its endpoints and its capabilities.
type ServiceDefinition struct {
	ID          ID
	PrincipalID ID
	// ProviderName is the provider's display name ("" = the principal's
	// name).
	ProviderName string
	ProviderURL  string
	JoinPolicy   ServiceJoinPolicy
	Metadata     map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
