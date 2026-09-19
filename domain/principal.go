package domain

import "time"

// PrincipalKind classifies a network principal. A principal is the durable
// network identity that participates in networks: agents and services.
//
// There are deliberately only two kinds. Worker/representative/system are
// NOT principal kinds — a representative is an agent principal with a
// UserRepresentative binding and memberships; a system component that
// participates in a network is a service.
type PrincipalKind string

const (
	PrincipalKindAgent   PrincipalKind = "agent"
	PrincipalKindService PrincipalKind = "service"
)

// Valid reports whether k is a known principal kind.
func (k PrincipalKind) Valid() bool {
	return k == PrincipalKindAgent || k == PrincipalKindService
}

// PrincipalVisibility controls who can discover the principal.
type PrincipalVisibility string

const (
	// PrincipalVisibilityPrivate: only members of the principal's networks
	// can see it.
	PrincipalVisibilityPrivate PrincipalVisibility = "private"
	// PrincipalVisibilityPublic: discoverable by anyone (public search).
	PrincipalVisibilityPublic PrincipalVisibility = "public"
)

// Valid reports whether v is a known visibility.
func (v PrincipalVisibility) Valid() bool {
	return v == PrincipalVisibilityPrivate || v == PrincipalVisibilityPublic
}

// Principal is the durable network identity shared by agents and services.
// It is the unit of membership, capability advertisement, communication and
// invocation. A principal is owned inside its owning tenant (ownership is
// NOT membership: a principal owned by tenant A may join a network owned by
// tenant B).
//
// ProviderName/ProviderURL are the service's display identity ("" for
// agents).
type Principal struct {
	ID             ID
	OwningTenantID ID
	// OwnershipScope is the principal's ownership inside its tenant
	// ("personal" | "organization").
	OwnershipScope OwnershipScope
	// OwnerUserID is the owning user for PERSONAL principals; nil for
	// ORGANIZATION principals.
	OwnerUserID *ID
	Kind        PrincipalKind
	Name        string
	Description string
	Visibility  PrincipalVisibility
	// ProviderName is the service's display identity ("" for agents).
	ProviderName string
	ProviderURL  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
