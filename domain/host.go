package domain

import (
	"errors"
	"fmt"
	"time"
)

// OwnershipScope is the ownership scope INSIDE the tenant
// (hosts.ownership_scope / enrollment_tokens.ownership_scope /
// principals.ownership_scope). The tenant stays the hard isolation
// boundary; ownership decides responsibility/visibility within it.
type OwnershipScope string

const (
	// OwnershipScopePersonal: the entity belongs to one user
	// (OwnerUserID is set).
	OwnershipScopePersonal OwnershipScope = "personal"
	// OwnershipScopeOrganization: the entity is tenant-wide (OwnerUserID
	// is NULL).
	OwnershipScopeOrganization OwnershipScope = "organization"
)

// ValidOwnershipScope reports whether scope is a known ownership scope.
func ValidOwnershipScope(scope OwnershipScope) bool {
	return scope == OwnershipScopePersonal || scope == OwnershipScopeOrganization
}

// ValidateOwnershipInvariant enforces the ownership invariant:
// PERSONAL requires an owner, ORGANIZATION requires none. Application
// validation runs this before every write; the DB CHECK constraint is the
// backstop.
func ValidateOwnershipInvariant(scope OwnershipScope, ownerUserID *ID) error {
	switch scope {
	case OwnershipScopePersonal:
		if ownerUserID == nil {
			return errors.New("personal ownership requires an owner")
		}
	case OwnershipScopeOrganization:
		if ownerUserID != nil {
			return errors.New("organization ownership requires no owner")
		}
	default:
		return fmt.Errorf("unknown ownership scope %q (want %q or %q)",
			scope, OwnershipScopePersonal, OwnershipScopeOrganization)
	}
	return nil
}

// Host is a physical or virtual machine running the pagnet daemon. A host
// is NOT a network: it may run agents belonging to different networks.
type Host struct {
	ID            ID
	TenantID      ID
	Name          string
	Status        HostStatus
	OS            string
	Arch          string
	DaemonVersion string

	CPUCount      int
	CPULoad       float64
	MemTotalBytes int64
	MemUsedBytes  int64
	DiskFreeBytes int64

	// RootsMode selects how the host's allowed roots are enforced
	// (allow_all by default: any absolute, existing path; allow_list:
	// only paths under one of the host's allowed roots).
	RootsMode string

	// OwnershipScope is the host's ownership inside the tenant
	// ("personal" | "organization").
	OwnershipScope OwnershipScope
	// OwnerUserID is the owning user for PERSONAL hosts; nil for
	// ORGANIZATION hosts.
	OwnerUserID *ID
	// EnrolledByUserID is the audit trail: who minted the enrollment
	// token that created this host (may differ from the owner — an admin
	// can provision a host for another user or for the organization).
	EnrolledByUserID *ID

	LastHeartbeatAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Host roots modes (hosts.roots_mode).
const (
	// RootsModeAllowAll is the default: the host allows any absolute,
	// existing path (the allowed-roots list is ignored).
	RootsModeAllowAll = "allow_all"
	// RootsModeAllowList confines the host to its allowed roots (the
	// existing enforcement: a path must sit under one of them).
	RootsModeAllowList = "allow_list"
)

// ValidRootsMode reports whether m is a known host roots mode (an empty
// mode is treated as the default, allow_all).
func ValidRootsMode(m string) bool {
	return m == "" || m == RootsModeAllowAll || m == RootsModeAllowList
}

// Online reports whether the host should be considered reachable based on its
// last heartbeat (threshold supplied by the server).
func (h Host) Online(offlineThreshold time.Duration) bool {
	if h.Status == HostStatusOnline && h.LastHeartbeatAt != nil {
		return time.Since(*h.LastHeartbeatAt) < offlineThreshold
	}
	return false
}

// HostAllowedRoot confines what filesystem paths a host may expose to the
// control plane. Canonicalized, symlink-resolved paths only.
type HostAllowedRoot struct {
	ID        ID
	HostID    ID
	Path      string
	CreatedAt time.Time
}

// RuntimeInstallation is a runtime detected on a host.
type RuntimeInstallation struct {
	ID         ID
	HostID     ID
	Runtime    RuntimeName
	Version    string
	Path       string
	DetectedAt time.Time
}

// EnrollmentToken is a one-time, short-lived token that enrolls a host.
// Stored hashed server-side.
type EnrollmentToken struct {
	ID           ID
	TenantID     ID
	TokenName    string // display name, e.g. "enroll owl"
	AllowedRoots []string
	ExpiresAt    time.Time
	UsedAt       *time.Time

	// OwnershipScope is the intended ownership the enrolled host gets
	// ("personal" | "organization"; empty/legacy = "organization").
	OwnershipScope OwnershipScope
	// OwnerUserID is the intended owner for PERSONAL tokens; nil for
	// ORGANIZATION tokens.
	OwnerUserID *ID
	// MintedByUserID is the audit trail: who minted this token (never the
	// owner by inference — the token actor is not automatically the
	// owner).
	MintedByUserID *ID
}

// HostMetrics is the per-heartbeat machine telemetry reported by the daemon.
type HostMetrics struct {
	CPUCount      int
	CPULoad       float64
	MemTotalBytes int64
	MemUsedBytes  int64
	DiskFreeBytes int64
}
