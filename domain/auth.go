package domain

import "time"

// AuthUser is the resolved human identity for a request. It carries NO
// credential material (no hashes, no tokens) — it is safe to log/attach to
// contexts.
type AuthUser struct {
	ID          ID
	TenantID    ID
	Username    string
	Email       string
	DisplayName string
	Role        string // "admin" | "user"
}

func (u AuthUser) IsAdmin() bool { return u.Role == "admin" }

// TenantMembership roles (migration 0014).
const (
	MembershipRoleOwner  = "owner"  // created the tenant / personal organization
	MembershipRoleAdmin  = "admin"  // manages the tenant
	MembershipRoleMember = "member" // regular participant
)

// TenantMembership links a user to a tenant with a per-tenant role. A
// user's tenants are exactly the rows they hold here; the MVP is still
// single-tenant (users.tenant_id is the home tenant) until the Phase 2b
// scoping audit moves authorization onto memberships.
type TenantMembership struct {
	ID        ID
	TenantID  ID
	UserID    ID
	Role      string // "owner" | "admin" | "member"
	CreatedAt time.Time
}

func (m TenantMembership) IsOwner() bool { return m.Role == MembershipRoleOwner }
func (m TenantMembership) IsAdmin() bool { return m.Role == MembershipRoleOwner || m.Role == MembershipRoleAdmin }

// Session is a live browser session. The cookie carries an opaque token;
// only its SHA-256 hash is stored, so a database leak never yields a
// working session.
type Session struct {
	ID        ID
	UserID    ID
	UserAgent string
	IP        string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// APIToken is a long-lived, revocable bearer token for CLI/API clients
// (hashed at rest like sessions and host credentials).
type APIToken struct {
	ID         ID
	UserID     ID
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
}
