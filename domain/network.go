package domain

import "time"

// Tenant is the top-level isolation owner. MVP runs a single default tenant;
// every table still carries tenant_id so the model scales.
type Tenant struct {
	ID        ID
	Slug      string
	Name      string
	CreatedAt time.Time
}

// User is a human account. MVP: a single admin-style role.
type User struct {
	ID          ID
	TenantID    ID
	Username    string
	Email       string
	DisplayName string
	Role        string // "admin" | "user"
	CreatedAt   time.Time
}

// PrivacyMode is a network's content-encryption mode (plan §10.3). It is
// explicit — privacy is never inferred from the subscription alone: a Pro
// customer may still have standard networks.
type PrivacyMode string

const (
	// PrivacyModeStandard is the default: the server processes content
	// normally (Community behavior).
	PrivacyModeStandard PrivacyMode = "standard"
	// PrivacyModePrivateE2EE enables Pagnet Private — Zero-Knowledge Content
	// Encryption: protected content is ciphertext to the server.
	PrivacyModePrivateE2EE PrivacyMode = "private_e2ee"
)

// Valid reports whether m is a known privacy mode.
func (m PrivacyMode) Valid() bool {
	return m == PrivacyModeStandard || m == PrivacyModePrivateE2EE
}

// Network is the primary security and isolation boundary. Agents from
// different networks must not discover or communicate with each other.
type Network struct {
	ID          ID
	TenantID    ID
	Slug        string
	Name        string
	Description string
	// PrivacyMode carries the network's content-encryption mode on the wire
	// so both the control plane and the daemon can act on it. The server's
	// networks.privacy_mode column (migration 0019) is the source of truth;
	// the JSON name matches the server's wire format.
	PrivacyMode PrivacyMode `json:"privacyMode"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
