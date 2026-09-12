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

// Network is the primary security and isolation boundary. Agents from
// different networks must not discover or communicate with each other.
type Network struct {
	ID          ID
	TenantID    ID
	Slug        string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
