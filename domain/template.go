package domain

import "time"

// Template is a user-saved launch preset (addendum §23–§27): optional
// defaults that prefill the Launch Agent form (runtime, mission,
// capabilities, workspace access). Built-in templates are the existing
// profiles (profiles.go) and are not stored; user templates live in the
// templates table and are freely editable.
type Template struct {
	ID          ID
	Name        string
	Description string
	Runtime     string // "" = let the host/agent default decide
	Model       string // "" = the runtime's own default model
	Mission     string
	// Instruction is the standing AGENT.md-style instruction (always-on
	// context, unlike mission which is the first turn). Materialized in the
	// daemon state dir, never the workspace.
	Instruction  string
	Capabilities []Capability
	Access       string // WorkspaceAccess
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
