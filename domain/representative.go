package domain

import "time"

// UserRepresentative binds a human user to the agent principal that
// represents them across the networks the user grants it.
//
// A representative is NOT a distinct principal kind: it is a regular agent
// principal plus this binding plus ordinary NetworkMemberships. Its
// effective authority in a network is the intersection of its owner's
// authority and the membership's permissions (computed — there is no
// separate grant table).
//
// A representative may summarize information from several networks TO THE
// HUMAN, but worker-agent traffic remains network-isolated: it is never an
// implicit cross-network relay.
type UserRepresentative struct {
	ID     ID
	UserID ID
	// AgentPrincipalID is the agent principal that represents the user.
	AgentPrincipalID ID
	// IsDefault marks the user's default representative (at most one per
	// user).
	IsDefault bool
	CreatedAt time.Time
}
