package domain

import "time"

// RepresentativeGrant grants a representative agent access to one network
// with a fixed permission set. A representative can NEVER exceed the
// permissions of the human who owns it: effective authority is
// human access ∩ representative grant. Grants are enforced server-side.
//
// A representative may summarize information from several networks TO THE
// HUMAN, but worker-agent traffic remains network-isolated: a grant never
// turns the representative into an implicit cross-network relay.
type RepresentativeGrant struct {
	ID               ID
	RepresentativeID ID // agent_definitions.id where kind = 'representative'
	NetworkID        ID
	Permissions      []string // observe | communicate | delegate | operate
	CreatedAt        time.Time
}

// Has reports whether the grant includes permission p.
func (g RepresentativeGrant) Has(p string) bool { return HasPermission(g.Permissions, p) }

// NetworkGrantRef pairs a network with the grants a representative holds on
// it (for UI/API listing).
type NetworkGrantRef struct {
	NetworkID   ID
	NetworkSlug string
	NetworkName string
	Permissions []string
}
