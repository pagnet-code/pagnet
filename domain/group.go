package domain

import "time"

// Group is a logical collection of agents for discovery, broadcast and task
// routing. A group is NOT a security boundary; the Network is.
type Group struct {
	ID          ID
	NetworkID   ID
	Slug        string // unique per network, e.g. "repo/github.com/xemahq/dsl"
	Name        string
	AutoCreated bool
	CreatedAt   time.Time
}

// ResourceGroupSlug is the automatic group slug for a resource.
func ResourceGroupSlug(canonicalKey string) string {
	return "repo/" + canonicalKey
}

// GroupMember links an agent definition to a group.
type GroupMember struct {
	GroupID           ID
	AgentDefinitionID ID
	JoinedAt          time.Time
}
