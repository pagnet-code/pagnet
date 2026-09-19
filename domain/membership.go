package domain

import "time"

// MembershipState is the lifecycle state of a network membership.
type MembershipState string

const (
	MembershipActive    MembershipState = "active"
	MembershipSuspended MembershipState = "suspended"
	MembershipRevoked   MembershipState = "revoked"
)

// Valid reports whether s is a known membership state.
func (s MembershipState) Valid() bool {
	return s == MembershipActive || s == MembershipSuspended || s == MembershipRevoked
}

// NetworkPermission is one network-scoped permission a membership carries.
//
// Permissions are what a principal is ALLOWED to do in a network. They are
// deliberately kept separate from capabilities (what a principal CAN do):
// advertising a capability never grants a permission, and a permission
// never implies a capability.
type NetworkPermission string

const (
	// PermDiscover: see the network's discoverable participants.
	PermDiscover NetworkPermission = "discover"
	// PermCommunicate: send messages to the network's participants.
	PermCommunicate NetworkPermission = "communicate"
	// PermInvoke: invoke the network participants' capabilities.
	PermInvoke NetworkPermission = "invoke"
	// PermEventPublish: publish events into the network.
	PermEventPublish NetworkPermission = "event_publish"
	// PermEventSubscribe: subscribe to the network's events.
	PermEventSubscribe NetworkPermission = "event_subscribe"
	// PermTaskRead: read the network's tasks.
	PermTaskRead NetworkPermission = "task_read"
	// PermTaskWrite: create and delegate tasks in the network.
	PermTaskWrite NetworkPermission = "task_write"
	// PermOperate: launch/wake/stop the network's managed agents.
	PermOperate NetworkPermission = "operate"
)

// Valid reports whether p is a known network permission.
func (p NetworkPermission) Valid() bool {
	switch p {
	case PermDiscover, PermCommunicate, PermInvoke, PermEventPublish,
		PermEventSubscribe, PermTaskRead, PermTaskWrite, PermOperate:
		return true
	}
	return false
}

// HasPermission reports whether perms contains p.
func HasPermission(perms []NetworkPermission, p NetworkPermission) bool {
	for _, x := range perms {
		if x == p {
			return true
		}
	}
	return false
}

// NetworkMembership is the central relationship between a principal and a
// network: the network is the communication security boundary, and a
// principal may be a member of zero, one, many or millions of networks.
//
// A representative's effective authority in a network is the intersection
// of its owner's authority and this membership's permissions — computed,
// never a separate grant table.
type NetworkMembership struct {
	ID          ID
	NetworkID   ID
	PrincipalID ID
	State       MembershipState
	Permissions []NetworkPermission
	// AddedByUserID is the user who added the principal (audit provenance;
	// nil when the membership was created by the system).
	AddedByUserID *ID
	JoinedAt      time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
