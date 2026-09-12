package domain

import "time"

// ChannelBinding associates a stable external identity (e.g. a Telegram
// user/chat id) with an authenticated pagnet user. External usernames are
// never trusted on their own: the association is created only through the
// one-time pairing-code flow.
type ChannelBinding struct {
	ID             ID
	TenantID       ID
	UserID         ID
	Channel        string // telegram | web | ...
	ExternalUserID string
	ExternalChatID string
	PairedAt       time.Time
	RevokedAt      *time.Time
}

// Active reports whether the binding is currently valid.
func (b ChannelBinding) Active() bool { return b.RevokedAt == nil }

// ChannelPairingCode is a short-lived, one-time code used to pair an
// external identity with an authenticated user. Only its hash is stored.
type ChannelPairingCode struct {
	ID        ID
	TenantID  ID
	UserID    ID // the authenticated user the code was minted for
	Channel   string
	ExpiresAt time.Time
	UsedAt    *time.Time
	// Set when the code is consumed (the bot reports the external identity).
	ExternalUserID *string
	ExternalChatID *string
}

// ExternalConversation is a human conversation with a representative agent
// on an external channel. active_network_id makes the selected Network
// deterministic across LLM session restarts (stored here, not only inside
// the model conversation).
type ExternalConversation struct {
	ID                     ID
	RepresentativeID       ID
	ChannelBindingID       ID
	ExternalConversationID string
	ActiveNetworkID        *ID
	CreatedAt              time.Time
	LastActivityAt         time.Time
}
