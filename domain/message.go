package domain

import (
	"encoding/json"
	"strings"
	"time"
)

// Thread is a conversation context for messages.
type Thread struct {
	ID        ID
	NetworkID ID
	// CreatedByPrincipalID is the principal that started the thread
	// (nil for system-created threads).
	CreatedByPrincipalID *ID
	Subject              string
	CreatedAt            time.Time
}

// Message part kinds.
const (
	MessagePartText     = "text"
	MessagePartData     = "data"
	MessagePartArtifact = "artifact"
)

// MessagePart is a typed part of a durable message. Messages are never
// assumed to be plain text: they can carry text, structured JSON data, or a
// reference to a first-class Artifact. This keeps the door open for future
// A2A-style message parts without MIME/content-negotiation overkill.
type MessagePart struct {
	Kind       string          `json:"kind"`
	Text       *string         `json:"text,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	ArtifactID *ID             `json:"artifactId,omitempty"`
}

// TextPart builds a text message part.
func TextPart(s string) MessagePart {
	return MessagePart{Kind: MessagePartText, Text: &s}
}

// DataPart builds a structured-data message part.
func DataPart(data json.RawMessage) MessagePart {
	return MessagePart{Kind: MessagePartData, Data: data}
}

// ArtifactPart builds a part that references a published artifact.
func ArtifactPart(artifactID ID) MessagePart {
	return MessagePart{Kind: MessagePartArtifact, ArtifactID: &artifactID}
}

// Message is a durable communication event between agents.
//
// Message = communication. Work delegation is a Task, never a message.
//
// The principals are the canonical sender/recipient; the instance ids are
// optional execution provenance (which endpoint actually sent/received).
type Message struct {
	ID                   ID
	NetworkID            ID
	ThreadID             ID
	Kind                 MessageKind
	SenderPrincipalID    *ID
	RecipientPrincipalID *ID
	// SenderInstanceID is the instance that sent the message (execution
	// provenance; nil when the sender is not a managed instance).
	SenderInstanceID *ID
	// RecipientInstanceID is the instance the message was addressed to
	// (execution provenance; nil when addressed to a principal/group).
	RecipientInstanceID *ID
	RecipientGroupID    *ID
	ResourceID          *ID
	TaskID              *ID
	CorrelationID       *ID
	Parts               []MessagePart
	Metadata            map[string]any
	CreatedAt           time.Time
	DeliveredAt         *time.Time
	// Human provenance (§10): when a representative caused this message on
	// a human's behalf, InitiatorUserID is that human and Source/SourceRef
	// record the path (channel:fake / network / web / api + origin ref).
	// Sender (the representative) is the actor; Recipient is the target.
	InitiatorUserID *ID
	Source          string
	SourceRef       string
}

// TextBody returns the concatenated text parts (display convenience).
func (m Message) TextBody() string {
	var b strings.Builder
	for _, p := range m.Parts {
		if p.Kind == MessagePartText && p.Text != nil {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(*p.Text)
		}
	}
	return b.String()
}

// InboxItem is what network_inbox returns for an agent instance: pending
// questions, replies, notices and relevant task notifications.
type InboxItem struct {
	Kind      MessageKind
	MessageID ID
	ThreadID  ID
	FromAgent string
	ToAgent   string
	Subject   string
	Body      string // rendered text of the message parts
	Resource  *string
	TaskID    *ID
	CreatedAt time.Time
}
