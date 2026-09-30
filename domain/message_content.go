package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Protected message senders use the existing typed-part array INSIDE the
// ciphertext. Literal human JSON remains inside a text part, while deployed
// SDK receivers continue to understand the payload without negotiation.
type messageContent struct {
	Version int           `json:"pagnet_message_version"`
	Parts   []MessagePart `json:"parts"`
}

func validMessageParts(parts []MessagePart) bool {
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		switch p.Kind {
		case MessagePartText:
			if p.Text == nil {
				return false
			}
		case MessagePartData:
			if len(p.Data) == 0 || !json.Valid(p.Data) {
				return false
			}
		case MessagePartArtifact:
			if p.ArtifactID == nil || *p.ArtifactID == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func EncodeMessageContent(parts []MessagePart) ([]byte, error) {
	if !validMessageParts(parts) {
		return nil, errors.New("message content requires valid typed parts")
	}
	return json.Marshal(parts)
}

// DecodeMessageContent keeps legacy raw text and typed-part arrays readable,
// and accepts the explicit version-1 document for forward compatibility.
func DecodeMessageContent(plain []byte) ([]MessagePart, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(plain, &fields) == nil {
		if _, wrapped := fields["pagnet_message_version"]; wrapped {
			var content messageContent
			if json.Unmarshal(plain, &content) != nil || content.Version != 1 || !validMessageParts(content.Parts) {
				return nil, errors.New("invalid protected message document")
			}
			return content.Parts, nil
		}
	}
	var legacy []MessagePart
	if json.Unmarshal(plain, &legacy) == nil && validMessageParts(legacy) {
		return legacy, nil
	}
	if strings.TrimSpace(string(plain)) == "" {
		return nil, errors.New("empty protected message content")
	}
	return []MessagePart{TextPart(string(plain))}, nil
}

// RenderMessageParts preserves data/artifact references in managed runtime
// prompts; deliveryInput subsequently escapes the result as untrusted XML.
func RenderMessageParts(parts []MessagePart) string {
	var rendered []string
	for _, p := range parts {
		switch p.Kind {
		case MessagePartText:
			if p.Text != nil {
				rendered = append(rendered, *p.Text)
			}
		case MessagePartData:
			rendered = append(rendered, "Message data: "+string(p.Data))
		case MessagePartArtifact:
			if p.ArtifactID != nil {
				rendered = append(rendered, fmt.Sprintf("Message artifact: %s", *p.ArtifactID))
			}
		}
	}
	return strings.Join(rendered, "\n")
}
