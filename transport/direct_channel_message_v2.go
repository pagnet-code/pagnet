package transport

import (
	"encoding/base64"

	"github.com/google/uuid"
)

const DirectChannelMessageMaxBytesV2 = 65536

// Declaration order defines canonical JSON. All fields, including empty links,
// are required on the wire.
type DirectChannelMessageHeaderV2 struct {
	Version         int    `json:"version"`
	Domain          string `json:"domain"`
	Kind            string `json:"kind"`
	ChannelID       string `json:"channelId"`
	DescriptorHash  string `json:"descriptorHash"`
	EpochID         string `json:"epochId"`
	MessageID       string `json:"messageId"`
	RootID          string `json:"rootId"`
	SenderRole      string `json:"senderRole"`
	ParentMessageID string `json:"parentMessageId"`
	ParentWireHash  string `json:"parentWireHash"`
	AskID           string `json:"askId"`
	AskWireHash     string `json:"askWireHash"`
}

type DirectChannelMessageV2 struct {
	Header     DirectChannelMessageHeaderV2 `json:"header"`
	Nonce      string                       `json:"nonce"`
	Ciphertext string                       `json:"ciphertext"`
}

func (h DirectChannelMessageHeaderV2) CanonicalBytes() ([]byte, error) {
	epoch, err := uuid.Parse(h.EpochID)
	if h.Version != 2 || h.Domain != DirectChannelDomainV2+"/message" || !directV2ID(h.EpochID) || err != nil || epoch.Version() != 7 || epoch.Variant() != uuid.RFC4122 || !directV2ID(h.MessageID) || !directV2ID(h.RootID) {
		return nil, errDirectChannelV2
	}
	for _, s := range []string{h.ChannelID, h.DescriptorHash} {
		if _, ok := directV2Binary(s, 32); !ok {
			return nil, errDirectChannelV2
		}
	}
	switch h.Kind {
	case "ASK":
		if h.SenderRole != "S" || h.AskID != "" || h.AskWireHash != "" {
			return nil, errDirectChannelV2
		}
		if h.ParentMessageID == "" && h.ParentWireHash == "" {
			if h.RootID != h.MessageID {
				return nil, errDirectChannelV2
			}
		} else {
			if !directV2ID(h.ParentMessageID) || h.RootID == h.MessageID {
				return nil, errDirectChannelV2
			}
			if _, ok := directV2Binary(h.ParentWireHash, 32); !ok {
				return nil, errDirectChannelV2
			}
		}
	case "REPLY":
		if h.SenderRole != "P" || h.ParentMessageID != "" || h.ParentWireHash != "" || !directV2ID(h.AskID) || h.MessageID == h.AskID {
			return nil, errDirectChannelV2
		}
		if _, ok := directV2Binary(h.AskWireHash, 32); !ok {
			return nil, errDirectChannelV2
		}
	default:
		return nil, errDirectChannelV2
	}
	return directV2Canonical(h, DirectChannelMessageMaxBytesV2)
}

func (w DirectChannelMessageV2) CanonicalBytes() ([]byte, error) {
	if _, err := w.Header.CanonicalBytes(); err != nil {
		return nil, err
	}
	if _, ok := directV2Binary(w.Nonce, 12); !ok {
		return nil, errDirectChannelV2
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(w.Ciphertext)
	if err != nil || len(ciphertext) < 16 || base64.RawURLEncoding.EncodeToString(ciphertext) != w.Ciphertext {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(w, DirectChannelMessageMaxBytesV2)
}

func DecodeDirectChannelMessageV2(raw []byte) (DirectChannelMessageV2, error) {
	var w DirectChannelMessageV2
	if directV2Decode(raw, &w, DirectChannelMessageMaxBytesV2) != nil {
		return DirectChannelMessageV2{}, errDirectChannelV2
	}
	if _, err := w.CanonicalBytes(); err != nil {
		return DirectChannelMessageV2{}, err
	}
	return w, nil
}

// DirectChannelMessageHashV2 hashes the complete canonical encrypted wire.
func DirectChannelMessageHashV2(w DirectChannelMessageV2) (string, error) {
	raw, err := w.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return directV2Hash(raw), nil
}

// ValidateDirectChannelMessageForDescriptorV2 checks structure and exact
// descriptor binding only; it does not establish current authority or expiry.
func ValidateDirectChannelMessageForDescriptorV2(w DirectChannelMessageV2, d DirectChannelDescriptorV2) error {
	raw, err := w.CanonicalBytes()
	if err != nil {
		return err
	}
	channelID, err := DirectChannelIDV2(d)
	if err != nil {
		return err
	}
	descriptorHash, err := DescriptorHashV2(d)
	if err != nil {
		return err
	}
	if w.Header.ChannelID != channelID || w.Header.DescriptorHash != descriptorHash || w.Header.EpochID != d.EpochID || len(raw) > d.Limits.MaxMessageWireBytes {
		return errDirectChannelV2
	}
	return nil
}

// ValidateDirectChannelReplyToV2 binds a reply to the exact canonical ASK wire.
func ValidateDirectChannelReplyToV2(reply, ask DirectChannelMessageV2) error {
	if _, err := reply.CanonicalBytes(); err != nil {
		return err
	}
	askHash, err := DirectChannelMessageHashV2(ask)
	if err != nil {
		return err
	}
	r, a := reply.Header, ask.Header
	if r.Kind != "REPLY" || a.Kind != "ASK" || r.AskID != a.MessageID || r.AskWireHash != askHash || r.RootID != a.RootID || r.ChannelID != a.ChannelID || r.DescriptorHash != a.DescriptorHash || r.EpochID != a.EpochID {
		return errDirectChannelV2
	}
	return nil
}
