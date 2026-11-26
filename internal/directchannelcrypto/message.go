package directchannelcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func (m *Material) messageAEAD(kind string) (cipher.AEAD, error) {
	key, err := m.derive(kind)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// OpenAsk authenticates an initial source ASK against caller-pinned IDs.
// Replay admission remains external. Continuations require ancestry evidence
// and are rejected by this narrow adapter. The caller owns and must clear plaintext.
func (m *Material) OpenAsk(id, root string, wire []byte, now time.Time) ([]byte, error) {
	if m == nil || now.IsZero() || m.Role != "P" || transport.ValidateDirectChannelDescriptorV2(m.Descriptor, now) != nil {
		return nil, ErrInvalid
	}
	w, err := transport.DecodeDirectChannelMessageV2(wire)
	if err != nil || transport.ValidateDirectChannelMessageForDescriptorV2(w, m.Descriptor) != nil || w.Header.Kind != "ASK" || w.Header.SenderRole != "S" || w.Header.MessageID != id || w.Header.RootID != root || w.Header.ParentMessageID != "" || w.Header.ParentWireHash != "" {
		return nil, ErrInvalid
	}
	aead, err := m.messageAEAD("ASK")
	if err != nil {
		return nil, err
	}
	nonce, _ := binary(w.Nonce, aead.NonceSize())
	ct, _ := binary(w.Ciphertext, -1)
	aad, _ := w.Header.CanonicalBytes()
	return aead.Open(nil, nonce, ct, aad)
}

// SealReply authenticates the exact initial ASK before binding a peer REPLY to
// its ID, root, and ciphertext hash. ID reservation and replay admission remain
// external; callers must retain the returned wire for retries.
func (m *Material) SealReply(id, root string, ask, plaintext []byte, now time.Time) ([]byte, error) {
	a, err := transport.DecodeDirectChannelMessageV2(ask)
	if err != nil {
		return nil, ErrInvalid
	}
	temporary, err := m.OpenAsk(a.Header.MessageID, root, ask, now)
	clear(temporary)
	if err != nil {
		return nil, err
	}
	hash, err := transport.DirectChannelMessageHashV2(a)
	if err != nil {
		return nil, ErrInvalid
	}
	h := transport.DirectChannelMessageHeaderV2{Version: 2, Domain: domain + "/message", Kind: "REPLY", ChannelID: channelID(m.Descriptor), DescriptorHash: b64(m.Hash[:]), EpochID: m.Descriptor.EpochID, MessageID: id, RootID: a.Header.RootID, SenderRole: "P", AskID: a.Header.MessageID, AskWireHash: hash}
	aad, err := h.CanonicalBytes()
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := m.messageAEAD("REPLY")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	w := transport.DirectChannelMessageV2{Header: h, Nonce: b64(nonce), Ciphertext: b64(aead.Seal(nil, nonce, plaintext, aad))}
	if transport.ValidateDirectChannelMessageForDescriptorV2(w, m.Descriptor) != nil {
		return nil, ErrInvalid
	}
	return w.CanonicalBytes()
}
