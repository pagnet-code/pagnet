package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/transport"
)

const directDomain = transport.DirectChannelDomainV2

var errDirect = directchannelcrypto.ErrInvalid

// Use the transport contract without exposing a public SDK direct-channel API.
type directParty = transport.DirectChannelEndpointV2
type directLimits = transport.DirectChannelLimitsV2
type directDescriptor = transport.DirectChannelDescriptorV2
type directPackage = transport.DirectChannelPublicationV2

func directCanonical(raw []byte, value any, max int) error {
	if len(raw) == 0 || len(raw) > max || json.Unmarshal(raw, value) != nil {
		return errDirect
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errDirect
	}
	return nil
}
func directBinary(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || (size >= 0 && len(b) != size) || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errDirect
	}
	return b, nil
}
func directB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func directValidate(raw []byte, expected directDescriptor, now time.Time) (directDescriptor, error) {
	d, err := transport.DecodeDirectChannelDescriptorV2(raw)
	trusted, terr := expected.CanonicalBytes()
	if err != nil || terr != nil || !bytes.Equal(raw, trusted) || transport.ValidateDirectChannelDescriptorV2(d, now) != nil {
		return directDescriptor{}, errDirect
	}
	return d, nil
}

func directChannelID(d directDescriptor) string {
	id, _ := transport.DirectChannelIDV2(d)
	return id
}

// directMaterial is local-only and must never be serialized to N. The derived
// readiness key is suitable for the readiness verifier; the root
// and traffic keys stay local.
type directMaterial struct {
	descriptor      directDescriptor
	hash            [32]byte
	key             [32]byte
	role            string
	publicationHash [32]byte // set only after preparing, accepting, or validating the stored exact publication
}

func directMaterialFor(d directDescriptor, raw, key []byte, role string) (*directMaterial, error) {
	if len(key) != 32 || (role != "S" && role != "P") {
		return nil, errDirect
	}
	m := &directMaterial{descriptor: d, hash: sha256.Sum256(raw), role: role}
	copy(m.key[:], key)
	return m, nil
}
func directMaterialFromCrypto(m *directchannelcrypto.Material) *directMaterial {
	defer m.Clear()
	return &directMaterial{descriptor: m.Descriptor, hash: m.Hash, key: m.Key, role: m.Role, publicationHash: m.PublicationHash}
}
func (m *directMaterial) cryptoMaterial() directchannelcrypto.Material {
	return directchannelcrypto.Material{Descriptor: m.descriptor, Hash: m.hash, Key: m.key, Role: m.role, PublicationHash: m.publicationHash}
}
func directPrepare(raw []byte, expected directDescriptor, private []byte, now time.Time) (*directMaterial, []byte, error) {
	m, wire, err := directchannelcrypto.Prepare(raw, expected, private, now)
	if err != nil {
		return nil, nil, err
	}
	return directMaterialFromCrypto(m), wire, nil
}
func directAccept(wire []byte, expected directDescriptor, private []byte, now time.Time) (*directMaterial, error) {
	m, err := directchannelcrypto.Accept(wire, expected, private, now)
	if err != nil {
		return nil, err
	}
	return directMaterialFromCrypto(m), nil
}
func (m *directMaterial) derive(purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, m.key[:], m.hash[:], directDomain+"/"+purpose, 32)
}
func (m *directMaterial) readinessKey() ([]byte, error) {
	material := m.cryptoMaterial()
	defer material.Clear()
	return material.ReadinessKey()
}
func (m *directMaterial) readinessProof(raw []byte, credentialID string, now time.Time) ([]byte, error) {
	material := m.cryptoMaterial()
	defer material.Clear()
	return material.ReadinessProof(raw, credentialID, now)
}
func (m *directMaterial) clear() { clear(m.key[:]) }
func (m directMaterial) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("sdk.directMaterial{REDACTED}"))
}

type directHeader = transport.DirectChannelMessageHeaderV2
type directWire = transport.DirectChannelMessageV2

func (m *directMaterial) header(kind, id, root string, ask []byte) (directHeader, error) {
	h := directHeader{Version: 2, Domain: directDomain + "/message", Kind: kind, ChannelID: directChannelID(m.descriptor), DescriptorHash: directB64(m.hash[:]), EpochID: m.descriptor.EpochID, MessageID: id, RootID: root, SenderRole: "S"}
	if kind == "REPLY" {
		a, err := transport.DecodeDirectChannelMessageV2(ask)
		if err != nil || transport.ValidateDirectChannelMessageForDescriptorV2(a, m.descriptor) != nil || a.Header.Kind != "ASK" || a.Header.RootID != root {
			return h, errDirect
		}
		h.SenderRole = "P"
		h.RootID = a.Header.RootID
		h.AskID = a.Header.MessageID
		h.AskWireHash, err = transport.DirectChannelMessageHashV2(a)
		if err != nil {
			return h, errDirect
		}
	} else if kind != "ASK" || len(ask) != 0 {
		return h, errDirect
	}
	if _, err := h.CanonicalBytes(); err != nil {
		return h, errDirect
	}
	return h, nil
}

func (m *directMaterial) aead(kind string) (cipher.AEAD, error) {
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

// prepareHeader validates deterministic inputs before a caller reserves the
// message ID. It performs no encryption and consumes no randomness.
func (m *directMaterial) prepareHeader(kind, id, root string, ask []byte, now time.Time) (directHeader, error) {
	if now.IsZero() || (kind == "ASK" && m.role != "S") || (kind == "REPLY" && m.role != "P") || transport.ValidateDirectChannelDescriptorV2(m.descriptor, now) != nil {
		return directHeader{}, errDirect
	}
	h, err := m.header(kind, id, root, ask)
	if err != nil {
		return directHeader{}, err
	}
	if kind == "REPLY" {
		// The receive path validates continuation ancestry. Preparation still
		// authenticates the exact ASK ciphertext named by the reply header.
		a, err := transport.DecodeDirectChannelMessageV2(ask)
		if err != nil {
			return directHeader{}, errDirect
		}
		temporary, err := m.decrypt(a)
		clear(temporary)
		if err != nil {
			return directHeader{}, err
		}
	}
	return h, nil
}

func (m *directMaterial) seal(kind, id, root string, ask, plaintext []byte, now time.Time) ([]byte, error) {
	h, err := m.prepareHeader(kind, id, root, ask, now)
	if err != nil {
		return nil, err
	}
	return m.sealHeader(h, ask, nil, plaintext, now)
}

// sealHeader revalidates the complete deterministic preparation, including role,
// time and predecessor evidence. A caller cannot bypass preparation by forging h.
func (m *directMaterial) sealHeader(h directHeader, ask, reply, plaintext []byte, now time.Time) ([]byte, error) {
	var expected directHeader
	var err error
	if h.Kind == "ASK" && h.ParentMessageID != "" {
		expected, err = m.prepareContinuationHeader(h.MessageID, ask, reply, now)
	} else {
		if len(reply) != 0 {
			return nil, errDirect
		}
		expected, err = m.prepareHeader(h.Kind, h.MessageID, h.RootID, ask, now)
	}
	if err != nil || expected != h {
		return nil, errDirect
	}
	aad, err := h.CanonicalBytes()
	if err != nil {
		return nil, errDirect
	}
	aead, err := m.aead(h.Kind)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	w := directWire{Header: h, Nonce: directB64(nonce), Ciphertext: directB64(ct)}
	if transport.ValidateDirectChannelMessageForDescriptorV2(w, m.descriptor) != nil {
		return nil, errDirect
	}
	return w.CanonicalBytes()
}

func (m *directMaterial) prepareContinuationHeader(id string, parentAskWire, parentReplyWire []byte, now time.Time) (directHeader, error) {
	if m.role != "S" {
		return directHeader{}, errDirect
	}
	parent, err := transport.DecodeDirectChannelMessageV2(parentReplyWire)
	if err != nil {
		return directHeader{}, errDirect
	}
	temporary, err := m.open("REPLY", parent.Header.MessageID, parent.Header.RootID, parentAskWire, parentReplyWire, now)
	clear(temporary)
	if err != nil {
		return directHeader{}, err
	}
	if id == parent.Header.MessageID || id == parent.Header.AskID {
		return directHeader{}, errDirect
	}
	hash, err := transport.DirectChannelMessageHashV2(parent)
	if err != nil {
		return directHeader{}, errDirect
	}
	h := directHeader{Version: 2, Domain: directDomain + "/message", Kind: "ASK", ChannelID: directChannelID(m.descriptor), DescriptorHash: directB64(m.hash[:]), EpochID: m.descriptor.EpochID, MessageID: id, RootID: parent.Header.RootID, SenderRole: "S", ParentMessageID: parent.Header.MessageID, ParentWireHash: hash}
	if _, err := h.CanonicalBytes(); err != nil {
		return directHeader{}, errDirect
	}
	return h, nil
}

// sealContinuationAsk binds a new turn to an authenticated exact parent reply.
func (m *directMaterial) sealContinuationAsk(id string, parentAskWire, parentReplyWire, plaintext []byte, now time.Time) ([]byte, error) {
	h, err := m.prepareContinuationHeader(id, parentAskWire, parentReplyWire, now)
	if err != nil {
		return nil, err
	}
	return m.sealHeader(h, parentAskWire, parentReplyWire, plaintext, now)
}

// openContinuationAsk requires exact predecessor wires, even though an AEAD
// could authenticate a header containing arbitrary predecessor claims.
func (m *directMaterial) openContinuationAsk(id, root string, parentAskWire, parentReplyWire, wire []byte, now time.Time) ([]byte, error) {
	if now.IsZero() || m.role != "P" || transport.ValidateDirectChannelDescriptorV2(m.descriptor, now) != nil {
		return nil, errDirect
	}
	ask, aerr := transport.DecodeDirectChannelMessageV2(parentAskWire)
	reply, rerr := transport.DecodeDirectChannelMessageV2(parentReplyWire)
	w, err := transport.DecodeDirectChannelMessageV2(wire)
	if aerr != nil || rerr != nil || err != nil || transport.ValidateDirectChannelMessageForDescriptorV2(ask, m.descriptor) != nil || transport.ValidateDirectChannelMessageForDescriptorV2(reply, m.descriptor) != nil || transport.ValidateDirectChannelMessageForDescriptorV2(w, m.descriptor) != nil || transport.ValidateDirectChannelReplyToV2(reply, ask) != nil {
		return nil, errDirect
	}
	hash, _ := transport.DirectChannelMessageHashV2(reply)
	if w.Header.Kind != "ASK" || w.Header.MessageID != id || w.Header.RootID != root || root != reply.Header.RootID || w.Header.ParentMessageID != reply.Header.MessageID || w.Header.ParentWireHash != hash || id == ask.Header.MessageID || id == reply.Header.MessageID {
		return nil, errDirect
	}
	for _, predecessor := range []directWire{ask, reply} {
		temporary, err := m.decrypt(predecessor)
		clear(temporary)
		if err != nil {
			return nil, err
		}
	}
	return m.decrypt(w)
}

// open requires caller-pinned IDs and the exact ASK for a REPLY. Replay and
// thread admission remain external to this private cryptographic helper.
func (m *directMaterial) open(kind, id, root string, ask, wire []byte, now time.Time) ([]byte, error) {
	if now.IsZero() || (kind == "ASK" && m.role != "P") || (kind == "REPLY" && m.role != "S") || transport.ValidateDirectChannelDescriptorV2(m.descriptor, now) != nil {
		return nil, errDirect
	}
	w, err := transport.DecodeDirectChannelMessageV2(wire)
	if err != nil || transport.ValidateDirectChannelMessageForDescriptorV2(w, m.descriptor) != nil || w.Header.Kind != kind || w.Header.MessageID != id || w.Header.RootID != root {
		return nil, errDirect
	}
	if kind == "REPLY" {
		a, err := transport.DecodeDirectChannelMessageV2(ask)
		if err != nil || transport.ValidateDirectChannelMessageForDescriptorV2(a, m.descriptor) != nil || transport.ValidateDirectChannelReplyToV2(w, a) != nil {
			return nil, errDirect
		}
		temporary, err := m.decrypt(a)
		clear(temporary)
		if err != nil {
			return nil, err
		}
	} else if kind != "ASK" || len(ask) != 0 || w.Header.ParentMessageID != "" {
		return nil, errDirect
	}
	return m.decrypt(w)
}

func (m *directMaterial) decrypt(w directWire) ([]byte, error) {
	aead, err := m.aead(w.Header.Kind)
	if err != nil {
		return nil, err
	}
	nonce, _ := directBinary(w.Nonce, 12)
	ct, _ := directBinary(w.Ciphertext, -1)
	aad, _ := w.Header.CanonicalBytes()
	return aead.Open(nil, nonce, ct, aad)
}
