package sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const directDomain = transport.DirectChannelDomainV2

var errDirect = errors.New("sdk: invalid direct channel context or wire")

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
func directPrepare(raw []byte, expected directDescriptor, private []byte, now time.Time) (*directMaterial, []byte, error) {
	d, err := directValidate(raw, expected, now)
	if err != nil {
		return nil, nil, err
	}
	pub, _ := directBinary(d.S.PublicKey, 32)
	recipient, _ := directBinary(d.P.PublicKey, 32)
	if !pairPrivateMatches(private, pub) {
		return nil, nil, errDirect
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, err
	}
	hash := sha256.Sum256(raw)
	enc, ct, err := e2ee.HPKEWrapAuth(recipient, private, []byte(directDomain+"/epoch-wrap"), hash[:], key)
	if err != nil {
		return nil, nil, err
	}
	wire, err := (directPackage{Descriptor: d, Enc: directB64(enc), Ciphertext: directB64(ct)}).CanonicalBytes()
	if err != nil {
		return nil, nil, err
	}
	m, err := directMaterialFor(d, raw, key, "S")
	if err != nil {
		return nil, nil, err
	}
	m.publicationHash = sha256.Sum256(wire)
	return m, wire, nil
}
func directAccept(wire []byte, expected directDescriptor, private []byte, now time.Time) (*directMaterial, error) {
	p, err := transport.DecodeDirectChannelPublicationV2(wire)
	if err != nil {
		return nil, errDirect
	}
	raw, err := p.Descriptor.CanonicalBytes()
	if err != nil {
		return nil, errDirect
	}
	d, err := directValidate(raw, expected, now)
	if err != nil {
		return nil, err
	}
	pub, _ := directBinary(d.P.PublicKey, 32)
	sender, _ := directBinary(d.S.PublicKey, 32)
	enc, eerr := directBinary(p.Enc, 32)
	ct, cerr := directBinary(p.Ciphertext, 48)
	if !pairPrivateMatches(private, pub) || eerr != nil || cerr != nil {
		return nil, errDirect
	}
	hash := sha256.Sum256(raw)
	key, err := e2ee.HPKEUnwrapAuth(private, sender, enc, []byte(directDomain+"/epoch-wrap"), hash[:], ct)
	defer clear(key)
	if err != nil {
		return nil, err
	}
	m, err := directMaterialFor(d, raw, key, "P")
	if err != nil {
		return nil, err
	}
	m.publicationHash = sha256.Sum256(wire)
	return m, nil
}
func (m *directMaterial) derive(purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, m.key[:], m.hash[:], directDomain+"/"+purpose, 32)
}
func (m *directMaterial) readinessKey() ([]byte, error) { return m.derive("readiness") }

// CredentialID comes from authenticated local credential metadata. This helper
// only proves possession; challenge issuance and replay consumption are external.
func (m *directMaterial) readinessProof(raw []byte, credentialID string, now time.Time) ([]byte, error) {
	challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(raw)
	if err != nil || m.publicationHash == ([32]byte{}) || challenge.Role != m.role {
		return nil, errDirect
	}
	d := m.descriptor
	party := d.S
	if m.role == "P" {
		party = d.P
	}
	issued, _ := time.Parse(time.RFC3339Nano, challenge.IssuedAt)
	expiry, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	descriptorExpiry, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if transport.ValidateDirectChannelDescriptorV2(d, now) != nil || now.Before(issued) || !expiry.After(now) || expiry.After(descriptorExpiry) || credentialID != party.CredentialID || challenge.CredentialID != credentialID || challenge.PrincipalID != party.PrincipalID || challenge.EndpointID != party.EndpointID || challenge.ChannelID != directChannelID(d) || challenge.ParentGrantID != d.ParentGrantID || challenge.GrantGeneration != d.GrantGeneration || challenge.ChannelGeneration != d.ChannelGeneration || challenge.DirectIntentID != d.DirectIntentID || challenge.DescriptorHash != directB64(m.hash[:]) || challenge.PublicationHash != directB64(m.publicationHash[:]) || challenge.EpochID != d.EpochID {
		return nil, errDirect
	}
	key, err := m.readinessKey()
	defer clear(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	transcriptHash := sha256.Sum256(raw)
	proof := transport.DirectChannelReadinessProofV2{ProtocolVersion: transport.DirectChannelReadinessProtocolV2, ChallengeID: challenge.ChallengeID, TranscriptHash: directB64(transcriptHash[:]), Confirmation: directB64(mac.Sum(nil))}
	return proof.CanonicalBytes()
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
func (m *directMaterial) seal(kind, id, root string, ask, plaintext []byte, now time.Time) ([]byte, error) {
	if (kind == "ASK" && m.role != "S") || (kind == "REPLY" && m.role != "P") || transport.ValidateDirectChannelDescriptorV2(m.descriptor, now) != nil {
		return nil, errDirect
	}
	h, err := m.header(kind, id, root, ask)
	if err != nil {
		return nil, err
	}
	if kind == "REPLY" {
		temporary, err := m.open("ASK", h.AskID, h.RootID, nil, ask, now)
		clear(temporary)
		if err != nil {
			return nil, err
		}
	}
	return m.sealHeader(h, plaintext)
}

func (m *directMaterial) sealHeader(h directHeader, plaintext []byte) ([]byte, error) {
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

// sealContinuationAsk binds a new turn to an authenticated exact parent reply.
func (m *directMaterial) sealContinuationAsk(id string, parentAskWire, parentReplyWire, plaintext []byte, now time.Time) ([]byte, error) {
	if m.role != "S" {
		return nil, errDirect
	}
	parent, err := transport.DecodeDirectChannelMessageV2(parentReplyWire)
	if err != nil {
		return nil, errDirect
	}
	temporary, err := m.open("REPLY", parent.Header.MessageID, parent.Header.RootID, parentAskWire, parentReplyWire, now)
	clear(temporary)
	if err != nil {
		return nil, err
	}
	hash, err := transport.DirectChannelMessageHashV2(parent)
	if err != nil {
		return nil, errDirect
	}
	h := directHeader{Version: 2, Domain: directDomain + "/message", Kind: "ASK", ChannelID: directChannelID(m.descriptor), DescriptorHash: directB64(m.hash[:]), EpochID: m.descriptor.EpochID, MessageID: id, RootID: parent.Header.RootID, SenderRole: "S", ParentMessageID: parent.Header.MessageID, ParentWireHash: hash}
	return m.sealHeader(h, plaintext)
}

// open requires caller-pinned IDs and the exact ASK for a REPLY. Replay and
// thread admission remain external to this private cryptographic helper.
func (m *directMaterial) open(kind, id, root string, ask, wire []byte, now time.Time) ([]byte, error) {
	if (kind == "ASK" && m.role != "P") || (kind == "REPLY" && m.role != "S") || transport.ValidateDirectChannelDescriptorV2(m.descriptor, now) != nil {
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
	} else if kind != "ASK" || len(ask) != 0 {
		return nil, errDirect
	}
	aead, err := m.aead(kind)
	if err != nil {
		return nil, err
	}
	nonce, _ := directBinary(w.Nonce, 12)
	ct, _ := directBinary(w.Ciphertext, -1)
	aad, _ := w.Header.CanonicalBytes()
	return aead.Open(nil, nonce, ct, aad)
}
