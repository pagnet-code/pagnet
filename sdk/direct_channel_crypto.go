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

type directHeader struct {
	Domain         string      `json:"domain"`
	Kind           string      `json:"kind"`
	ChannelID      string      `json:"channelId"`
	DescriptorHash string      `json:"descriptorHash"`
	MessageID      string      `json:"messageId"`
	RootID         string      `json:"rootId"`
	From           directParty `json:"from"`
	To             directParty `json:"to"`
	AskID          string      `json:"askId"`
	AskWireHash    string      `json:"askWireHash"`
}
type directWire struct {
	Header     directHeader `json:"header"`
	Nonce      string       `json:"nonce"`
	Ciphertext string       `json:"ciphertext"`
}

func (m *directMaterial) header(kind, id, root string, ask []byte) (directHeader, error) {
	d := m.descriptor
	h := directHeader{Domain: directDomain + "/message", Kind: kind, ChannelID: directChannelID(d), DescriptorHash: directB64(m.hash[:]), MessageID: id, RootID: root, From: d.S, To: d.P}
	if !validPairPathID(id) || !validPairPathID(root) {
		return h, errDirect
	}
	if kind == "REPLY" {
		var a directWire
		if directCanonical(ask, &a, d.Limits.MaxMessageWireBytes) != nil || a.Header.Kind != "ASK" || a.Header.RootID != root {
			return h, errDirect
		}
		expected, err := m.header("ASK", a.Header.MessageID, root, nil)
		if err != nil || a.Header != expected {
			return h, errDirect
		}
		if directWireBinary(a) != nil {
			return h, errDirect
		}
		hash := sha256.Sum256(ask)
		h.From = d.P
		h.To = d.S
		h.AskID = a.Header.MessageID
		h.AskWireHash = directB64(hash[:])
	} else if kind != "ASK" || len(ask) != 0 {
		return h, errDirect
	}
	return h, nil
}
func directWireBinary(w directWire) error {
	_, err := directBinary(w.Nonce, 12)
	ct, cerr := directBinary(w.Ciphertext, -1)
	if err != nil || cerr != nil || len(ct) < 16 {
		return errDirect
	}
	return nil
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
	if (kind == "ASK" && m.role != "S") || (kind == "REPLY" && m.role != "P") {
		return nil, errDirect
	}
	expiry, _ := time.Parse(time.RFC3339Nano, m.descriptor.ExpiresAt)
	if !expiry.After(now) {
		return nil, errDirect
	}
	h, err := m.header(kind, id, root, ask)
	if err != nil {
		return nil, err
	}
	if kind == "REPLY" {
		askPlaintext, err := m.open("ASK", h.AskID, root, nil, ask, now)
		clear(askPlaintext)
		if err != nil {
			return nil, err
		}
	}
	aead, err := m.aead(kind)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(h)
	ct := aead.Seal(nil, nonce, plaintext, aad)
	wire, err := json.Marshal(directWire{h, directB64(nonce), directB64(ct)})
	if len(wire) > m.descriptor.Limits.MaxMessageWireBytes {
		return nil, errDirect
	}
	return wire, err
}

// open requires caller-pinned message/root IDs and, for REPLY, the exact ASK
// wire. Replay/deduplication and one terminal reply are server/store constraints.
func (m *directMaterial) open(kind, id, root string, ask, wire []byte, now time.Time) ([]byte, error) {
	if (kind == "ASK" && m.role != "P") || (kind == "REPLY" && m.role != "S") {
		return nil, errDirect
	}
	expiry, _ := time.Parse(time.RFC3339Nano, m.descriptor.ExpiresAt)
	if !expiry.After(now) {
		return nil, errDirect
	}
	var w directWire
	if directCanonical(wire, &w, m.descriptor.Limits.MaxMessageWireBytes) != nil || directWireBinary(w) != nil {
		return nil, errDirect
	}
	expected, err := m.header(kind, id, root, ask)
	if err != nil || w.Header != expected {
		return nil, errDirect
	}
	aead, err := m.aead(kind)
	if err != nil {
		return nil, err
	}
	nonce, _ := directBinary(w.Nonce, 12)
	ct, _ := directBinary(w.Ciphertext, -1)
	aad, _ := json.Marshal(w.Header)
	return aead.Open(nil, nonce, ct, aad)
}
