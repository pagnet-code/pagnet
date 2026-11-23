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
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
)

const directDomain = "pagnet/direct_ask_reply_v1"

var errDirect = errors.New("sdk: invalid direct channel context or wire")

// These pure internal types deliberately have no transport or persistence hooks.
// Struct field order is the canonical JSON order; decoders require byte equality
// with re-encoding, rejecting duplicate/unknown fields and alternate encodings.
type directParty struct {
	TenantID    string `json:"tenantId"`
	PrincipalID string `json:"principalId"`
	EndpointID  string `json:"endpointId"`
	PublicKey   string `json:"publicKey"`
}
type directLimits struct {
	MaxMessageWireBytes int `json:"maxMessageWireBytes"`
	MaxAsksPerMinute    int `json:"maxAsksPerMinute"`
	MaxAsksPerDay       int `json:"maxAsksPerDay"`
	MaxWireBytesPerDay  int `json:"maxWireBytesPerDay"`
	MaxInFlight         int `json:"maxInFlight"`
}
type directDescriptor struct {
	Domain        string       `json:"domain"`
	Suite         string       `json:"suite"`
	ParentGrantID string       `json:"parentGrantId"`
	Generation    string       `json:"generation"`
	NetworkID     string       `json:"networkId"`
	S             directParty  `json:"s"`
	P             directParty  `json:"p"`
	EpochID       string       `json:"epochId"`
	ExpiresAt     string       `json:"expiresAt"`
	Limits        directLimits `json:"limits"`
}

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
func directPartyValid(p directParty) bool {
	_, err := directBinary(p.PublicKey, 32)
	return err == nil && validPairPathID(p.TenantID) && validPairPathID(p.PrincipalID) && validPairPathID(p.EndpointID)
}
func directValidate(raw []byte, expected directDescriptor, now time.Time) (directDescriptor, error) {
	var d directDescriptor
	if directCanonical(raw, &d, 4096) != nil {
		return d, errDirect
	}
	trusted, _ := json.Marshal(expected)
	generation, err := strconv.ParseUint(d.Generation, 10, 64)
	epoch, eerr := uuid.Parse(d.EpochID)
	expiry, terr := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	l := d.Limits
	if !bytes.Equal(raw, trusted) || d.Domain != directDomain || d.Suite != pairSuite || err != nil || generation == 0 || strconv.FormatUint(generation, 10) != d.Generation || eerr != nil || epoch.Version() != 7 || epoch.String() != d.EpochID || terr != nil || expiry.UTC().Format(time.RFC3339Nano) != d.ExpiresAt || !expiry.After(now) || !validPairPathID(d.ParentGrantID) || !validPairPathID(d.NetworkID) || !directPartyValid(d.S) || !directPartyValid(d.P) || d.S.PrincipalID == d.P.PrincipalID || d.S.PublicKey == d.P.PublicKey || l.MaxMessageWireBytes < 1024 || l.MaxMessageWireBytes > 65536 || l.MaxAsksPerMinute < 1 || l.MaxAsksPerMinute > 10 || l.MaxAsksPerDay < 1 || l.MaxAsksPerDay > 200 || l.MaxWireBytesPerDay < l.MaxMessageWireBytes || l.MaxWireBytesPerDay > 8388608 || l.MaxInFlight < 1 || l.MaxInFlight > 2 {
		return d, errDirect
	}
	return d, nil
}

// Channel identity excludes mutable policy fields, but every cryptographic
// operation additionally binds the hash of the complete immutable descriptor.
func directChannelID(d directDescriptor) string {
	identity := struct {
		Domain        string      `json:"domain"`
		ParentGrantID string      `json:"parentGrantId"`
		Generation    string      `json:"generation"`
		S             directParty `json:"s"`
		P             directParty `json:"p"`
		EpochID       string      `json:"epochId"`
	}{directDomain + "/channel-id", d.ParentGrantID, d.Generation, d.S, d.P, d.EpochID}
	raw, _ := json.Marshal(identity)
	hash := sha256.Sum256(raw)
	return directB64(hash[:])
}

type directPackage struct {
	Descriptor json.RawMessage `json:"descriptor"`
	Enc        string          `json:"enc"`
	Ciphertext string          `json:"ciphertext"`
}

// directMaterial is local-only and must never be serialized to N. Only
// readinessKey() is suitable for server publication, alongside directPackage.
type directMaterial struct {
	descriptor directDescriptor
	hash       [32]byte
	key        [32]byte
	role       string
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
	if _, err = rand.Read(key); err != nil {
		return nil, nil, err
	}
	m, _ := directMaterialFor(d, raw, key, "S")
	enc, ct, err := e2ee.HPKEWrapAuth(recipient, private, []byte(directDomain+"/epoch-wrap"), m.hash[:], key)
	if err != nil {
		return nil, nil, err
	}
	wire, err := json.Marshal(directPackage{append(json.RawMessage(nil), raw...), directB64(enc), directB64(ct)})
	return m, wire, err
}
func directAccept(wire []byte, expected directDescriptor, private []byte, now time.Time) (*directMaterial, error) {
	var p directPackage
	if directCanonical(wire, &p, 8192) != nil {
		return nil, errDirect
	}
	d, err := directValidate(p.Descriptor, expected, now)
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
	hash := sha256.Sum256(p.Descriptor)
	key, err := e2ee.HPKEUnwrapAuth(private, sender, enc, []byte(directDomain+"/epoch-wrap"), hash[:], ct)
	if err != nil {
		return nil, err
	}
	return directMaterialFor(d, p.Descriptor, key, "P")
}
func (m *directMaterial) derive(purpose string) ([]byte, error) {
	return hkdf.Key(sha256.New, m.key[:], m.hash[:], directDomain+"/"+purpose, 32)
}
func (m *directMaterial) readinessKey() ([]byte, error) { return m.derive("readiness") }

type directProofTranscript struct {
	Domain         string `json:"domain"`
	ChallengeID    string `json:"challengeId"`
	Role           string `json:"role"`
	PrincipalID    string `json:"principalId"`
	EndpointID     string `json:"endpointId"`
	CredentialID   string `json:"credentialId"`
	ChannelID      string `json:"channelId"`
	ParentGrantID  string `json:"parentGrantId"`
	Generation     string `json:"generation"`
	DescriptorHash string `json:"descriptorHash"`
	EpochID        string `json:"epochId"`
	Nonce          string `json:"nonce"`
}
type directChallenge struct {
	ID         string
	Transcript []byte
	ExpiresAt  time.Time
}

// CredentialID must come from the caller's authenticated credential metadata.
// No interpretation of credential IDs or server challenge issuance occurs here.
func (m *directMaterial) readinessProof(challenge directChallenge, credentialID string, now time.Time) ([]byte, error) {
	var t directProofTranscript
	if directCanonical(challenge.Transcript, &t, 4096) != nil {
		return nil, errDirect
	}
	d := m.descriptor
	party := d.S
	if m.role == "P" {
		party = d.P
	}
	_, err := directBinary(t.Nonce, 32)
	expiry, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if err != nil || !expiry.After(now) || !challenge.ExpiresAt.After(now) || !validPairPathID(challenge.ID) || !validPairPathID(credentialID) || t.Domain != directDomain+"/proof" || t.ChallengeID != challenge.ID || t.Role != m.role || t.PrincipalID != party.PrincipalID || t.EndpointID != party.EndpointID || t.CredentialID != credentialID || t.ChannelID != directChannelID(d) || t.ParentGrantID != d.ParentGrantID || t.Generation != d.Generation || t.DescriptorHash != directB64(m.hash[:]) || t.EpochID != d.EpochID {
		return nil, errDirect
	}
	key, err := m.readinessKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge.Transcript)
	return mac.Sum(nil), nil
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
		if _, err = m.open("ASK", h.AskID, root, nil, ask, now); err != nil {
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
