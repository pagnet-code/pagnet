package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

const ownerTextProjectMessageInfo = "pagnet/owner-text-project/message/v1"
const ownerTextProjectMessageSuite = "HPKE-X25519-HKDF-SHA256-AES256GCM-Auth-v1"

// OwnerTextProjectMessageHeader is the canonical AuthHPKE AAD. Field order is
// part of the owner text protocol; correlationId is null for a root ASK.
type OwnerTextProjectMessageHeader struct {
	Version              int     `json:"version"`
	Domain               string  `json:"domain"`
	ProjectID            string  `json:"projectId"`
	NetworkID            string  `json:"networkId"`
	PolicyHash           string  `json:"policyHash"`
	DescriptorHash       string  `json:"descriptorHash"`
	ID                   string  `json:"id"`
	ThreadID             string  `json:"threadId"`
	CorrelationID        *string `json:"correlationId"`
	Kind                 string  `json:"kind"`
	SenderPrincipalID    string  `json:"senderPrincipalId"`
	RecipientPrincipalID string  `json:"recipientPrincipalId"`
	CreatedAt            string  `json:"createdAt"`
}
type ownerTextProjectMessageEnvelope struct {
	Suite      string `json:"suite"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
}
type ownerTextProjectMessageWire struct {
	OwnerTextProjectMessageHeader
	Envelope ownerTextProjectMessageEnvelope `json:"envelope"`
}

// EncryptedOwnerTextProjectMessage contains canonical wire bytes and local
// evidence authenticating those exact bytes to the preparing identity. Retain
// ASK evidence to decrypt its REPLY. This API does not persist or reserve IDs;
// callers must allocate a fresh UUIDv7 and retain exact bytes for retries.
type EncryptedOwnerTextProjectMessage struct {
	ID            string
	Wire          []byte
	LocalEvidence []byte
}
type DecryptedOwnerTextProjectMessage struct {
	Header    OwnerTextProjectMessageHeader
	Plaintext []byte
}

func (c *Client) ownerTextMessageDescriptor(project string) (ownerTextProjectDescriptor, []byte, error) {
	var d ownerTextProjectDescriptor
	principal := c.principalID.Load()
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(principal, false) || !pairPrivateMatches(c.identityPriv, c.identityPub) {
		return d, nil, errors.New("sdk: invalid owner text message identity")
	}
	raw, err := readPrivatePairFile(filepath.Join(c.kr.root, principal, "owner-text-projects", project+".json"))
	if err != nil {
		return d, nil, err
	}
	if err = json.Unmarshal(raw, &d); err != nil {
		return d, nil, err
	}
	hash := sha256.Sum256(raw)
	status := OwnerTextProjectStatus{ProjectID: project, NetworkID: d.NetworkID, Descriptor: raw, DescriptorHash: hash[:], RosterSize: len(d.Roster)}
	installation := ""
	for _, member := range d.Roster {
		status.Roles = append(status.Roles, OwnerTextProjectRoleStatus{Role: member.Role, PrincipalID: member.PrincipalID, InstallationID: member.InstallationID})
		if member.PrincipalID == principal {
			installation = member.InstallationID
		}
	}
	if err = validateOwnerTextProjectDescriptor(status, project, principal, installation, c.identityPub, "", time.Now()); err != nil {
		return d, nil, err
	}
	return d, hash[:], nil
}
func ownerTextRosterKey(d ownerTextProjectDescriptor, principal string) ([]byte, error) {
	for _, member := range d.Roster {
		if member.PrincipalID == principal {
			return base64.StdEncoding.DecodeString(member.PublicKey)
		}
	}
	return nil, errors.New("sdk: owner text principal outside roster")
}
func parseOwnerTextProjectMessage(raw []byte, d ownerTextProjectDescriptor, hash []byte) (ownerTextProjectMessageWire, []byte, []byte, error) {
	var w ownerTextProjectMessageWire
	invalid := errors.New("sdk: invalid owner text message wire")
	if len(raw) == 0 || len(raw) > d.Limits.MaxMessageWireBytes || json.Unmarshal(raw, &w) != nil {
		return w, nil, nil, invalid
	}
	canonical, _ := json.Marshal(w)
	created, err := time.Parse(time.RFC3339Nano, w.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !bytes.Equal(raw, canonical) || w.Version != 1 || w.Domain != ownerTextProjectMessageInfo || w.ProjectID != d.ProjectID || w.NetworkID != d.NetworkID || w.PolicyHash != d.PolicyHash || w.DescriptorHash != hex.EncodeToString(hash) || !projectUUID(w.ID, true) || !projectUUID(w.ThreadID, true) || err != nil || created.UTC().Format(time.RFC3339Nano) != w.CreatedAt || !created.Before(expires) || w.Envelope.Suite != ownerTextProjectMessageSuite {
		return w, nil, nil, invalid
	}
	switch w.Kind {
	case "ASK":
		if w.SenderPrincipalID != d.Roster[0].PrincipalID || w.RecipientPrincipalID != d.Roster[1].PrincipalID || w.ThreadID != w.ID || w.CorrelationID != nil {
			return w, nil, nil, invalid
		}
	case "REPLY":
		if w.SenderPrincipalID != d.Roster[1].PrincipalID || w.RecipientPrincipalID != d.Roster[0].PrincipalID || w.CorrelationID == nil || !projectUUID(*w.CorrelationID, true) || *w.CorrelationID != w.ThreadID || w.ID == w.ThreadID {
			return w, nil, nil, invalid
		}
	default:
		return w, nil, nil, invalid
	}
	enc, err := base64.RawURLEncoding.Strict().DecodeString(w.Envelope.Enc)
	if err != nil || len(enc) != 32 || base64.RawURLEncoding.EncodeToString(enc) != w.Envelope.Enc {
		return w, nil, nil, invalid
	}
	ct, err := base64.RawURLEncoding.Strict().DecodeString(w.Envelope.Ciphertext)
	if err != nil || len(ct) < 16 || base64.RawURLEncoding.EncodeToString(ct) != w.Envelope.Ciphertext {
		return w, nil, nil, invalid
	}
	return w, enc, ct, nil
}
func (c *Client) unwrapOwnerTextMessage(w ownerTextProjectMessageWire, d ownerTextProjectDescriptor, enc, ct []byte) ([]byte, error) {
	if w.RecipientPrincipalID != c.principalID.Load() {
		return nil, errors.New("sdk: owner text message addressed to another principal")
	}
	sender, err := ownerTextRosterKey(d, w.SenderPrincipalID)
	if err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(w.OwnerTextProjectMessageHeader)
	return e2ee.HPKEUnwrapAuth(c.identityPriv, sender, enc, []byte(ownerTextProjectMessageInfo), aad, ct)
}
func validateOwnerTextReply(w, ask ownerTextProjectMessageWire) error {
	created, _ := time.Parse(time.RFC3339Nano, w.CreatedAt)
	prior, _ := time.Parse(time.RFC3339Nano, ask.CreatedAt)
	if ask.Kind != "ASK" || w.Kind != "REPLY" || w.CorrelationID == nil || *w.CorrelationID != ask.ID || w.ThreadID != ask.ID || w.SenderPrincipalID != ask.RecipientPrincipalID || w.RecipientPrincipalID != ask.SenderPrincipalID || created.Before(prior) {
		return errors.New("sdk: owner text reply root ASK binding mismatch")
	}
	return nil
}
func (c *Client) ownerTextMessageEvidence(wire []byte) []byte {
	mac := hmac.New(sha256.New, c.identityPriv)
	mac.Write([]byte("pagnet/owner-text-project/local-message-evidence/v1\x00"))
	mac.Write(wire)
	return mac.Sum(nil)
}

// EncryptOwnerTextProjectMessage encrypts using an explicit fresh UUIDv7. A
// REPLY requires the root ASK wire, authenticated with the pinned sender key.
func (c *Client) EncryptOwnerTextProjectMessage(project, recipient, kind, id string, plaintext, predecessorWire []byte) (EncryptedOwnerTextProjectMessage, error) {
	result := EncryptedOwnerTextProjectMessage{ID: id}
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	if !projectUUID(id, true) || len(plaintext) > d.Limits.MaxMessageWireBytes {
		return result, errors.New("sdk: invalid owner text message ID or size")
	}
	key, err := ownerTextRosterKey(d, recipient)
	if err != nil {
		return result, err
	}
	w := ownerTextProjectMessageWire{OwnerTextProjectMessageHeader: OwnerTextProjectMessageHeader{Version: 1, Domain: ownerTextProjectMessageInfo, ProjectID: project, NetworkID: d.NetworkID, PolicyHash: d.PolicyHash, DescriptorHash: hex.EncodeToString(hash), ID: id, ThreadID: id, Kind: kind, SenderPrincipalID: c.principalID.Load(), RecipientPrincipalID: recipient, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	if kind == "REPLY" {
		ask, enc, ct, err := parseOwnerTextProjectMessage(predecessorWire, d, hash)
		if err != nil {
			return result, err
		}
		if _, err = c.unwrapOwnerTextMessage(ask, d, enc, ct); err != nil {
			return result, err
		}
		w.ThreadID, w.CorrelationID = ask.ID, &ask.ID
		if err = validateOwnerTextReply(w, ask); err != nil {
			return result, err
		}
	} else if kind != "ASK" || len(predecessorWire) != 0 {
		return result, errors.New("sdk: invalid owner text message kind or predecessor")
	}
	// Validate direction and all header fields before encrypting.
	w.Envelope = ownerTextProjectMessageEnvelope{ownerTextProjectMessageSuite, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	raw, _ := json.Marshal(w)
	if _, _, _, err = parseOwnerTextProjectMessage(raw, d, hash); err != nil {
		return result, err
	}
	aad, _ := json.Marshal(w.OwnerTextProjectMessageHeader)
	enc, ct, err := e2ee.HPKEWrapAuth(key, c.identityPriv, []byte(ownerTextProjectMessageInfo), aad, plaintext)
	if err != nil {
		return result, err
	}
	w.Envelope = ownerTextProjectMessageEnvelope{ownerTextProjectMessageSuite, base64.RawURLEncoding.EncodeToString(enc), base64.RawURLEncoding.EncodeToString(ct)}
	raw, _ = json.Marshal(w)
	if _, _, _, err = parseOwnerTextProjectMessage(raw, d, hash); err != nil {
		return result, err
	}
	result.Wire, result.LocalEvidence = raw, c.ownerTextMessageEvidence(raw)
	return result, nil
}

// DecryptOwnerTextProjectMessage requires the original root ASK and its local
// evidence when opening a REPLY. Arbitrary caller-supplied predecessor bytes do
// not authenticate a locally sent ASK. ASK messages require neither argument.
func (c *Client) DecryptOwnerTextProjectMessage(project string, wire, predecessorWire, predecessorEvidence []byte) (DecryptedOwnerTextProjectMessage, error) {
	var result DecryptedOwnerTextProjectMessage
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	w, enc, ct, err := parseOwnerTextProjectMessage(wire, d, hash)
	if err != nil {
		return result, err
	}
	if w.Kind == "REPLY" {
		if !hmac.Equal(predecessorEvidence, c.ownerTextMessageEvidence(predecessorWire)) {
			return result, errors.New("sdk: unauthenticated owner text predecessor")
		}
		ask, _, _, err := parseOwnerTextProjectMessage(predecessorWire, d, hash)
		if err != nil {
			return result, err
		}
		if ask.SenderPrincipalID != c.principalID.Load() {
			return result, errors.New("sdk: owner text predecessor belongs to another sender")
		}
		if err = validateOwnerTextReply(w, ask); err != nil {
			return result, err
		}
	} else if len(predecessorWire) != 0 || len(predecessorEvidence) != 0 {
		return result, errors.New("sdk: root owner text message has predecessor")
	}
	result.Plaintext, err = c.unwrapOwnerTextMessage(w, d, enc, ct)
	if err != nil {
		return result, err
	}
	result.Header = w.OwnerTextProjectMessageHeader
	return result, nil
}
