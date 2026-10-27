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

	"github.com/google/uuid"
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

// PreparedOwnerTextProjectMessage contains immutable canonical wire bytes and
// local evidence authenticating those exact bytes to the preparing identity.
// Preparation reserves the ID durably before encryption; retry by loading it.
type PreparedOwnerTextProjectMessage struct {
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
func ownerTextProjectLocalEvidence(private, wire []byte) []byte {
	mac := hmac.New(sha256.New, private)
	mac.Write([]byte("pagnet/owner-text-project/local-message-evidence/v1\x00"))
	mac.Write(wire)
	return mac.Sum(nil)
}

// PrepareOwnerTextProjectMessage reserves a new UUIDv7 before encryption and
// durably stores the canonical wire. An error may return a reserved ID; a
// reservation without wire is unresolved and must never be reencrypted.
func (c *Client) PrepareOwnerTextProjectMessage(project, recipient, kind string, plaintext, predecessorWire []byte) (PreparedOwnerTextProjectMessage, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return PreparedOwnerTextProjectMessage{}, err
	}
	return c.PrepareOwnerTextProjectMessageWithID(project, recipient, kind, id.String(), plaintext, predecessorWire)
}

// PrepareOwnerTextProjectMessageWithID reserves an explicit strict UUIDv7. The
// ID is returned on every error for reconciliation with LoadPreparedOwnerTextProjectMessage.
// A reserved ID cannot be prepared again, even when its reservation has no wire.
func (c *Client) PrepareOwnerTextProjectMessageWithID(project, recipient, kind, id string, plaintext, predecessorWire []byte) (PreparedOwnerTextProjectMessage, error) {
	result := PreparedOwnerTextProjectMessage{ID: id}
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
	input := sha256.New()
	input.Write(aad)
	input.Write(plaintext)
	reservation := ownerTextProjectMessageReservation{Header: w.OwnerTextProjectMessageHeader, InputDigest: hex.EncodeToString(input.Sum(nil)), ExpiresAt: d.ExpiresAt}
	if err = c.kr.reserveOwnerTextProjectMessage(c.principalID.Load(), c.identityPriv, reservation); err != nil {
		return result, err
	}
	enc, ct, err := e2ee.HPKEWrapAuth(key, c.identityPriv, []byte(ownerTextProjectMessageInfo), aad, plaintext)
	if err != nil {
		return result, err
	}
	w.Envelope = ownerTextProjectMessageEnvelope{ownerTextProjectMessageSuite, base64.RawURLEncoding.EncodeToString(enc), base64.RawURLEncoding.EncodeToString(ct)}
	raw, _ = json.Marshal(w)
	if _, _, _, err = parseOwnerTextProjectMessage(raw, d, hash); err != nil {
		return result, err
	}
	evidence := ownerTextProjectLocalEvidence(c.identityPriv, raw)
	if err = c.kr.storeOwnerTextProjectMessage(c.principalID.Load(), c.identityPriv, reservation, raw, evidence); err != nil {
		return result, err
	}
	result.Wire, result.LocalEvidence = raw, evidence
	return result, nil
}

// DecryptOwnerTextProjectMessage authenticates REPLY predecessors using either
// a durable local ASK binding (when both predecessor arguments are absent) or
// exact original ASK wire and its local evidence. ASK requires neither argument.
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
		var ask ownerTextProjectMessageWire
		if len(predecessorWire) == 0 && len(predecessorEvidence) == 0 {
			record, loadErr := c.kr.loadOwnerTextProjectMessageBinding(c.principalID.Load(), c.identityPriv, *w.CorrelationID)
			if loadErr != nil {
				return result, loadErr
			}
			if record.Reservation.Header.ProjectID != project || record.Reservation.Header.DescriptorHash != hex.EncodeToString(hash) {
				return result, errors.New("sdk: owner text predecessor project binding mismatch")
			}
			ask.OwnerTextProjectMessageHeader = record.Reservation.Header
		} else {
			if !hmac.Equal(predecessorEvidence, ownerTextProjectLocalEvidence(c.identityPriv, predecessorWire)) {
				return result, errors.New("sdk: unauthenticated owner text predecessor")
			}
			ask, _, _, err = parseOwnerTextProjectMessage(predecessorWire, d, hash)
			if err != nil {
				return result, err
			}
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

// LoadPreparedOwnerTextProjectMessage returns the exact persisted retry wire.
// Reserved, admitted and abandoned messages cannot be loaded for retry.
func (c *Client) LoadPreparedOwnerTextProjectMessage(project, id string) (PreparedOwnerTextProjectMessage, error) {
	result := PreparedOwnerTextProjectMessage{ID: id}
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(id, true) || !projectUUID(c.principalID.Load(), false) {
		return result, errors.New("sdk: invalid owner text prepared message identity")
	}
	record, err := c.kr.loadOwnerTextProjectMessage(c.principalID.Load(), c.identityPriv, id)
	if err != nil {
		return result, err
	}
	d, hash, err := c.ownerTextMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	w, _, _, err := parseOwnerTextProjectMessage(record.Wire, d, hash)
	if err != nil {
		return result, err
	}
	header, _ := json.Marshal(w.OwnerTextProjectMessageHeader)
	reserved, _ := json.Marshal(record.Reservation.Header)
	if !bytes.Equal(header, reserved) || w.SenderPrincipalID != c.principalID.Load() || record.Reservation.ExpiresAt != d.ExpiresAt {
		return result, errors.New("sdk: owner text prepared message binding mismatch")
	}
	result.Wire, result.LocalEvidence = record.Wire, record.LocalEvidence
	return result, nil
}
