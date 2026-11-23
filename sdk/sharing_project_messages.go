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

const sharingProjectMessageInfo = "pagnet/sdk-project/message/v2"
const sharingProjectMessageSuite = "HPKE-X25519-HKDF-SHA256-AES256GCM-Auth-v1"

// SharingProjectMessageHeader is the canonical AuthHPKE AAD. Field order is
// part of the protocol; correlationId is null for a root ASK.
type SharingProjectMessageHeader struct {
	Version              int     `json:"version"`
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
type sharingProjectMessageEnvelope struct {
	Suite      string `json:"suite"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
}
type sharingProjectMessageWire struct {
	SharingProjectMessageHeader
	Envelope sharingProjectMessageEnvelope `json:"envelope"`
}

// PreparedSharingProjectMessage is a durable immutable send candidate. Retry by
// loading its ID; preparing again creates a different logical message.
type PreparedSharingProjectMessage struct {
	ID   string
	Wire []byte
}

type DecryptedSharingProjectMessage struct {
	Header    SharingProjectMessageHeader
	Plaintext []byte
}

func projectUUID(id string, version7 bool) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.Variant() == uuid.RFC4122 && parsed.String() == id && (!version7 || parsed.Version() == 7)
}
func projectHexHash(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func projectRawURL(s string, size int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s || (size >= 0 && len(raw) != size) {
		return nil, errors.New("sdk: invalid project message encoding")
	}
	return raw, nil
}

func (c *Client) projectMessageDescriptor(project string) (sharingProjectDescriptor, []byte, error) {
	var d sharingProjectDescriptor
	principal := c.principalID.Load()
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(principal, false) {
		return d, nil, errors.New("sdk: invalid project message identity")
	}
	raw, err := readPrivatePairFile(filepath.Join(c.kr.root, principal, "sharing-projects", project+".json"))
	if err != nil {
		return d, nil, err
	}
	if err = json.Unmarshal(raw, &d); err != nil {
		return d, nil, err
	}
	hash := sha256.Sum256(raw)
	status := SharingProjectStatus{ProjectID: project, NetworkID: d.NetworkID, Descriptor: raw, DescriptorHash: hash[:], RosterSize: len(d.Roster)}
	if err = validateSharingProjectDescriptor(status, project, principal, c.identityPub, "", time.Now()); err != nil {
		return d, nil, err
	}
	if !pairPrivateMatches(c.identityPriv, c.identityPub) || !projectUUID(d.NetworkID, false) || !projectHexHash(d.PolicyHash) {
		return d, nil, errors.New("sdk: invalid project message descriptor identity")
	}
	for _, id := range []string{d.IssuerTenantID, d.IssuerUserID, d.RecipientTenantID, d.RecipientUserID} {
		if !projectUUID(id, false) {
			return d, nil, errors.New("sdk: invalid project descriptor owner UUID")
		}
	}
	for _, member := range d.Roster {
		if !projectUUID(member.PrincipalID, false) {
			return d, nil, errors.New("sdk: invalid project roster principal")
		}
	}
	return d, hash[:], nil
}
func projectRosterKey(d sharingProjectDescriptor, principal string) ([]byte, error) {
	for _, member := range d.Roster {
		if member.PrincipalID == principal {
			return base64.StdEncoding.DecodeString(member.PublicKey)
		}
	}
	return nil, errors.New("sdk: project message principal is outside roster")
}
func parseSharingProjectMessage(raw []byte, d sharingProjectDescriptor, hash []byte) (sharingProjectMessageWire, []byte, []byte, error) {
	var w sharingProjectMessageWire
	invalid := errors.New("sdk: invalid project message wire")
	if len(raw) == 0 || len(raw) > d.Limits.MaxMessageWireBytes || json.Unmarshal(raw, &w) != nil {
		return w, nil, nil, invalid
	}
	canonical, _ := json.Marshal(w)
	created, err := time.Parse(time.RFC3339Nano, w.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !bytes.Equal(canonical, raw) || w.Version != 2 || w.ProjectID != d.ProjectID || w.NetworkID != d.NetworkID || w.PolicyHash != d.PolicyHash || w.DescriptorHash != hex.EncodeToString(hash) || !projectHexHash(w.DescriptorHash) || !projectUUID(w.ID, true) || !projectUUID(w.ThreadID, true) || !projectUUID(w.SenderPrincipalID, false) || !projectUUID(w.RecipientPrincipalID, false) || w.SenderPrincipalID == w.RecipientPrincipalID || err != nil || created.UTC().Format(time.RFC3339Nano) != w.CreatedAt || !created.Before(expires) || w.Envelope.Suite != sharingProjectMessageSuite {
		return w, nil, nil, invalid
	}
	if _, err = projectRosterKey(d, w.SenderPrincipalID); err != nil {
		return w, nil, nil, err
	}
	if _, err = projectRosterKey(d, w.RecipientPrincipalID); err != nil {
		return w, nil, nil, err
	}
	switch w.Kind {
	case "ASK":
		if w.ThreadID != w.ID || w.CorrelationID != nil {
			return w, nil, nil, invalid
		}
	case "REPLY":
		if w.CorrelationID == nil || !projectUUID(*w.CorrelationID, true) || *w.CorrelationID == w.ID || w.ThreadID == w.ID {
			return w, nil, nil, invalid
		}
	default:
		return w, nil, nil, invalid
	}
	enc, err := projectRawURL(w.Envelope.Enc, 32)
	if err != nil {
		return w, nil, nil, err
	}
	ct, err := projectRawURL(w.Envelope.Ciphertext, -1)
	if err != nil || len(ct) < 16 {
		return w, nil, nil, invalid
	}
	return w, enc, ct, nil
}
func (c *Client) unwrapProjectMessage(w sharingProjectMessageWire, d sharingProjectDescriptor, enc, ct []byte) ([]byte, error) {
	if w.RecipientPrincipalID != c.principalID.Load() {
		return nil, errors.New("sdk: project message addressed to another principal")
	}
	sender, err := projectRosterKey(d, w.SenderPrincipalID)
	if err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(w.SharingProjectMessageHeader)
	return e2ee.HPKEUnwrapAuth(c.identityPriv, sender, enc, []byte(sharingProjectMessageInfo), aad, ct)
}
func (c *Client) projectMessagePredecessor(raw []byte, d sharingProjectDescriptor, hash []byte) (sharingProjectMessageWire, error) {
	w, enc, ct, err := parseSharingProjectMessage(raw, d, hash)
	if err != nil {
		return w, err
	}
	if w.RecipientPrincipalID == c.principalID.Load() {
		_, err = c.unwrapProjectMessage(w, d, enc, ct)
	} else if w.SenderPrincipalID == c.principalID.Load() {
		record, readErr := c.kr.loadProjectMessageBinding(c.principalID.Load(), c.identityPriv, w.ID)
		err = readErr
		if err == nil {
			digest := sha256.Sum256(raw)
			header, _ := json.Marshal(w.SharingProjectMessageHeader)
			saved, _ := json.Marshal(record.Reservation.Header)
			if record.WireDigest != hex.EncodeToString(digest[:]) || !bytes.Equal(header, saved) {
				err = errors.New("sdk: project predecessor differs from authenticated spool")
			}
		}
	} else {
		err = errors.New("sdk: project predecessor belongs to other principals")
	}
	return w, err
}
func validateProjectReply(w, previous sharingProjectMessageWire) error {
	if w.CorrelationID == nil || *w.CorrelationID != previous.ID || w.ThreadID != previous.ThreadID || w.SenderPrincipalID != previous.RecipientPrincipalID || w.RecipientPrincipalID != previous.SenderPrincipalID {
		return errors.New("sdk: project reply thread binding mismatch")
	}
	created, _ := time.Parse(time.RFC3339Nano, w.CreatedAt)
	prior, _ := time.Parse(time.RFC3339Nano, previous.CreatedAt)
	if created.Before(prior) {
		return errors.New("sdk: project reply predates predecessor")
	}
	return nil
}

// PrepareSharingProjectMessage reserves a new UUIDv7 before encryption and
// durably stores the exact canonical wire. An error can return a reserved ID;
// a reservation without wire is unresolved and must never be reencrypted.
func (c *Client) PrepareSharingProjectMessage(project, recipient, kind string, plaintext, predecessorWire []byte) (PreparedSharingProjectMessage, error) {
	return c.prepareSharingProjectMessage(project, recipient, kind, "", plaintext, predecessorWire)
}

// PrepareSharingProjectMessageWithID prepares a message with the caller's strict,
// canonical UUIDv7 ID. The ID follows kind and precedes the plaintext and
// predecessor wire. It is returned on every error for reconciliation with
// LoadPreparedSharingProjectMessage. An ID is durably reserved before encryption
// and cannot be prepared again, even when its reservation has no wire.
func (c *Client) PrepareSharingProjectMessageWithID(project, recipient, kind, id string, plaintext, predecessorWire []byte) (PreparedSharingProjectMessage, error) {
	if !projectUUID(id, true) {
		return PreparedSharingProjectMessage{ID: id}, errors.New("sdk: invalid project message ID")
	}
	return c.prepareSharingProjectMessage(project, recipient, kind, id, plaintext, predecessorWire)
}

func (c *Client) prepareSharingProjectMessage(project, recipient, kind, id string, plaintext, predecessorWire []byte) (PreparedSharingProjectMessage, error) {
	result := PreparedSharingProjectMessage{ID: id}
	d, hash, err := c.projectMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	if recipient == c.principalID.Load() {
		return result, errors.New("sdk: project message requires another recipient")
	}
	recipientKey, err := projectRosterKey(d, recipient)
	if err != nil {
		return result, err
	}
	if len(plaintext) > d.Limits.MaxMessageWireBytes {
		return result, errors.New("sdk: project plaintext exceeds wire limit")
	}
	if result.ID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return result, err
		}
		result.ID = generated.String()
	}
	w := sharingProjectMessageWire{SharingProjectMessageHeader: SharingProjectMessageHeader{Version: 2, ProjectID: project, NetworkID: d.NetworkID, PolicyHash: d.PolicyHash, DescriptorHash: hex.EncodeToString(hash), ID: result.ID, ThreadID: result.ID, Kind: kind, SenderPrincipalID: c.principalID.Load(), RecipientPrincipalID: recipient, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	if kind == "REPLY" {
		previous, err := c.projectMessagePredecessor(predecessorWire, d, hash)
		if err != nil {
			return result, err
		}
		w.ThreadID, w.CorrelationID = previous.ThreadID, &previous.ID
		if err = validateProjectReply(w, previous); err != nil {
			return result, err
		}
	} else if kind != "ASK" || len(predecessorWire) != 0 {
		return result, errors.New("sdk: invalid project message kind or predecessor")
	}
	aad, _ := json.Marshal(w.SharingProjectMessageHeader)
	input := sha256.New()
	input.Write(aad)
	input.Write(plaintext)
	binding := projectMessageReservation{Header: w.SharingProjectMessageHeader, InputDigest: hex.EncodeToString(input.Sum(nil)), ExpiresAt: d.ExpiresAt}
	if err = c.kr.reserveProjectMessage(c.principalID.Load(), c.identityPriv, binding); err != nil {
		return result, err
	}
	enc, ct, err := e2ee.HPKEWrapAuth(recipientKey, c.identityPriv, []byte(sharingProjectMessageInfo), aad, plaintext)
	if err != nil {
		return result, err
	}
	w.Envelope = sharingProjectMessageEnvelope{sharingProjectMessageSuite, base64.RawURLEncoding.EncodeToString(enc), base64.RawURLEncoding.EncodeToString(ct)}
	wire, _ := json.Marshal(w)
	if _, _, _, err = parseSharingProjectMessage(wire, d, hash); err != nil {
		return result, err
	}
	if err = c.kr.storeProjectMessage(c.principalID.Load(), c.identityPriv, binding, wire); err != nil {
		return result, err
	}
	result.Wire = wire
	return result, nil
}

func (c *Client) LoadPreparedSharingProjectMessage(project, id string) (PreparedSharingProjectMessage, error) {
	result := PreparedSharingProjectMessage{ID: id}
	if c.kr == nil || !projectUUID(project, false) || !projectUUID(c.principalID.Load(), false) {
		return result, errors.New("sdk: invalid project message identity")
	}
	if !projectUUID(id, true) {
		return result, errors.New("sdk: invalid prepared project message ID")
	}
	record, err := c.kr.loadProjectMessage(c.principalID.Load(), c.identityPriv, id)
	if err != nil {
		return result, err
	}
	d, hash, err := c.projectMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	w, _, _, err := parseSharingProjectMessage(record.Wire, d, hash)
	if err != nil {
		return result, err
	}
	header, _ := json.Marshal(w.SharingProjectMessageHeader)
	reserved, _ := json.Marshal(record.Reservation.Header)
	if !bytes.Equal(header, reserved) || w.SenderPrincipalID != c.principalID.Load() {
		return result, errors.New("sdk: prepared project message binding mismatch")
	}
	result.Wire = record.Wire
	return result, nil
}

func (c *Client) DecryptSharingProjectMessage(project string, wire, predecessorWire []byte) (DecryptedSharingProjectMessage, error) {
	var result DecryptedSharingProjectMessage
	d, hash, err := c.projectMessageDescriptor(project)
	if err != nil {
		return result, err
	}
	w, enc, ct, err := parseSharingProjectMessage(wire, d, hash)
	if err != nil {
		return result, err
	}
	if w.Kind == "REPLY" {
		var previous sharingProjectMessageWire
		if len(predecessorWire) == 0 && w.CorrelationID != nil {
			record, loadErr := c.kr.loadProjectMessageBinding(c.principalID.Load(), c.identityPriv, *w.CorrelationID)
			if loadErr != nil {
				return result, loadErr
			}
			if record.Reservation.Header.ProjectID != project || record.Reservation.Header.DescriptorHash != hex.EncodeToString(hash) {
				return result, errors.New("sdk: predecessor project binding mismatch")
			}
			previous.SharingProjectMessageHeader = record.Reservation.Header
		} else {
			previous, err = c.projectMessagePredecessor(predecessorWire, d, hash)
		}
		if err != nil {
			return result, err
		}
		if err = validateProjectReply(w, previous); err != nil {
			return result, err
		}
	} else if len(predecessorWire) != 0 {
		return result, errors.New("sdk: root project message has predecessor")
	}
	plaintext, err := c.unwrapProjectMessage(w, d, enc, ct)
	if err != nil {
		return result, err
	}
	result.Header, result.Plaintext = w.SharingProjectMessageHeader, plaintext
	return result, nil
}

// A domain-separated MAC authenticates local reservations and exact wire bytes
// with the persisted SDK identity. No plaintext or epoch key is stored.
func projectMessageMAC(private, data []byte) []byte {
	mac := hmac.New(sha256.New, private)
	mac.Write([]byte("pagnet/sdk-project/spool/v2\x00"))
	mac.Write(data)
	return mac.Sum(nil)
}
