package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"
)

// These dormant contracts are not a live server API. They convey encrypted
// delivery evidence only; authenticated transport supplies credential authority.
const (
	DirectInboxPageMaxItemsV2        = 50
	DirectInboxPageMaxBytesV2        = 4 * 1024 * 1024
	directDeliveryMetadataMaxBytesV2 = 8192
)

// DirectDeliveryPartyV2 identifies the descriptor credential, not an assertion
// that a JSON sender possesses that credential.
type DirectDeliveryPartyV2 struct {
	Role         string `json:"role"`
	PrincipalID  string `json:"principalId"`
	EndpointID   string `json:"endpointId"`
	CredentialID string `json:"credentialId"`
}

type DirectDeliveryContextV2 struct {
	ChannelID       string `json:"channelId"`
	DescriptorHash  string `json:"descriptorHash"`
	PublicationHash string `json:"publicationHash"`
	ParentGrantID   string `json:"parentGrantId"`
	GrantGeneration string `json:"grantGeneration"`
}

type DirectMessageBindingV2 struct {
	Context   DirectDeliveryContextV2 `json:"context"`
	MessageID string                  `json:"messageId"`
	WireHash  string                  `json:"wireHash"`
	WireBytes int                     `json:"wireBytes"`
	Sender    DirectDeliveryPartyV2   `json:"sender"`
	Recipient DirectDeliveryPartyV2   `json:"recipient"`
}

type DirectMessageAdmissionReceiptV2 struct {
	Version        int                    `json:"version"`
	Domain         string                 `json:"domain"`
	Binding        DirectMessageBindingV2 `json:"binding"`
	AdmissionState string                 `json:"admissionState"`
	AdmittedAt     string                 `json:"admittedAt"`
	ExpiresAt      string                 `json:"expiresAt"`
}

// DirectInboxRequestV2 is a non-destructive read. Cursor is opaque; no cursor
// value or credential field grants authority, changes state, or sets deadlines.
type DirectInboxRequestV2 struct {
	Version   int                     `json:"version"`
	Domain    string                  `json:"domain"`
	Context   DirectDeliveryContextV2 `json:"context"`
	Recipient DirectDeliveryPartyV2   `json:"recipient"`
	Cursor    string                  `json:"cursor"`
	Limit     int                     `json:"limit"`
}

type DirectDeliveryV2 struct {
	Version       int                             `json:"version"`
	Domain        string                          `json:"domain"`
	Admission     DirectMessageAdmissionReceiptV2 `json:"admission"`
	DeliveryState string                          `json:"deliveryState"`
	TerminalAt    string                          `json:"terminalAt"`
	Wire          json.RawMessage                 `json:"wire"`
}

type DirectInboxPageV2 struct {
	Version    int                     `json:"version"`
	Domain     string                  `json:"domain"`
	Context    DirectDeliveryContextV2 `json:"context"`
	Recipient  DirectDeliveryPartyV2   `json:"recipient"`
	Deliveries []DirectDeliveryV2      `json:"deliveries"`
	NextCursor string                  `json:"nextCursor"`
}

type DirectMessageAckV2 struct {
	Version int                    `json:"version"`
	Domain  string                 `json:"domain"`
	Binding DirectMessageBindingV2 `json:"binding"`
}

type DirectMessageAckReceiptV2 struct {
	Version        int                    `json:"version"`
	Domain         string                 `json:"domain"`
	Binding        DirectMessageBindingV2 `json:"binding"`
	DeliveryState  string                 `json:"deliveryState"`
	AcknowledgedAt string                 `json:"acknowledgedAt"`
}

func directDeliveryDomain(version int, domain, suffix string) bool {
	return version == 2 && domain == DirectChannelDomainV2+"/delivery/"+suffix
}
func (p DirectDeliveryPartyV2) valid() bool {
	return (p.Role == "S" || p.Role == "P") && directV2ID(p.PrincipalID) && directV2ID(p.EndpointID) && directV2ID(p.CredentialID)
}
func (c DirectDeliveryContextV2) valid() bool {
	for _, digest := range []string{c.ChannelID, c.DescriptorHash, c.PublicationHash} {
		if _, ok := directV2Binary(digest, 32); !ok {
			return false
		}
	}
	return directV2ID(c.ParentGrantID) && directV2Decimal(c.GrantGeneration)
}
func (b DirectMessageBindingV2) valid() bool {
	_, ok := directV2Binary(b.WireHash, 32)
	return b.Context.valid() && directV2ID(b.MessageID) && ok && b.WireBytes > 0 && b.WireBytes <= DirectChannelMessageMaxBytesV2 && b.Sender.valid() && b.Recipient.valid() && b.Sender.Role != b.Recipient.Role
}
func directDeliveryCursor(s string) bool { return len(s) <= 1024 && utf8.ValidString(s) }
func (r DirectMessageAdmissionReceiptV2) CanonicalBytes() ([]byte, error) {
	admitted, aok := directV2Time(r.AdmittedAt)
	expires, eok := directV2Time(r.ExpiresAt)
	if !directDeliveryDomain(r.Version, r.Domain, "admission") || !r.Binding.valid() || r.AdmissionState != "admitted" || !aok || !eok || !expires.After(admitted) {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(r, directDeliveryMetadataMaxBytesV2)
}
func (r DirectInboxRequestV2) CanonicalBytes() ([]byte, error) {
	if !directDeliveryDomain(r.Version, r.Domain, "inbox-request") || !r.Context.valid() || !r.Recipient.valid() || !directDeliveryCursor(r.Cursor) || r.Limit < 1 || r.Limit > DirectInboxPageMaxItemsV2 {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(r, directDeliveryMetadataMaxBytesV2)
}
func (d DirectDeliveryV2) CanonicalBytes() ([]byte, error) {
	if !directDeliveryDomain(d.Version, d.Domain, "item") {
		return nil, errDirectChannelV2
	}
	if _, err := d.Admission.CanonicalBytes(); err != nil {
		return nil, err
	}
	admitted, _ := directV2Time(d.Admission.AdmittedAt)
	expires, _ := directV2Time(d.Admission.ExpiresAt)
	if d.DeliveryState == "pending" {
		if d.TerminalAt != "" {
			return nil, errDirectChannelV2
		}
	} else {
		terminal, ok := directV2Time(d.TerminalAt)
		if !ok || terminal.Before(admitted) {
			return nil, errDirectChannelV2
		}
		switch d.DeliveryState {
		case "acknowledged":
			if !terminal.Before(expires) {
				return nil, errDirectChannelV2
			}
		case "expired":
			if terminal.Before(expires) {
				return nil, errDirectChannelV2
			}
		case "cancelled", "revoked":
		default:
			return nil, errDirectChannelV2
		}
	}
	w, err := DecodeDirectChannelMessageV2(d.Wire)
	if err != nil {
		return nil, err
	}
	hash, _ := DirectChannelMessageHashV2(w)
	b := d.Admission.Binding
	if b.WireBytes != len(d.Wire) || b.WireHash != hash || b.MessageID != w.Header.MessageID || b.Context.ChannelID != w.Header.ChannelID || b.Context.DescriptorHash != w.Header.DescriptorHash || b.Sender.Role != w.Header.SenderRole {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(d, DirectChannelMessageMaxBytesV2+directDeliveryMetadataMaxBytesV2)
}
func (p DirectInboxPageV2) CanonicalBytes() ([]byte, error) {
	if !directDeliveryDomain(p.Version, p.Domain, "inbox-page") || !p.Context.valid() || !p.Recipient.valid() || p.Deliveries == nil || len(p.Deliveries) > DirectInboxPageMaxItemsV2 || !directDeliveryCursor(p.NextCursor) {
		return nil, errDirectChannelV2
	}
	seen := make(map[string]bool, len(p.Deliveries))
	for _, d := range p.Deliveries {
		if _, err := d.CanonicalBytes(); err != nil {
			return nil, err
		}
		b := d.Admission.Binding
		if b.Context != p.Context || b.Recipient != p.Recipient || seen[b.MessageID] {
			return nil, errDirectChannelV2
		}
		seen[b.MessageID] = true
	}
	return directV2Canonical(p, DirectInboxPageMaxBytesV2)
}
func (a DirectMessageAckV2) CanonicalBytes() ([]byte, error) {
	if !directDeliveryDomain(a.Version, a.Domain, "ack") || !a.Binding.valid() {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(a, directDeliveryMetadataMaxBytesV2)
}
func (a DirectMessageAckReceiptV2) CanonicalBytes() ([]byte, error) {
	_, ok := directV2Time(a.AcknowledgedAt)
	if !directDeliveryDomain(a.Version, a.Domain, "ack-receipt") || !a.Binding.valid() || a.DeliveryState != "acknowledged" || !ok {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(a, directDeliveryMetadataMaxBytesV2)
}

// ValidateForPublication checks pinned publication evidence. Canonical decoding
// alone establishes structure, never current grant or credential authority.
func (b DirectMessageBindingV2) ValidateForPublication(p DirectChannelPublicationV2) error {
	raw, err := p.CanonicalBytes()
	if err != nil || !b.valid() {
		return errDirectChannelV2
	}
	d := p.Descriptor
	channel, _ := DirectChannelIDV2(d)
	hash, _ := DescriptorHashV2(d)
	if b.Context != (DirectDeliveryContextV2{ChannelID: channel, DescriptorHash: hash, PublicationHash: directV2Hash(raw), ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration}) || b.WireBytes > d.Limits.MaxMessageWireBytes {
		return errDirectChannelV2
	}
	source := DirectDeliveryPartyV2{Role: "S", PrincipalID: d.S.PrincipalID, EndpointID: d.S.EndpointID, CredentialID: d.S.CredentialID}
	peer := DirectDeliveryPartyV2{Role: "P", PrincipalID: d.P.PrincipalID, EndpointID: d.P.EndpointID, CredentialID: d.P.CredentialID}
	if (b.Sender == source && b.Recipient == peer) || (b.Sender == peer && b.Recipient == source) {
		return nil
	}
	return errDirectChannelV2
}

// ValidateForAdmission verifies a committed ACK's exact admission and deadline.
func (a DirectMessageAckReceiptV2) ValidateForAdmission(r DirectMessageAdmissionReceiptV2) error {
	if _, err := a.CanonicalBytes(); err != nil {
		return err
	}
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	at, _ := directV2Time(a.AcknowledgedAt)
	admitted, _ := directV2Time(r.AdmittedAt)
	expires, _ := directV2Time(r.ExpiresAt)
	if a.Binding != r.Binding || at.Before(admitted) || !at.Before(expires) {
		return errDirectChannelV2
	}
	return nil
}

// Bound page bytes and item count before allocating the deliveries slice. The
// token preflight does not interpret cursor contents or change delivery state.
func directInboxPreflight(raw []byte) error {
	if len(raw) == 0 || len(raw) > DirectInboxPageMaxBytesV2 {
		return errDirectChannelV2
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errDirectChannelV2
	}
	// Canonical top-level keys are required in declaration order. In particular,
	// reject the case-insensitive aliases accepted by encoding/json, and reject
	// duplicate keys before the deliveries slice can be allocated.
	for _, expected := range []string{"version", "domain", "context", "recipient", "deliveries", "nextCursor"} {
		key, err := decoder.Token()
		if err != nil || key != expected {
			return errDirectChannelV2
		}
		if expected != "deliveries" {
			if directInboxSkipValue(decoder) != nil {
				return errDirectChannelV2
			}
			continue
		}
		token, err := decoder.Token()
		if err != nil || token != json.Delim('[') {
			return errDirectChannelV2
		}
		items := 0
		for decoder.More() {
			items++
			if items > DirectInboxPageMaxItemsV2 || directInboxSkipValue(decoder) != nil {
				return errDirectChannelV2
			}
		}
		token, err = decoder.Token()
		if err != nil || token != json.Delim(']') {
			return errDirectChannelV2
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return errDirectChannelV2
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errDirectChannelV2
	}
	return nil
}

// Scan one JSON value without allocating a decoded slice or object.
func directInboxSkipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errDirectChannelV2
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return errDirectChannelV2
	}
	depth := 1
	for depth > 0 {
		token, err = decoder.Token()
		if err != nil {
			return errDirectChannelV2
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter == '{' || delimiter == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

func DecodeDirectMessageAdmissionReceiptV2(raw []byte) (DirectMessageAdmissionReceiptV2, error) {
	var value DirectMessageAdmissionReceiptV2
	if directV2Decode(raw, &value, directDeliveryMetadataMaxBytesV2) != nil {
		return DirectMessageAdmissionReceiptV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectMessageAdmissionReceiptV2{}, err
	}
	return value, nil
}

func DecodeDirectInboxRequestV2(raw []byte) (DirectInboxRequestV2, error) {
	var value DirectInboxRequestV2
	if directV2Decode(raw, &value, directDeliveryMetadataMaxBytesV2) != nil {
		return DirectInboxRequestV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectInboxRequestV2{}, err
	}
	return value, nil
}

func DecodeDirectDeliveryV2(raw []byte) (DirectDeliveryV2, error) {
	var value DirectDeliveryV2
	if directV2Decode(raw, &value, DirectChannelMessageMaxBytesV2+directDeliveryMetadataMaxBytesV2) != nil {
		return DirectDeliveryV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectDeliveryV2{}, err
	}
	return value, nil
}

func DecodeDirectInboxPageV2(raw []byte) (DirectInboxPageV2, error) {
	var value DirectInboxPageV2
	if directInboxPreflight(raw) != nil {
		return value, errDirectChannelV2
	}
	if directV2Decode(raw, &value, DirectInboxPageMaxBytesV2) != nil {
		return DirectInboxPageV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectInboxPageV2{}, err
	}
	return value, nil
}

func DecodeDirectMessageAckV2(raw []byte) (DirectMessageAckV2, error) {
	var value DirectMessageAckV2
	if directV2Decode(raw, &value, directDeliveryMetadataMaxBytesV2) != nil {
		return DirectMessageAckV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectMessageAckV2{}, err
	}
	return value, nil
}

func DecodeDirectMessageAckReceiptV2(raw []byte) (DirectMessageAckReceiptV2, error) {
	var value DirectMessageAckReceiptV2
	if directV2Decode(raw, &value, directDeliveryMetadataMaxBytesV2) != nil {
		return DirectMessageAckReceiptV2{}, errDirectChannelV2
	}
	if _, err := value.CanonicalBytes(); err != nil {
		return DirectMessageAckReceiptV2{}, err
	}
	return value, nil
}

// ValidateForPublication checks deadline evidence against the pinned descriptor.
// It does not make an admission decision or establish present authority.
func (r DirectMessageAdmissionReceiptV2) ValidateForPublication(p DirectChannelPublicationV2) error {
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	if err := r.Binding.ValidateForPublication(p); err != nil {
		return err
	}
	expires, _ := directV2Time(r.ExpiresAt)
	admitted, _ := directV2Time(r.AdmittedAt)
	descriptorExpiry, _ := directV2Time(p.Descriptor.ExpiresAt)
	if expires.After(descriptorExpiry) || (r.Binding.Sender.Role == "P" && expires.Sub(admitted) > 60*time.Second) {
		return errDirectChannelV2
	}
	return nil
}

func (d DirectDeliveryV2) ValidateForPublication(p DirectChannelPublicationV2) error {
	if _, err := d.CanonicalBytes(); err != nil {
		return err
	}
	if err := d.Admission.ValidateForPublication(p); err != nil {
		return err
	}
	w, err := DecodeDirectChannelMessageV2(d.Wire)
	if err != nil {
		return err
	}
	return ValidateDirectChannelMessageForDescriptorV2(w, p.Descriptor)
}
