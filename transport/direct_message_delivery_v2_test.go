package transport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func directDeliveryFixture(t *testing.T) (DirectDeliveryV2, DirectChannelPublicationV2) {
	t.Helper()
	p, c, _, _, now := directV2TestFixture(t)
	ask, _, _ := directMessageV2Fixture(t)
	wire, err := ask.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := DirectChannelMessageHashV2(ask)
	d := p.Descriptor
	b := DirectMessageBindingV2{Context: DirectDeliveryContextV2{ChannelID: c.ChannelID, DescriptorHash: c.DescriptorHash, PublicationHash: c.PublicationHash, ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration}, MessageID: ask.Header.MessageID, WireHash: hash, WireBytes: len(wire), Sender: DirectDeliveryPartyV2{Role: "S", PrincipalID: d.S.PrincipalID, EndpointID: d.S.EndpointID, CredentialID: d.S.CredentialID}, Recipient: DirectDeliveryPartyV2{Role: "P", PrincipalID: d.P.PrincipalID, EndpointID: d.P.EndpointID, CredentialID: d.P.CredentialID}}
	r := DirectMessageAdmissionReceiptV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/admission", Binding: b, AdmissionState: "admitted", AdmittedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	return DirectDeliveryV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/item", Admission: r, DeliveryState: "pending", Wire: wire}, p
}

func TestDirectDeliveryV2Contracts(t *testing.T) {
	d, p := directDeliveryFixture(t)
	b := d.Admission.Binding
	request := DirectInboxRequestV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/inbox-request", Context: b.Context, Recipient: b.Recipient, Limit: 50}
	page := DirectInboxPageV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/inbox-page", Context: b.Context, Recipient: b.Recipient, Deliveries: []DirectDeliveryV2{d}, NextCursor: "opaque-cursor"}
	ack := DirectMessageAckV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/ack", Binding: b}
	receipt := DirectMessageAckReceiptV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/ack-receipt", Binding: b, DeliveryState: "acknowledged", AcknowledgedAt: d.Admission.AdmittedAt}
	cases := []struct {
		name   string
		value  interface{ CanonicalBytes() ([]byte, error) }
		decode func([]byte) error
	}{
		{"admission", d.Admission, func(raw []byte) error { _, err := DecodeDirectMessageAdmissionReceiptV2(raw); return err }},
		{"request", request, func(raw []byte) error { _, err := DecodeDirectInboxRequestV2(raw); return err }},
		{"delivery", d, func(raw []byte) error { _, err := DecodeDirectDeliveryV2(raw); return err }},
		{"page", page, func(raw []byte) error { _, err := DecodeDirectInboxPageV2(raw); return err }},
		{"ack", ack, func(raw []byte) error { _, err := DecodeDirectMessageAckV2(raw); return err }},
		{"ack receipt", receipt, func(raw []byte) error { _, err := DecodeDirectMessageAckReceiptV2(raw); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.decode(raw); err != nil {
				t.Fatal(err)
			}
			for name, changed := range map[string][]byte{
				"space":     append([]byte(" "), raw...),
				"duplicate": bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
				"unknown":   bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"plaintext":"secret"`), 1),
				"version":   bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":1`), 1),
				"trailing":  append(append([]byte{}, raw...), []byte(`{}`)...),
			} {
				t.Run(name, func(t *testing.T) {
					if tc.decode(changed) == nil {
						t.Fatal("accepted")
					}
				})
			}
		})
	}
	if err := d.ValidateForPublication(p); err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateForAdmission(d.Admission); err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Descriptor.P.CredentialID = directV2TestID(99)
	if d.ValidateForPublication(changed) == nil {
		t.Fatal("accepted replacement descriptor credential")
	}
}

func TestDirectDeliveryV2EvidenceAndStates(t *testing.T) {
	d, p := directDeliveryFixture(t)
	for name, mutate := range map[string]func(*DirectDeliveryV2){
		"wire hash":        func(d *DirectDeliveryV2) { d.Admission.Binding.WireHash = directV2TestBinary(88, 32) },
		"wire length":      func(d *DirectDeliveryV2) { d.Admission.Binding.WireBytes++ },
		"message":          func(d *DirectDeliveryV2) { d.Admission.Binding.MessageID = directV2TestID(99) },
		"role":             func(d *DirectDeliveryV2) { d.Admission.Binding.Sender.Role = "P" },
		"admission state":  func(d *DirectDeliveryV2) { d.Admission.AdmissionState = "acknowledged" },
		"pending terminal": func(d *DirectDeliveryV2) { d.TerminalAt = d.Admission.AdmittedAt },
		"ack deadline":     func(d *DirectDeliveryV2) { d.DeliveryState = "acknowledged"; d.TerminalAt = d.Admission.ExpiresAt },
		"early expiry":     func(d *DirectDeliveryV2) { d.DeliveryState = "expired"; d.TerminalAt = d.Admission.AdmittedAt },
		"unknown state":    func(d *DirectDeliveryV2) { d.DeliveryState = "acked" },
		"plaintext wire":   func(d *DirectDeliveryV2) { d.Wire = json.RawMessage(`{"plaintext":"secret"}`) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d
			mutate(&changed)
			raw, _ := json.Marshal(changed)
			if _, err := DecodeDirectDeliveryV2(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, state := range []string{"acknowledged", "expired", "cancelled", "revoked"} {
		changed := d
		changed.DeliveryState = state
		changed.TerminalAt = d.Admission.AdmittedAt
		if state == "expired" {
			changed.TerminalAt = d.Admission.ExpiresAt
		}
		if _, err := changed.CanonicalBytes(); err != nil {
			t.Fatalf("%s: %v", state, err)
		}
	}
	changed := d
	changed.Admission.Binding.Recipient.CredentialID = directV2TestID(99)
	if changed.ValidateForPublication(p) == nil {
		t.Fatal("accepted wrong recipient credential")
	}
	receipt := DirectMessageAckReceiptV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/ack-receipt", Binding: d.Admission.Binding, DeliveryState: "acknowledged", AcknowledgedAt: d.Admission.ExpiresAt}
	if receipt.ValidateForAdmission(d.Admission) == nil {
		t.Fatal("accepted late committed ACK")
	}
	receipt.AcknowledgedAt = d.Admission.AdmittedAt
	receipt.Binding.WireBytes++
	if receipt.ValidateForAdmission(d.Admission) == nil {
		t.Fatal("accepted wrong ACK bytes")
	}
}

func TestDirectInboxV2Bounds(t *testing.T) {
	d, _ := directDeliveryFixture(t)
	b := d.Admission.Binding
	page := DirectInboxPageV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/inbox-page", Context: b.Context, Recipient: b.Recipient, Deliveries: []DirectDeliveryV2{d}}
	raw, err := page.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"bytes":      bytes.Repeat([]byte(" "), DirectInboxPageMaxBytesV2+1),
		"null items": bytes.Replace(raw, []byte(`"deliveries":[`), []byte(`"deliveries":[`+strings.Repeat("null,", 50)), 1),
		"cursor":     bytes.Replace(raw, []byte(`"nextCursor":""`), []byte(`"nextCursor":"`+strings.Repeat("a", 1025)+`"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDirectInboxPageV2(changed); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	tooMany := []byte(`{"deliveries":[` + strings.Repeat("{},", 50) + `{}]}`)
	if directInboxPreflight(tooMany) == nil {
		t.Fatal("item count not bounded before decode")
	}
	page.Deliveries = append(page.Deliveries, d)
	if _, err := page.CanonicalBytes(); err == nil {
		t.Fatal("duplicate delivery accepted")
	}
	page.Deliveries = []DirectDeliveryV2{}
	if _, err := page.CanonicalBytes(); err != nil {
		t.Fatal("empty page", err)
	}
}
