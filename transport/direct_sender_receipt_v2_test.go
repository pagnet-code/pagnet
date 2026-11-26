package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestDirectSenderReceiptV2(t *testing.T) {
	d, _ := directDeliveryFixture(t)
	q := DirectSenderReceiptRequestV2{2, DirectChannelDomainV2 + "/delivery/sender-receipt-request", d.Admission.Binding}
	raw, err := q.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDirectSenderReceiptRequestV2(raw); err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, d.Admission.AdmittedAt)
	r := DirectSenderReceiptV2{Version: 2, Domain: DirectChannelDomainV2 + "/delivery/sender-receipt", Status: "admitted", Admission: &d.Admission, DeliveryState: "pending", ObservedAt: at.Add(time.Hour).Format(time.RFC3339Nano), ReconcileUntil: at.Add(24 * time.Hour).Format(time.RFC3339Nano)}
	for _, status := range []string{"admitted", "not_found"} {
		t.Run(status, func(t *testing.T) {
			v := r
			if status == "not_found" {
				v.Status = status
				v.Admission = nil
				v.DeliveryState = ""
			}
			raw, err := v.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeDirectSenderReceiptV2(raw); err != nil {
				t.Fatal(err)
			}
			if err := v.ValidateForRequest(q); err != nil {
				t.Fatal(err)
			}
			for _, bad := range [][]byte{append([]byte(" "), raw...), append(bytes.Clone(raw), []byte(`{}`)...), bytes.Replace(raw, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1)} {
				if _, err := DecodeDirectSenderReceiptV2(bad); err == nil {
					t.Fatal("accepted noncanonical receipt")
				}
			}
		})
	}
	for _, mutate := range []func(*DirectSenderReceiptV2){func(r *DirectSenderReceiptV2) { r.DeliveryState = "acknowledged" }, func(r *DirectSenderReceiptV2) { r.Status = "unknown" }, func(r *DirectSenderReceiptV2) { r.ReconcileUntil = r.ObservedAt }, func(r *DirectSenderReceiptV2) { r.TerminalAt = r.ObservedAt }} {
		v := r
		mutate(&v)
		if _, err := v.CanonicalBytes(); err == nil {
			t.Fatal("accepted invalid receipt")
		}
	}
	q.Binding.WireBytes++
	if r.ValidateForRequest(q) == nil {
		t.Fatal("accepted mismatched binding")
	}
}
