package transport

import "time"

// DirectSenderReceiptRequestV2 asks for retained delivery metadata only.
// Neither the request nor its response confers traffic authority.
type DirectSenderReceiptRequestV2 struct {
	Version int                    `json:"version"`
	Domain  string                 `json:"domain"`
	Binding DirectMessageBindingV2 `json:"binding"`
}

type DirectSenderReceiptV2 struct {
	Version        int                              `json:"version"`
	Domain         string                           `json:"domain"`
	Status         string                           `json:"status"`
	Admission      *DirectMessageAdmissionReceiptV2 `json:"admission,omitempty"`
	DeliveryState  string                           `json:"deliveryState"`
	TerminalAt     string                           `json:"terminalAt"`
	ObservedAt     string                           `json:"observedAt"`
	ReconcileUntil string                           `json:"reconcileUntil"`
}

func (r DirectSenderReceiptRequestV2) CanonicalBytes() ([]byte, error) {
	if !directDeliveryDomain(r.Version, r.Domain, "sender-receipt-request") || !r.Binding.valid() {
		return nil, errDirectChannelV2
	}
	return directV2Canonical(r, directDeliveryMetadataMaxBytesV2)
}

func (r DirectSenderReceiptV2) CanonicalBytes() ([]byte, error) {
	observed, ok := directV2Time(r.ObservedAt)
	until, uok := directV2Time(r.ReconcileUntil)
	if !directDeliveryDomain(r.Version, r.Domain, "sender-receipt") || !ok || !uok || !until.After(observed) {
		return nil, errDirectChannelV2
	}
	switch r.Status {
	case "not_found":
		if r.Admission != nil || r.DeliveryState != "" || r.TerminalAt != "" {
			return nil, errDirectChannelV2
		}
	case "admitted":
		if r.Admission == nil {
			return nil, errDirectChannelV2
		}
		if _, err := r.Admission.CanonicalBytes(); err != nil {
			return nil, err
		}
		admitted, _ := directV2Time(r.Admission.AdmittedAt)
		expires, _ := directV2Time(r.Admission.ExpiresAt)
		if observed.Before(admitted) || !until.Equal(admitted.Add(24*time.Hour)) {
			return nil, errDirectChannelV2
		}
		if r.DeliveryState == "pending" {
			if r.TerminalAt != "" {
				return nil, errDirectChannelV2
			}
		} else {
			terminal, tok := directV2Time(r.TerminalAt)
			if !tok || terminal.Before(admitted) || terminal.After(observed) {
				return nil, errDirectChannelV2
			}
			switch r.DeliveryState {
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
	default:
		return nil, errDirectChannelV2
	}
	return directV2Canonical(r, directDeliveryMetadataMaxBytesV2)
}
func DecodeDirectSenderReceiptRequestV2(raw []byte) (DirectSenderReceiptRequestV2, error) {
	var r DirectSenderReceiptRequestV2
	if directV2Decode(raw, &r, directDeliveryMetadataMaxBytesV2) != nil {
		return r, errDirectChannelV2
	}
	_, err := r.CanonicalBytes()
	return r, err
}
func DecodeDirectSenderReceiptV2(raw []byte) (DirectSenderReceiptV2, error) {
	var r DirectSenderReceiptV2
	if directV2Decode(raw, &r, directDeliveryMetadataMaxBytesV2) != nil {
		return r, errDirectChannelV2
	}
	_, err := r.CanonicalBytes()
	return r, err
}
func (r DirectSenderReceiptV2) ValidateForRequest(q DirectSenderReceiptRequestV2) error {
	if _, err := q.CanonicalBytes(); err != nil {
		return err
	}
	if _, err := r.CanonicalBytes(); err != nil {
		return err
	}
	if r.Admission != nil && r.Admission.Binding != q.Binding {
		return errDirectChannelV2
	}
	return nil
}
