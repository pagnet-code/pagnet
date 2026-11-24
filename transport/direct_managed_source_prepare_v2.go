package transport

import (
	"bytes"
	"encoding/json"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	MsgDirectManagedSourcePrepareV2      = "host.direct_managed_source_prepare"
	DirectManagedSourcePrepareProtocolV2 = "direct_managed_source_prepare_v2"
	DirectManagedSourcePrepareFailureV2  = "direct_managed_source_prepare_failed"
)

// DirectManagedSourcePrepareCommandV2 carries closed enrollment evidence only.
type DirectManagedSourcePrepareCommandV2 struct {
	ProtocolVersion string                       `json:"protocolVersion"`
	CommandID       domain.ID                    `json:"commandId"`
	Subject         DirectManagedSourceBindingV2 `json:"subject"`
}

func (p DirectManagedSourcePrepareCommandV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocolV2 || !nativeShareBindingID(p.CommandID) {
		return nil, errDirectManagedSourceBinding
	}
	raw, err := p.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Subject) != nil {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareCommandV2(raw []byte) (DirectManagedSourcePrepareCommandV2, error) {
	var p DirectManagedSourcePrepareCommandV2
	fields, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "subject")
	if err != nil {
		return p, err
	}
	subject, err := DecodeDirectManagedSourceBindingV2(fields["subject"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return DirectManagedSourcePrepareCommandV2{}, errDirectManagedSourceBinding
	}
	p.Subject = subject
	if _, err = p.CanonicalBytes(); err != nil {
		return DirectManagedSourcePrepareCommandV2{}, err
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}

// DirectManagedSourcePrepareACKV2 is the success-only ACK. Failure has a separate
// exact shape and cannot carry a reservation or any arbitrary diagnostic.
type DirectManagedSourcePrepareACKV2 struct {
	ProtocolVersion string                              `json:"protocolVersion"`
	CommandID       domain.ID                           `json:"commandId"`
	Reservation     DirectManagedSourceKeyReservationV2 `json:"reservation"`
}

func (p DirectManagedSourcePrepareACKV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocolV2 || !nativeShareBindingID(p.CommandID) {
		return nil, errDirectManagedSourceBinding
	}
	raw, err := p.Reservation.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Reservation) != nil {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

// DecodeDirectManagedSourcePrepareACKV2 requires the complete retained request. It
// validates evidence only; callers still authenticate ingress independently.
func DecodeDirectManagedSourcePrepareACKV2(raw []byte, expected DirectManagedSourcePrepareCommandV2) (DirectManagedSourcePrepareACKV2, error) {
	var p DirectManagedSourcePrepareACKV2
	fields, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "reservation")
	if err != nil {
		return p, err
	}
	reservation, err := DecodeDirectManagedSourceKeyReservationV2(fields["reservation"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return DirectManagedSourcePrepareACKV2{}, errDirectManagedSourceBinding
	}
	p.Reservation = reservation
	if _, err = expected.CanonicalBytes(); err != nil {
		return DirectManagedSourcePrepareACKV2{}, err
	}
	if _, err = p.CanonicalBytes(); err != nil || p.CommandID != expected.CommandID || p.Reservation.VerifySubject(expected.Subject) != nil {
		return DirectManagedSourcePrepareACKV2{}, errDirectManagedSourceBinding
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}

type DirectManagedSourcePrepareFailureACKV2 struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CommandID       domain.ID `json:"commandId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourcePrepareFailureACKV2) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocolV2 || !nativeShareBindingID(p.CommandID) || p.Error != DirectManagedSourcePrepareFailureV2 {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareFailureACKV2(raw []byte, commandID domain.ID) (DirectManagedSourcePrepareFailureACKV2, error) {
	var p DirectManagedSourcePrepareFailureACKV2
	if _, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "error"); err != nil || json.Unmarshal(raw, &p) != nil {
		return p, errDirectManagedSourceBinding
	}
	if _, err := p.CanonicalBytes(); err != nil || p.CommandID != commandID {
		return DirectManagedSourcePrepareFailureACKV2{}, errDirectManagedSourceBinding
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}
