package transport

import (
	"bytes"
	"encoding/json"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	MsgDirectManagedSourcePrepare      = "host.direct_managed_source_prepare"
	DirectManagedSourcePrepareProtocol = "direct_managed_source_prepare_v1"
	DirectManagedSourcePrepareFailure  = "direct_managed_source_prepare_failed"
)

// DirectManagedSourcePrepareCommand carries closed enrollment evidence only.
type DirectManagedSourcePrepareCommand struct {
	ProtocolVersion string                       `json:"protocolVersion"`
	CommandID       domain.ID                    `json:"commandId"`
	Subject         DirectManagedSourceBindingV1 `json:"subject"`
}

func (p DirectManagedSourcePrepareCommand) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocol || !nativeShareBindingID(p.CommandID) {
		return nil, errDirectManagedSourceBinding
	}
	raw, err := p.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Subject) != nil {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareCommand(raw []byte) (DirectManagedSourcePrepareCommand, error) {
	var p DirectManagedSourcePrepareCommand
	fields, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "subject")
	if err != nil {
		return p, err
	}
	subject, err := DecodeDirectManagedSourceBindingV1(fields["subject"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return DirectManagedSourcePrepareCommand{}, errDirectManagedSourceBinding
	}
	p.Subject = subject
	if _, err = p.CanonicalBytes(); err != nil {
		return DirectManagedSourcePrepareCommand{}, err
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}

// DirectManagedSourcePrepareACK is the success-only ACK. Failure has a separate
// exact shape and cannot carry a reservation or any arbitrary diagnostic.
type DirectManagedSourcePrepareACK struct {
	ProtocolVersion string                            `json:"protocolVersion"`
	CommandID       domain.ID                         `json:"commandId"`
	Reservation     DirectManagedSourceKeyReservation `json:"reservation"`
}

func (p DirectManagedSourcePrepareACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocol || !nativeShareBindingID(p.CommandID) {
		return nil, errDirectManagedSourceBinding
	}
	raw, err := p.Reservation.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Reservation) != nil {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

// DecodeDirectManagedSourcePrepareACK requires the complete retained request. It
// validates evidence only; callers still authenticate ingress independently.
func DecodeDirectManagedSourcePrepareACK(raw []byte, expected DirectManagedSourcePrepareCommand) (DirectManagedSourcePrepareACK, error) {
	var p DirectManagedSourcePrepareACK
	fields, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "reservation")
	if err != nil {
		return p, err
	}
	reservation, err := DecodeDirectManagedSourceKeyReservation(fields["reservation"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return DirectManagedSourcePrepareACK{}, errDirectManagedSourceBinding
	}
	p.Reservation = reservation
	if _, err = expected.CanonicalBytes(); err != nil {
		return DirectManagedSourcePrepareACK{}, err
	}
	if _, err = p.CanonicalBytes(); err != nil || p.CommandID != expected.CommandID || p.Reservation.VerifySubject(expected.Subject) != nil {
		return DirectManagedSourcePrepareACK{}, errDirectManagedSourceBinding
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}

type DirectManagedSourcePrepareFailureACK struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CommandID       domain.ID `json:"commandId"`
	Error           string    `json:"error"`
}

func (p DirectManagedSourcePrepareFailureACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != DirectManagedSourcePrepareProtocol || !nativeShareBindingID(p.CommandID) || p.Error != DirectManagedSourcePrepareFailure {
		return nil, errDirectManagedSourceBinding
	}
	return json.Marshal(p)
}

func DecodeDirectManagedSourcePrepareFailureACK(raw []byte, commandID domain.ID) (DirectManagedSourcePrepareFailureACK, error) {
	var p DirectManagedSourcePrepareFailureACK
	if _, err := directManagedSourcePrepareObject(raw, "protocolVersion", "commandId", "error"); err != nil || json.Unmarshal(raw, &p) != nil {
		return p, errDirectManagedSourceBinding
	}
	if _, err := p.CanonicalBytes(); err != nil || p.CommandID != commandID {
		return DirectManagedSourcePrepareFailureACK{}, errDirectManagedSourceBinding
	}
	canonical, canonicalErr := p.CanonicalBytes()
	if canonicalErr != nil || !bytes.Equal(raw, canonical) {
		return p, errDirectManagedSourceBinding
	}
	return p, nil
}

func directManagedSourcePrepareObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	if len(raw) > 24*1024 || !managedEndpointJSONStringsValid(raw) {
		return nil, errDirectManagedSourceBinding
	}
	values, err := nativeShareSourceObject(raw, fields...)
	if err != nil {
		return nil, errDirectManagedSourceBinding
	}
	return values, nil
}
