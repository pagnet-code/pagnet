package transport

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const (
	MsgManagedEndpointPrepare      = "host.managed_endpoint_prepare"
	ManagedEndpointPrepareProtocol = "managed_native_endpoint_prepare_v1"
	ManagedEndpointPrepareFailure  = "managed_endpoint_prepare_failed"
)

// ManagedEndpointPrepareCommand carries closed enrollment evidence only.
type ManagedEndpointPrepareCommand struct {
	ProtocolVersion string                       `json:"protocolVersion"`
	CommandID       domain.ID                    `json:"commandId"`
	Subject         ManagedEndpointBindingIntent `json:"subject"`
}

func (p ManagedEndpointPrepareCommand) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointPrepareProtocol || !nativeShareBindingID(p.CommandID) {
		return nil, errManagedEndpointBinding
	}
	raw, err := p.Subject.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Subject) != nil {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}

func DecodeManagedEndpointPrepareCommand(raw []byte) (ManagedEndpointPrepareCommand, error) {
	var p ManagedEndpointPrepareCommand
	fields, err := managedEndpointPrepareObject(raw, "protocolVersion", "commandId", "subject")
	if err != nil {
		return p, err
	}
	subject, err := DecodeManagedEndpointBindingIntent(fields["subject"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return ManagedEndpointPrepareCommand{}, errManagedEndpointBinding
	}
	p.Subject = subject
	if _, err = p.CanonicalBytes(); err != nil {
		return ManagedEndpointPrepareCommand{}, err
	}
	return p, nil
}

// ManagedEndpointPrepareACK is the success-only ACK. Failure has a separate
// exact shape and cannot carry a reservation or any arbitrary diagnostic.
type ManagedEndpointPrepareACK struct {
	ProtocolVersion string                        `json:"protocolVersion"`
	CommandID       domain.ID                     `json:"commandId"`
	Reservation     ManagedEndpointKeyReservation `json:"reservation"`
}

func (p ManagedEndpointPrepareACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointPrepareProtocol || !nativeShareBindingID(p.CommandID) {
		return nil, errManagedEndpointBinding
	}
	raw, err := p.Reservation.CanonicalBytes()
	if err != nil || json.Unmarshal(raw, &p.Reservation) != nil {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}

// DecodeManagedEndpointPrepareACK requires the complete retained request. It
// validates evidence only; callers still authenticate ingress independently.
func DecodeManagedEndpointPrepareACK(raw []byte, expected ManagedEndpointPrepareCommand) (ManagedEndpointPrepareACK, error) {
	var p ManagedEndpointPrepareACK
	fields, err := managedEndpointPrepareObject(raw, "protocolVersion", "commandId", "reservation")
	if err != nil {
		return p, err
	}
	reservation, err := DecodeManagedEndpointKeyReservation(fields["reservation"])
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return ManagedEndpointPrepareACK{}, errManagedEndpointBinding
	}
	p.Reservation = reservation
	if _, err = expected.CanonicalBytes(); err != nil {
		return ManagedEndpointPrepareACK{}, err
	}
	if _, err = p.CanonicalBytes(); err != nil || p.CommandID != expected.CommandID || p.Reservation.VerifySubject(expected.Subject) != nil {
		return ManagedEndpointPrepareACK{}, errManagedEndpointBinding
	}
	return p, nil
}

type ManagedEndpointPrepareFailureACK struct {
	ProtocolVersion string    `json:"protocolVersion"`
	CommandID       domain.ID `json:"commandId"`
	Error           string    `json:"error"`
}

func (p ManagedEndpointPrepareFailureACK) CanonicalBytes() ([]byte, error) {
	if p.ProtocolVersion != ManagedEndpointPrepareProtocol || !nativeShareBindingID(p.CommandID) || p.Error != ManagedEndpointPrepareFailure {
		return nil, errManagedEndpointBinding
	}
	return json.Marshal(p)
}

func DecodeManagedEndpointPrepareFailureACK(raw []byte, commandID domain.ID) (ManagedEndpointPrepareFailureACK, error) {
	var p ManagedEndpointPrepareFailureACK
	if _, err := managedEndpointPrepareObject(raw, "protocolVersion", "commandId", "error"); err != nil || json.Unmarshal(raw, &p) != nil {
		return p, errManagedEndpointBinding
	}
	if _, err := p.CanonicalBytes(); err != nil || p.CommandID != commandID {
		return ManagedEndpointPrepareFailureACK{}, errManagedEndpointBinding
	}
	return p, nil
}

func managedEndpointPrepareObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	if len(raw) > 24*1024 || !utf8.Valid(raw) {
		return nil, errManagedEndpointBinding
	}
	values, err := nativeShareSourceObject(raw, fields...)
	if err != nil {
		return nil, errManagedEndpointBinding
	}
	return values, nil
}
