package transport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func managedPrepareFixture(t *testing.T) (ManagedEndpointPrepareCommand, ManagedEndpointPrepareACK) {
	t.Helper()
	command := ManagedEndpointPrepareCommand{ManagedEndpointPrepareProtocol, domain.NewID(), managedBindingFixture()}
	reservation := ManagedEndpointKeyReservation{Subject: command.Subject, ServerURL: "https://control.example.test", InstallationID: domain.NewID(), KeyGeneration: 1, X25519: strings.Repeat("ab", 32)}
	var err error
	reservation.EnrollmentDigest, err = reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return command, ManagedEndpointPrepareACK{ManagedEndpointPrepareProtocol, command.CommandID, reservation}
}

func TestManagedEndpointPrepareRoundTrip(t *testing.T) {
	command, ack := managedPrepareFixture(t)
	raw, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManagedEndpointPrepareCommand(raw)
	if err != nil || decoded != command {
		t.Fatal("command round trip", err)
	}
	raw, err = ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeManagedEndpointPrepareACK(raw, command)
	if err != nil || result != ack {
		t.Fatal("ACK round trip", err)
	}
	failure := ManagedEndpointPrepareFailureACK{ManagedEndpointPrepareProtocol, command.CommandID, ManagedEndpointPrepareFailure}
	raw, err = failure.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	failed, err := DecodeManagedEndpointPrepareFailureACK(raw, command.CommandID)
	if err != nil || failed != failure {
		t.Fatal("failure round trip", err)
	}
	if _, err := DecodeManagedEndpointPrepareACK(raw, command); err == nil {
		t.Fatal("failure accepted as success")
	}
}

func TestManagedEndpointPrepareStrictWire(t *testing.T) {
	command, ack := managedPrepareFixture(t)
	request, _ := command.CanonicalBytes()
	response, _ := ack.CanonicalBytes()
	for name, decode := range map[string]func([]byte) error{
		"command": func(raw []byte) error { _, err := DecodeManagedEndpointPrepareCommand(raw); return err },
		"ack":     func(raw []byte) error { _, err := DecodeManagedEndpointPrepareACK(raw, command); return err },
	} {
		t.Run(name, func(t *testing.T) {
			raw := request
			if name == "ack" {
				raw = response
			}
			for _, bad := range [][]byte{
				append(append([]byte(nil), raw...), []byte(` {}`)...),
				bytes.Replace(raw, []byte(`"commandId":`), []byte(`"commandId":"`+string(command.CommandID)+`","commandId":`), 1),
				bytes.Replace(raw, []byte(`"commandId"`), []byte(`"CommandId"`), 1),
				bytes.Replace(raw, []byte(`"subject":`), []byte(`"unexpected":0,"subject":`), 1),
				bytes.Replace(raw, []byte(`"state":"pending_closed"`), []byte(`"state":"pending_closed","state":"pending_closed"`), 1),
				bytes.Replace(raw, []byte(`"state":"pending_closed"`), []byte(`"state":null`), 1),
				bytes.Replace(raw, []byte(string(command.CommandID)), []byte(strings.ToUpper(string(command.CommandID))), 1),
				bytes.Repeat([]byte(" "), 24*1024+1),
			} {
				if err := decode(bad); err == nil {
					t.Fatal("ambiguous or malformed wire accepted", string(bad[:min(len(bad), 200)]))
				}
			}
		})
	}
}

func TestManagedEndpointPrepareBindsCompleteSubject(t *testing.T) {
	command, ack := managedPrepareFixture(t)
	for name, mutate := range map[string]func(*ManagedEndpointKeyReservation){
		"endpoint": func(p *ManagedEndpointKeyReservation) { p.Subject.EndpointID = domain.NewID() },
		"creation": func(p *ManagedEndpointKeyReservation) { p.Subject.CreatedAt = p.Subject.CreatedAt.Add(time.Second) },
		"expiry":   func(p *ManagedEndpointKeyReservation) { p.Subject.ExpiresAt = p.Subject.ExpiresAt.Add(-time.Second) },
		"runner": func(p *ManagedEndpointKeyReservation) {
			p.Subject.RunnerConnectedAt = p.Subject.RunnerConnectedAt.Add(time.Second)
		},
		"native generation":    func(p *ManagedEndpointKeyReservation) { p.Subject.NativeGeneration += "-other" },
		"ownership generation": func(p *ManagedEndpointKeyReservation) { p.Subject.OwnershipGeneration += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := ack
			mutate(&altered.Reservation)
			altered.Reservation.EnrollmentDigest, _ = altered.Reservation.Digest()
			raw, err := altered.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeManagedEndpointPrepareACK(raw, command); err == nil {
				t.Fatal("altered retained subject accepted")
			}
		})
	}
	raw, _ := ack.CanonicalBytes()
	command.CommandID = domain.NewID()
	if _, err := DecodeManagedEndpointPrepareACK(raw, command); err == nil {
		t.Fatal("wrong command accepted")
	}
}

func TestManagedEndpointReservationCanonicalValidation(t *testing.T) {
	_, ack := managedPrepareFixture(t)
	p := ack.Reservation
	digest, _ := p.Digest()
	p.Subject.CreatedAt = p.Subject.CreatedAt.In(time.FixedZone("offset", 3600))
	other, err := p.Digest()
	if err != nil || other != digest {
		t.Fatal("equivalent UTC time changed digest")
	}
	for name, mutate := range map[string]func(*ManagedEndpointKeyReservation){
		"public key case": func(p *ManagedEndpointKeyReservation) { p.X25519 = strings.ToUpper(p.X25519) },
		"public key size": func(p *ManagedEndpointKeyReservation) { p.X25519 = "ab" },
		"digest case":     func(p *ManagedEndpointKeyReservation) { p.EnrollmentDigest = strings.ToUpper(p.EnrollmentDigest) },
		"digest mismatch": func(p *ManagedEndpointKeyReservation) { p.X25519 = strings.Repeat("cd", 32) },
		"installation":    func(p *ManagedEndpointKeyReservation) { p.InstallationID = "not-an-id" },
		"generation":      func(p *ManagedEndpointKeyReservation) { p.KeyGeneration = 2 },
		"origin":          func(p *ManagedEndpointKeyReservation) { p.ServerURL += "/" },
	} {
		t.Run(name, func(t *testing.T) {
			altered := p
			mutate(&altered)
			raw, _ := json.Marshal(altered)
			if _, err := DecodeManagedEndpointKeyReservation(raw); err == nil {
				t.Fatal("invalid reservation accepted")
			}
		})
	}
}

func TestManagedEndpointPrepareFailureSanitized(t *testing.T) {
	command, _ := managedPrepareFixture(t)
	failure := ManagedEndpointPrepareFailureACK{ManagedEndpointPrepareProtocol, command.CommandID, ManagedEndpointPrepareFailure}
	raw, _ := failure.CanonicalBytes()
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(ManagedEndpointPrepareFailure), []byte("private diagnostic"), 1),
		bytes.Replace(raw, []byte(`"error":`), []byte(`"reservation":{},"error":`), 1),
		bytes.Replace(raw, []byte(`"error":`), []byte(`"result":{},"error":`), 1),
		bytes.Replace(raw, []byte(`"error":`), []byte(`"error":"managed_endpoint_prepare_failed","error":`), 1),
		append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		if _, err := DecodeManagedEndpointPrepareFailureACK(bad, command.CommandID); err == nil {
			t.Fatal("unsanitized failure accepted")
		}
	}
	if _, err := DecodeManagedEndpointPrepareFailureACK(raw, domain.NewID()); err == nil {
		t.Fatal("wrong command accepted")
	}
}
