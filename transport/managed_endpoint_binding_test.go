package transport

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func managedBindingFixture() ManagedEndpointBindingIntent {
	now := time.Now().UTC().Truncate(time.Microsecond)
	admission := domain.NewID()
	return ManagedEndpointBindingIntent{ID: domain.NewID(), DirectIntentID: domain.NewID(), ProtocolVersion: ManagedEndpointBindingProtocol, TenantID: domain.NewID(), AccountID: domain.NewID(), OwnershipScope: "personal", PrincipalID: domain.NewID(), EndpointID: domain.NewID(), InstanceID: domain.NewID(), OriginID: domain.NewID(), NativeGeneration: "generation", NativeSessionID: "session", OwnershipID: domain.NewID(), OwnershipGeneration: "ownership-generation", NativeAdmissionID: admission, ConnectionIncarnationID: admission, HostID: domain.NewID(), HostCredentialID: domain.NewID(), RunnerID: domain.NewID(), RunnerConnectedAt: now, BootID: "boot", BindingGeneration: 1, State: "pending_closed", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
}
func TestManagedEndpointBindingStrictWire(t *testing.T) {
	p := managedBindingFixture()
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeManagedEndpointBindingIntent(raw)
	if err != nil || decoded != p {
		t.Fatal("valid server subject rejected", err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), raw...),
		bytes.Replace(raw, []byte(`"state":"pending_closed"`), []byte(`"state":"pending_closed","state":"pending_closed"`), 1),
		bytes.Replace(raw, []byte(`"state"`), []byte(`"State"`), 1),
		bytes.Replace(raw, []byte(`"state":"pending_closed"`), []byte(`"state":null`), 1),
		bytes.Replace(raw, []byte(`"state":"pending_closed"`), []byte(`"state":"pending_closed","serverUrl":"https://attacker.test"`), 1),
		bytes.Repeat([]byte(" "), 16*1024+1),
	} {
		if _, err := DecodeManagedEndpointBindingIntent(bad); err == nil {
			t.Fatal("ambiguous wire subject accepted")
		}
	}
}
func TestManagedEndpointBindingClosedSubject(t *testing.T) {
	for _, field := range []string{"state", "protocol", "ownership", "generation", "connection", "missing", "expiry", "lifetime", "time", "nativeGeneration", "nativeSession", "workerGeneration"} {
		t.Run(field, func(t *testing.T) {
			p := managedBindingFixture()
			switch field {
			case "state":
				p.State = "active"
			case "protocol":
				p.ProtocolVersion = "other"
			case "ownership":
				p.OwnershipScope = "network"
			case "generation":
				p.BindingGeneration = 2
			case "connection":
				p.ConnectionIncarnationID = domain.NewID()
			case "missing":
				p.EndpointID = ""
			case "expiry":
				p.ExpiresAt = p.CreatedAt
			case "lifetime":
				p.ExpiresAt = p.CreatedAt.Add(6 * time.Minute)
			case "time":
				p.RunnerConnectedAt = time.Time{}
			case "nativeGeneration":
				p.NativeGeneration = ""
			case "nativeSession":
				p.NativeSessionID = ""
			case "workerGeneration":
				p.OwnershipGeneration = ""
			}
			raw, _ := json.Marshal(p)
			if _, err := DecodeManagedEndpointBindingIntent(raw); err == nil {
				t.Fatal("invalid subject accepted")
			}
		})
	}
	// Equivalent timestamptz representations retain the same canonical digest input.
	p := managedBindingFixture()
	canonical, _ := p.CanonicalBytes()
	p.RunnerConnectedAt = p.RunnerConnectedAt.In(time.FixedZone("offset", 3600))
	other, _ := p.CanonicalBytes()
	if !bytes.Equal(canonical, other) {
		t.Fatal("time representation changed subject")
	}
}
