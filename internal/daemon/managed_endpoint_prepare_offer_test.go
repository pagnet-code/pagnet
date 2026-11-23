package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedEndpointPrepareQueryStripped(t *testing.T) {
	for _, query := range []string{
		"",
		"managed_endpoint_prepare=" + transport.ManagedEndpointPrepareProtocol,
		"managed_endpoint_prepare=untrusted&managed_endpoint_prepare=" + transport.ManagedEndpointPrepareProtocol,
		"managed_endpoint_prepare=%zz",
		"managed_endpoint_prepare=bad;value",
		"managed%5fendpoint%5fprepare=" + transport.ManagedEndpointPrepareProtocol,
	} {
		t.Run(query, func(t *testing.T) {
			d := &Daemon{Config: Config{ServerURL: "https://example.test?" + query}}
			u, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := u.Query()["managed_endpoint_prepare"]; exists {
				t.Fatal("uncomposed managed Prepare capability advertised")
			}
		})
	}
}

func TestManagedEndpointPrepareUnofferedFeatureRejected(t *testing.T) {
	host, runner, boot := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	admission := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: runner, HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	for _, repeat := range []bool{false, true} {
		for _, count := range []int{1, 2} {
			conn := NewNativeObservationConnection("https://example.test", host, boot, nil)
			if repeat {
				if err := conn.Admit(admission); err != nil {
					t.Fatal(err)
				}
			}
			unoffered := admission
			unoffered.ProtocolFeatures = append([]string(nil), admission.ProtocolFeatures...)
			for range count {
				unoffered.ProtocolFeatures = append(unoffered.ProtocolFeatures, transport.ManagedEndpointPrepareProtocol)
			}
			if err := conn.Admit(unoffered); !errors.Is(err, ErrNativeObservationConflict) {
				t.Fatal("unoffered managed Prepare feature admitted", err)
			}
			if err := conn.Admit(admission); err != nil {
				t.Fatal("ordinary admission rejected", err)
			}
			retained, err := conn.AuthenticatedNativeHostSession()
			if err != nil || len(retained.ProtocolFeatures) != 1 {
				t.Fatal("rejected feature changed retained session", err)
			}
		}
	}
}

func TestManagedEndpointPrepareExcludedFromGenericRouter(t *testing.T) {
	// A nil daemon and socket prove the reserved type is discarded before
	// generic routing can touch persistence, queues, logging or ACK writers.
	var d *Daemon
	for _, raw := range []string{
		`{"commandId":"` + domain.NewID().String() + `","protocolVersion":"` + transport.ManagedEndpointPrepareProtocol + `"}`,
		`{}`, `null`, `{"commandId":"x","commandId":"y"}`,
	} {
		d.handleCommand(nil, transport.Envelope{Type: transport.MsgManagedEndpointPrepare, Payload: json.RawMessage(raw)})
	}
}
