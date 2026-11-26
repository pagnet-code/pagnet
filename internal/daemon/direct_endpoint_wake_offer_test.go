//go:build linux || darwin

package daemon

import (
	"net/url"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectEndpointWakeURLReadyTarget(t *testing.T) {
	d := &Daemon{Config: Config{ServerURL: "https://example.test?direct_endpoint_wake=bad&direct_endpoint_wake=duplicate", ManagedEndpointPrepareEnabled: true, ManagedEndpointPoPEnabled: true, ManagedDirectCredentialEnabled: true}, managedEndpointPrepare: &managedPrepareLaneExecutor{available: true}, managedEndpointPoP: &managedPoPLaneExecutor{available: true}, managedDirectCredential: &managedCredentialLaneExecutor{available: true}}
	for _, ready := range []bool{true, false, true} {
		d.managedDirectCredential.(*managedCredentialLaneExecutor).available = ready
		u, err := url.Parse(d.wsURLWithSnapshotSigningKey(t.Context(), ""))
		if err != nil {
			t.Fatal(err)
		}
		values := u.Query()[transport.DirectEndpointWakeQueryKey]
		if ready {
			if len(values) != 1 || values[0] != transport.DirectEndpointWakeProtocolV1 {
				t.Fatal("ready target missing exact wake offer", values)
			}
		} else if len(values) != 0 {
			t.Fatal("unready target advertised wake")
		}
		if d.nativeServerURL() != "https://example.test" {
			t.Fatal("wake offer entered native authority")
		}
	}
}
