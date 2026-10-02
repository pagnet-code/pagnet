//go:build linux || darwin

package daemon

import (
	"encoding/json"
	"testing"
)

func TestOwnedCapabilityDeclarationUsesOriginalNativeRelay(t *testing.T) {
	registry, scope, spec := nativeRegistryFixture(t)
	if _, err := registry.Reserve(scope, spec, "original", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeRegistry: registry}
	row := &InstanceRow{InstanceID: scope.InstanceID, Kind: "worker", NetworkID: spec.NetworkID}
	args := json.RawMessage(`{"capabilities":[{"id":"original.echo","name":"Original echo"}]}`)
	calls := 0
	result, message := d.executeBridgeToolWithRead(row, "network_register_capabilities", args, func(tool string, got json.RawMessage) (json.RawMessage, string) {
		calls++
		if tool != "network_register_capabilities" || string(got) != string(args) {
			t.Fatal("declaration mutated")
		}
		return json.RawMessage(`{"registered":[{"id":"original.echo"}],"count":1}`), ""
	}, nil)
	if message != "" || calls != 1 || len(result) == 0 {
		t.Fatal("owned declaration bypassed native relay", calls, message)
	}
	_, message = d.executeBridgeToolWithRead(row, "network_register_capabilities", args, func(string, json.RawMessage) (json.RawMessage, string) {
		return nil, "native source context unavailable"
	}, nil)
	if message != "native source context unavailable" {
		t.Fatal("rejected native authority fell back to local publication")
	}
}
