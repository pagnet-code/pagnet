package transport

import (
	"encoding/json"
	"testing"
)

func TestNativeWorkerAvailabilityValidation(t *testing.T) {
	valid := NativeWorkerAvailabilityPayload{InstanceID: "00000000-0000-4000-8000-000000000001", OwnershipGeneration: "00000000-0000-4000-8000-000000000002", Sequence: 1, State: "connected"}
	for _, state := range []string{"connected", "unavailable", "unknown"} {
		p := valid
		p.State = state
		wire, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var decoded NativeWorkerAvailabilityPayload
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded != p || decoded.Validate() != nil {
			t.Fatal("invalid round trip", err)
		}
	}
	for _, mutate := range []func(*NativeWorkerAvailabilityPayload){
		func(p *NativeWorkerAvailabilityPayload) { p.InstanceID = "" },
		func(p *NativeWorkerAvailabilityPayload) { p.OwnershipGeneration = "wrong" },
		func(p *NativeWorkerAvailabilityPayload) { p.Sequence = 0 },
		func(p *NativeWorkerAvailabilityPayload) { p.Sequence = -1 },
		func(p *NativeWorkerAvailabilityPayload) { p.State = "stopped" },
	} {
		p := valid
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("invalid observation accepted", p)
		}
	}
}
