package sdk

import (
	"encoding/json"
	"testing"
)

func TestRegisterPayloadMessageReceive(t *testing.T) {
	for _, disable := range []bool{false, true} {
		name := "legacy omission"
		if disable {
			name = "explicit opt-out"
		}
		t.Run(name, func(t *testing.T) {
			c := &Client{cfg: Config{DisableMessageReceive: disable}}
			payload, _ := c.registerPayloadVersioned()
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			value, present := fields["receiveMessages"]
			if disable {
				if !present || string(value) != "false" {
					t.Fatalf("receiveMessages = %s, present=%v, want explicit false", value, present)
				}
			} else if present {
				t.Fatalf("default registration carries receiveMessages=%s, want omission", value)
			}
		})
	}
}
