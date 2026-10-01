package daemon

import (
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestWakeRejectsInvalidPayloadWithoutChangingInstance(t *testing.T) {
	for _, payload := range []string{`{`, `{}`, `{"instanceId":"sleeping","reason":"work_queued"}`} {
		t.Run(payload, func(t *testing.T) {
			d := newTestDaemon(t)
			if err := d.state.UpsertInstance(InstanceRow{InstanceID: "sleeping", Status: "hibernated", SessionID: "original-session"}); err != nil {
				t.Fatal(err)
			}
			// Missing identifiers are valid JSON but must not crash the command
			// processor or claim work with an unacknowledgeable generation.
			d.handleCommand(nil, transport.Envelope{Type: transport.MsgWakeAgent, Payload: json.RawMessage(payload)})
			row, ok, err := d.state.GetInstance("sleeping")
			if err != nil || !ok || row.Status != "hibernated" || row.SessionID != "original-session" {
				t.Fatalf("invalid wake changed the preserved instance: %+v %v", row, err)
			}
			d.seenMu.Lock()
			claimed := len(d.seen)
			d.seenMu.Unlock()
			if claimed != 0 {
				t.Fatal("invalid wake claimed a command")
			}
		})
	}
}
