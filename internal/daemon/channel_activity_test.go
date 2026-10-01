package daemon

import (
	"encoding/json"
	"github.com/pagnet-code/pagnet/domain"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
	"github.com/pagnet-code/pagnet/transport"
	"testing"
	"time"
)

func TestStartedTurnReportsExactDeliveryCommand(t *testing.T) {
	d := newTestDaemon(t)
	client, server := newMemWS(t)
	for _, command := range []string{"delivery-command", ""} {
		spec := agentruntime.TurnSpec{TurnID: "turn", InstanceID: "instance", InputKind: "channel", Metadata: map[string]any{"deliveryCommandId": command}}
		d.sendTurn(client, transport.MsgRuntimeTurnStarted, spec, "session", nil, nil, nil, "", "", nil)
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		var env transport.Envelope
		if err := server.ReadJSON(&env); err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if command != "" && payload["commandId"] != command {
			t.Fatalf("missing actual delivery correlation: %#v", payload)
		}
		if command == "" {
			if _, ok := payload["commandId"]; ok {
				t.Fatal("undelivered turn claims command")
			}
		}
	}
}

func TestChannelDeliveryStartedReportsCommandThroughRealRuntime(t *testing.T) {
	d := newPersistentTestDaemon(t)
	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	instance := domain.NewID().String()
	driveLaunch(t, d, server, transport.LaunchAgentPayload{CommandID: "activity-launch", InstanceID: instance, Runtime: string(domain.RuntimeFakePersistent), Kind: "representative"})
	waitForEndpointLive(t, d, instance)
	envelopes := driveDeliver(t, d, server, transport.NetworkEventPayload{CommandID: "activity-delivery", InstanceID: instance, Kind: "channel", ConversationID: "chat", Body: "hello"})
	for _, env := range envelopes {
		if env.Type == transport.MsgRuntimeTurnStarted {
			payload := envelopePayload(t, env)
			if payload["commandId"] != "activity-delivery" || payload["inputKind"] != "channel" {
				t.Fatalf("wrong actual turn correlation %#v", payload)
			}
			return
		}
	}
	t.Fatal("no runtime started event")
}
