package daemon

// Focused relay round-trip for the Codex real smoke (Wave 4).
//
// The real smoke's whoami turn hung (context deadline exceeded). This test
// isolates the daemon-side half of that path — bridge socket → relayToServer
// → in-memory host connection → agent.response → deliverAgentResponse — from
// the codex/MCP-worker half, so a failure here localizes the hang to the
// daemon relay (not codex, not the MCP worker).

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestCodexSmokeRelayRoundTrip(t *testing.T) {
	d := newTestDaemon(t)
	t.Cleanup(func() { d.stopBridgeSocket() })
	if err := d.startBridgeSocket(); err != nil {
		t.Fatalf("start bridge socket: %v", err)
	}
	instanceID := domain.NewID().String()
	networkID := "net-codex-relay"
	if err := d.state.UpsertInstance(InstanceRow{
		InstanceID: instanceID,
		Runtime:    string(domain.RuntimeCodex),
		Status:     "idle",
		NetworkID:  networkID,
	}); err != nil {
		t.Fatalf("upsert instance: %v", err)
	}

	client, server := newMemWS(t)
	d.connMu.Lock()
	d.curConn = client
	d.connMu.Unlock()
	startWhoamiRelay(t, server, instanceID, networkID)
	// The daemon-side read loop (the piece connectAndRun provides on a real
	// connection): route agent.response envelopes back to the bridge relay.
	go func() {
		for {
			_, raw, err := client.ReadMessage()
			if err != nil {
				return
			}
			var env transport.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				continue
			}
			if env.Type == transport.MsgAgentResponse {
				d.deliverAgentResponse(env)
			}
		}
	}()

	// The exact relay call the bridge handler makes for network_whoami.
	result, errMsg := d.relayToServer(instanceID, "", "network_whoami", nil)
	if errMsg != "" {
		t.Fatalf("relayToServer(network_whoami) error: %q (result=%s)", errMsg, result)
	}
	s := string(result)
	if !strings.Contains(s, "principal-codex-smoke") || !strings.Contains(s, instanceID) {
		t.Fatalf("relay result missing the whoami identity: %s", s)
	}
	t.Logf("relay round-trip OK: %s", s)
}
