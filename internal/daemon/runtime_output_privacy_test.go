package daemon

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestNetworkOutputWithoutCryptoStreamCannotFallBackToPlaintext(t *testing.T) {
	for _, network := range []string{"", "network-provisioning"} {
		t.Run(network, func(t *testing.T) {
			client, peer := newMemWS(t)
			d := &Daemon{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), writeTimeout: 5 * time.Second}
			d.sendRuntimeOutput(client, &InstanceRow{InstanceID: "instance", NetworkID: network}, "", "private runtime content")
			if network != "" {
				// A later control frame proves the connection works and gives
				// a deterministic boundary: no content may precede it.
				if err := d.send(client, transport.MsgHeartbeat, map[string]any{"marker": "after-output"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var env transport.Envelope
			err := peer.ReadJSON(&env)
			if network != "" {
				if err != nil || env.Type != transport.MsgHeartbeat {
					t.Fatalf("network without an encryption stream emitted content before the control frame: %v %+v", err, env)
				}
				return
			}
			// Unscoped representative output follows the separate host relay.
			if err != nil || env.Type != transport.MsgRuntimeOutput {
				t.Fatalf("unscoped relay: %v %+v", err, env)
			}
			p := envelopePayload(t, env)
			if p["output"] != "private runtime content" {
				t.Fatalf("unscoped relay payload: %+v", p)
			}
		})
	}
}
