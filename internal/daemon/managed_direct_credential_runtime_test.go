//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedCredentialRuntimeOffer(t *testing.T) {
	for _, reason := range []string{"exact", "off", "prepare", "pop", "credential", "unrelated", "malformed"} {
		t.Run(reason, func(t *testing.T) {
			d, _, _, executor, _ := managedCredentialLaneFixture(t)
			d.ServerURL += "?managed_direct_credential=wrong&managed_direct_credential=duplicate&managed_endpoint_prepare=wrong&managed_endpoint_pop=wrong"
			switch reason {
			case "off":
				d.ManagedDirectCredentialEnabled = false
			case "prepare":
				d.managedEndpointPrepare = nil
			case "pop":
				d.managedEndpointPoP = nil
			case "credential":
				executor.available = false
			case "unrelated":
				d.ServerURL += "&unrelated=value"
			case "malformed":
				d.ServerURL += "&managed_direct_credential=%zz"
			}
			endpoint, err := url.Parse(d.wsURL(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			got := endpoint.Query()["managed_direct_credential"]
			if reason == "exact" {
				if len(got) != 1 || got[0] != transport.ManagedDirectCredentialProtocol {
					t.Fatal("incorrect exact offer", got)
				}
				if d.nativeServerURL() != "https://example.test" {
					t.Fatal("query became native authority")
				}
			} else if len(got) != 0 {
				t.Fatal("unready target offered", got)
			}
		})
	}
}

func TestManagedCredentialNegotiation(t *testing.T) {
	for _, reason := range []string{"downgrade", "duplicate", "unoffered", "prepare", "pop"} {
		t.Run(reason, func(t *testing.T) {
			_, lane, _, executor, issue := managedCredentialLaneFixture(t)
			session := lane.negotiation.session
			session.ProtocolFeatures = append([]string(nil), session.ProtocolFeatures...)
			switch reason {
			case "downgrade":
				session.ProtocolFeatures = session.ProtocolFeatures[:len(session.ProtocolFeatures)-1]
			case "duplicate":
				session.ProtocolFeatures = append(session.ProtocolFeatures, transport.ManagedDirectCredentialProtocol)
			case "unoffered":
				lane.native.offeredManagedDirectCredential = false
			case "prepare":
				lane.native.offeredManagedEndpointPrepare = false
			case "pop":
				lane.native.offeredManagedEndpointPoP = false
			}
			if err := lane.native.Admit(session); err == nil {
				t.Fatal("invalid target negotiation admitted")
			}
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
			select {
			case <-executor.started:
				t.Fatal("revoked negotiation executed")
			default:
			}
		})
	}
}

func TestManagedCredentialLanePacketIsolation(t *testing.T) {
	_, lane, _, executor, issue := managedCredentialLaneFixture(t)
	_, source, _ := directSourceCredentialFixtureV2(t)
	if lane.handle(nativeBindingEnvelope(t, transport.MsgDirectManagedSourceCredentialV2, source)) {
		t.Fatal("target consumed source lane")
	}
	if !lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, source)) {
		t.Fatal("source payload escaped target lane")
	}
	raw, _ := issue.CanonicalBytes()
	malformed := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unexpected":true}`)...)
	lane.handle(transport.Envelope{Type: transport.MsgManagedDirectCredential, Payload: malformed})
	select {
	case <-executor.started:
		t.Fatal("invalid packet executed")
	default:
	}
}

func TestManagedCredentialLaneExactRedelivery(t *testing.T) {
	_, lane, peer, executor, issue := managedCredentialLaneFixture(t)
	// The first ACK may collide with the server command-row transaction. It has
	// no receipt; only retained exact server redelivery triggers an idempotent replay.
	var first []byte
	for i := 0; i < 2; i++ {
		lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		var env transport.Envelope
		if err := peer.ReadJSON(&env); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = append([]byte(nil), env.Payload...)
		} else if string(first) != string(env.Payload) {
			t.Fatal("redelivery changed ACK")
		}
	}
	if len(executor.started) != 2 {
		t.Fatal("redelivery not revalidated")
	}
}

func TestManagedCredentialLaneInvalidACK(t *testing.T) {
	for _, reason := range []string{"wrong-id", "source", "late", "authority"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, peer, executor, issue := managedCredentialLaneFixture(t)
			switch reason {
			case "wrong-id":
				var ack transport.ManagedDirectCredentialACK
				if err := json.Unmarshal(executor.result, &ack); err != nil {
					t.Fatal(err)
				}
				ack.CredentialID = issue.PoP.Prepare.CommandID
				executor.result, _ = ack.CanonicalBytes()
			case "source":
				executor.result = []byte(`{"protocolVersion":"direct_managed_source_credential_v2"}`)
			case "late":
				issue.InstallExpiresAt = time.Now().Add(-time.Second)
			case "authority":
				d.curConn = nil
			}
			lane.handle(nativeBindingEnvelope(t, transport.MsgManagedDirectCredential, issue))
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := peer.ReadMessage(); err == nil {
				t.Fatal("invalid ACK published")
			}
		})
	}
}

func TestManagedCredentialRuntimeStartupRecovery(t *testing.T) {
	_, _, d, _, _ := managedCredentialAuthorityFixture(t)
	registry := d.nativeRegistry
	d.nativeRegistry = nil
	d.ManagedEndpointPrepareEnabled = true
	d.ManagedEndpointPoPEnabled = true
	d.ManagedDirectCredentialEnabled = true
	prepare := &managedPrepareLaneExecutor{available: false}
	pop := &managedPoPLaneExecutor{available: false}
	d.managedEndpointPrepare = prepare
	d.managedEndpointPoP = pop
	offer := func() []string {
		t.Helper()
		endpoint, err := url.Parse(d.wsURL(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		return endpoint.Query()["managed_direct_credential"]
	}
	// A failed startup construction must be retried on the next connection.
	if got := offer(); len(got) != 0 || d.managedDirectCredential != nil {
		t.Fatal("failed startup offered custody", got)
	}
	d.nativeRegistry = registry
	if got := offer(); len(got) != 0 || d.managedDirectCredential == nil {
		t.Fatal("unready executor was not retained", got)
	}
	retained := d.managedDirectCredential
	lock, err := os.CreateTemp(t.TempDir(), "serve.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	d.serveLockFile = lock
	prepare.available = true
	pop.available = true
	for attempt := 0; attempt < 2; attempt++ {
		got := offer()
		if len(got) != 1 || got[0] != transport.ManagedDirectCredentialProtocol {
			t.Fatal("healthy reconnect did not offer exact custody", got)
		}
		if d.managedDirectCredential != retained {
			t.Fatal("reconnect replaced retained custody")
		}
	}
}

func TestManagedCredentialRuntimeReconnectRecoversOffer(t *testing.T) {
	offers := make(chan []string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offers <- r.URL.Query()["managed_direct_credential"]
		http.Error(w, "retry connection", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	d := newTestDaemon(t)
	d.ServerURL = server.URL
	d.ManagedEndpointPrepareEnabled = true
	d.ManagedEndpointPoPEnabled = true
	d.ManagedDirectCredentialEnabled = true
	prepare := &managedPrepareLaneExecutor{available: false}
	pop := &managedPoPLaneExecutor{available: false}
	d.managedEndpointPrepare = prepare
	d.managedEndpointPoP = pop
	reconnect := func() []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		if _, err := d.connectAndRun(ctx); err == nil {
			t.Fatal("test server should reject upgrade")
		}
		select {
		case got := <-offers:
			return got
		default:
			t.Fatal("connection did not reach server")
			return nil
		}
	}
	if got := reconnect(); len(got) != 0 || d.managedDirectCredential == nil {
		t.Fatal("unready connection did not retain dormant custody", got)
	}
	retained := d.managedDirectCredential
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	prepare.available = true
	pop.available = true
	got := reconnect()
	if len(got) != 1 || got[0] != transport.ManagedDirectCredentialProtocol || d.managedDirectCredential != retained {
		t.Fatal("healthy reconnect did not offer retained custody", got)
	}
}
