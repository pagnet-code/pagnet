package daemon

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func wakeOffer(source bool) url.Values {
	q := url.Values{transport.DirectEndpointWakeQueryKey: {transport.DirectEndpointWakeProtocolV1}}
	if source {
		for i, key := range directManagedSourceQueryKeys {
			q.Set(key, directManagedSourceProtocolsV2[i])
		}
	} else {
		q.Set("managed_endpoint_prepare", transport.ManagedEndpointPrepareProtocol)
		q.Set("managed_endpoint_pop", transport.ManagedEndpointPoPProtocol)
		q.Set("managed_direct_credential", transport.ManagedDirectCredentialProtocol)
	}
	return q
}
func wakeNative(t *testing.T, q url.Values) (*NativeObservationConnection, transport.HostSessionPayload) {
	t.Helper()
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	c := NewNativeObservationConnection("https://example.test", host, boot, func(context.Context, string, any) error { t.Fatal("inert wake lane sent traffic"); return nil })
	c.captureDirectManagedSourceOffers(q)
	c.offeredManagedEndpointPrepare = q.Get("managed_endpoint_prepare") == transport.ManagedEndpointPrepareProtocol
	c.offeredManagedEndpointPoP = q.Get("managed_endpoint_pop") == transport.ManagedEndpointPoPProtocol
	c.offeredManagedDirectCredential = q.Get("managed_direct_credential") == transport.ManagedDirectCredentialProtocol
	c.captureDirectEndpointWakeOffer(q)
	p := transport.HostSessionPayload{HostID: host, BootID: boot, TenantID: host, AccountID: host, NativeAdmissionID: runner, RunnerID: runner, OwnershipScope: "personal", RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol, transport.DirectEndpointWakeFeatureV1}}
	for key, values := range q {
		if key != transport.DirectEndpointWakeQueryKey {
			p.ProtocolFeatures = append(p.ProtocolFeatures, values[0])
		}
	}
	return c, p
}

func TestDirectEndpointWakeSelection(t *testing.T) {
	for _, source := range []bool{false, true} {
		for _, reason := range []string{"exact", "omitted", "unsolicited", "duplicate", "duplicate-offer", "missing-suite", "role-mismatch", "partial-suite", "source-v1"} {
			t.Run(reason+map[bool]string{true: "/source", false: "/target"}[source], func(t *testing.T) {
				q := wakeOffer(source)
				if reason == "unsolicited" {
					q.Del(transport.DirectEndpointWakeQueryKey)
				}
				if reason == "duplicate-offer" {
					q.Add(transport.DirectEndpointWakeQueryKey, transport.DirectEndpointWakeProtocolV1)
				}
				c, p := wakeNative(t, q)
				switch reason {
				case "omitted":
					p.ProtocolFeatures = p.ProtocolFeatures[0:1]
				case "duplicate":
					p.ProtocolFeatures = append(p.ProtocolFeatures, transport.DirectEndpointWakeFeatureV1)
				case "missing-suite":
					p.ProtocolFeatures = p.ProtocolFeatures[:2]
				case "role-mismatch":
					p.ProtocolFeatures = p.ProtocolFeatures[:2]
					for key, values := range wakeOffer(!source) {
						if key != transport.DirectEndpointWakeQueryKey {
							p.ProtocolFeatures = append(p.ProtocolFeatures, values[0])
						}
					}
				case "partial-suite":
					p.ProtocolFeatures = p.ProtocolFeatures[:len(p.ProtocolFeatures)-1]
				case "source-v1":
					p.ProtocolFeatures = append(p.ProtocolFeatures[:2], directManagedSourceProtocolsV1[:]...)
					c.captureDirectManagedSourceOffers(url.Values{directManagedSourceQueryKeys[0]: {directManagedSourceProtocolsV1[0]}, directManagedSourceQueryKeys[1]: {directManagedSourceProtocolsV1[1]}, directManagedSourceQueryKeys[2]: {directManagedSourceProtocolsV1[2]}})
				}
				err := c.Admit(p)
				if (err == nil) != (reason == "exact" || reason == "omitted") {
					t.Fatalf("selection: %v", err)
				}
			})
		}
	}
}

func TestDirectEndpointWakeReplayAndReconnect(t *testing.T) {
	q := wakeOffer(true)
	c, p := wakeNative(t, q)
	socket := new(websocket.Conn)
	lane := newDirectEndpointWakeConnection(socket, c)
	if lane.socket != socket || lane.native != c {
		t.Fatal("lane lost captured connection")
	}
	if err := c.Admit(p); err != nil {
		t.Fatal(err)
	}
	replay := p
	replay.ProtocolFeatures = append([]string(nil), p.ProtocolFeatures...)
	for i, j := 0, len(replay.ProtocolFeatures)-1; i < j; i, j = i+1, j-1 {
		replay.ProtocolFeatures[i], replay.ProtocolFeatures[j] = replay.ProtocolFeatures[j], replay.ProtocolFeatures[i]
	}
	if err := c.Admit(replay); err != nil {
		t.Fatal("exact replay rejected", err)
	}
	replay.ProtocolFeatures = nil
	for _, feature := range p.ProtocolFeatures {
		if feature != transport.DirectEndpointWakeFeatureV1 {
			replay.ProtocolFeatures = append(replay.ProtocolFeatures, feature)
		}
	}
	if c.Admit(replay) == nil {
		t.Fatal("changed selection replay accepted")
	}
	replay = p
	replay.NativeAdmissionID = domain.NewID().String()
	if c.Admit(replay) == nil {
		t.Fatal("changed admission replay accepted")
	}
	for _, typ := range []string{transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeOffer, transport.MsgDirectEndpointWakeACK, transport.MsgDirectEndpointWakeUnsubscribe, transport.MsgDirectEndpointWakeClosed} {
		if handled, err := lane.handle(transport.Envelope{Type: typ, Payload: []byte(`{}`)}); !handled || err != ErrNativeObservationConflict {
			t.Fatal("unattached reserved message did not reject connection")
		}
	}
	if handled, err := lane.handle(transport.Envelope{Type: "unrelated"}); handled || err != nil {
		t.Fatal("unrelated message consumed")
	}
	c.Close()
	c.Close()
	lane.close()
	select {
	case <-lane.done:
	default:
		t.Fatal("lane survived connection close")
	}
	if c.Admit(p) != ErrNativeOriginAdmissionDeferred {
		t.Fatal("closed connection admitted replay")
	}
	next, nextSession := wakeNative(t, url.Values{})
	nextLane := newDirectEndpointWakeConnection(new(websocket.Conn), next)
	defer next.Close()
	nextSession.ProtocolFeatures = append(nextSession.ProtocolFeatures, transport.DirectEndpointWakeFeatureV1)
	if next.Admit(nextSession) == nil {
		t.Fatal("reconnect inherited previous negotiation")
	}
	select {
	case <-nextLane.done:
		t.Fatal("old close reached replacement lane")
	default:
	}
}

func TestDirectEndpointWakeURLStripsInheritedOffer(t *testing.T) {
	d := &Daemon{Config: Config{ServerURL: "https://example.test?direct_endpoint_wake=bad&direct_endpoint_wake=direct-endpoint-wake-v1"}}
	u, err := url.Parse(d.wsURLWithSnapshotSigningKey(t.Context(), ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Query()[transport.DirectEndpointWakeQueryKey]; ok {
		t.Fatal("inherited offer survived without supported suite")
	}
	for _, source := range []bool{false, true} {
		q := wakeOffer(source)
		if !directEndpointWakeSuiteOffered(q) {
			t.Fatal("supported suite unavailable")
		}
		key := "managed_direct_credential"
		if source {
			key = directManagedSourceQueryKeys[2]
		}
		q.Add(key, q.Get(key))
		if directEndpointWakeSuiteOffered(q) {
			t.Fatal("duplicate suite offer accepted")
		}
	}
}
