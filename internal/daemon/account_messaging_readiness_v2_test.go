package daemon

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func newReadinessSubscriptionFixture(t *testing.T) readinessFixture {
	t.Helper()
	f := newReadinessFixture(t)
	f.session.ProtocolFeatures = []string{transport.AccountMessagingReadinessSubscriptionProtocol}
	f.c.native.mu.Lock()
	f.c.native.session.ProtocolFeatures = f.session.ProtocolFeatures
	f.c.native.mu.Unlock()
	f.frames = make(chan transport.Envelope, 300)
	f.c.subscription = &accountMessagingReadinessSubscription{c: f.c}
	f.c.write = func(raw []byte, guard func() bool) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		if guard() {
			f.frames <- env
		}
		return nil
	}
	return f
}

func readinessSubscriptionFrame() transport.AccountMessagingReadinessSubscriptionFrame {
	return transport.AccountMessagingReadinessSubscriptionFrame{V: 2, Protocol: transport.AccountMessagingReadinessSubscriptionProtocol, SubscriptionID: domain.NewID(), Version: "1"}
}

func readinessSubscriptionSend(t *testing.T, f readinessFixture, kind string, payload any) {
	t.Helper()
	env, err := transport.NewEnvelope(kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	f.c.offer(env)
}

func readinessSubscriptionReset(t *testing.T, f readinessFixture, frame transport.AccountMessagingReadinessSubscriptionFrame) {
	t.Helper()
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessReset, transport.AccountMessagingReadinessSubscriptionResetPayload{AccountMessagingReadinessSubscriptionFrame: frame, Reason: "initial"})
}

func readinessSubscriptionOffer(t *testing.T, f readinessFixture, frame transport.AccountMessagingReadinessSubscriptionFrame, route transport.AccountMessagingReadinessRoute) {
	t.Helper()
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessOffer, transport.AccountMessagingReadinessSubscriptionOfferPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: route})
}

func readinessSubscriptionComplete(t *testing.T, f readinessFixture, frame transport.AccountMessagingReadinessSubscriptionFrame, count int) {
	t.Helper()
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessSnapshotComplete, transport.AccountMessagingReadinessSubscriptionCompletePayload{AccountMessagingReadinessSubscriptionFrame: frame, OfferCount: count, Status: "complete"})
}

func readinessSubscriptionAdmit(t *testing.T, f readinessFixture) {
	t.Helper()
	f.c.admitted()
	e := f.expect(t, transport.MsgAccountMessagingReadinessHello)
	var hello transport.AccountMessagingReadinessSubscriptionHelloPayload
	if json.Unmarshal(e.Payload, &hello) != nil || hello.V != 2 || hello.Protocol != transport.AccountMessagingReadinessSubscriptionProtocol || hello.Reset {
		t.Fatal("invalid initial v2 hello")
	}
	f.network()
	e = f.expect(t, transport.MsgAccountMessagingReadinessHello)
	if json.Unmarshal(e.Payload, &hello) != nil || !hello.Reset {
		t.Fatal("network change did not request reset")
	}
}

func readinessSubscriptionWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(what)
	}
}

func readinessSubscriptionIdle(t *testing.T, f readinessFixture) {
	t.Helper()
	done := make(chan struct{})
	f.c.enqueue(func() { close(done) })
	readinessSubscriptionWait(t, done, "worker did not become idle")
}

func TestAccountMessagingReadinessSubscriptionSnapshots(t *testing.T) {
	for _, count := range []int{0, 1, 256, 257} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newReadinessSubscriptionFixture(t)
			readinessSubscriptionAdmit(t, f)
			frame := readinessSubscriptionFrame()
			readinessSubscriptionReset(t, f, frame)
			offers := make(map[domain.ID]transport.AccountMessagingReadinessRoute)
			for i := 0; i < count; i++ {
				r := f.route
				r.ConnectionID, r.OfferID = domain.NewID(), domain.NewID()
				offers[r.OfferID] = r
				readinessSubscriptionOffer(t, f, frame, r)
			}
			if count == 257 {
				readinessSubscriptionWait(t, f.c.ctx.Done(), "257 offers did not close subscription")
				f.quiet(t)
				return
			}
			f.quiet(t) // Offers cannot trigger ACK before completion.
			readinessSubscriptionComplete(t, f, frame, count)
			for i := 0; i < count; i++ {
				e := f.expect(t, transport.MsgAccountMessagingReadinessAck)
				var ack transport.AccountMessagingReadinessSubscriptionAckPayload
				if json.Unmarshal(e.Payload, &ack) != nil {
					t.Fatal("invalid ACK")
				}
				r, ok := offers[ack.OfferID]
				if !ok || ack.AccountMessagingReadinessSubscriptionFrame != frame || ack.AccountMessagingReadinessCandidate != r.AccountMessagingReadinessCandidate || ack.Generation != r.Generation || ack.Digest != r.Digest {
					t.Fatal("ACK did not echo snapshot offer")
				}
				delete(offers, ack.OfferID)
			}
			readinessSubscriptionIdle(t, f)
			f.quiet(t)
		})
	}
}

func TestAccountMessagingReadinessSubscriptionRejectsFrames(t *testing.T) {
	for _, kind := range []string{"count", "subscription", "version", "route"} {
		t.Run(kind, func(t *testing.T) {
			f := newReadinessSubscriptionFixture(t)
			readinessSubscriptionAdmit(t, f)
			frame := readinessSubscriptionFrame()
			readinessSubscriptionReset(t, f, frame)
			readinessSubscriptionOffer(t, f, frame, f.route)
			switch kind {
			case "count":
				readinessSubscriptionComplete(t, f, frame, 0)
			case "subscription":
				frame.SubscriptionID = domain.NewID()
				readinessSubscriptionComplete(t, f, frame, 1)
			case "version":
				frame.Version = "2"
				readinessSubscriptionComplete(t, f, frame, 1)
			case "route":
				readinessSubscriptionComplete(t, f, frame, 1)
				f.expect(t, transport.MsgAccountMessagingReadinessAck)
				r := f.route
				r.Status, r.AckedAt = "ready", &r.OfferedAt
				r.Digest = "cd" + r.Digest[2:]
				readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, transport.AccountMessagingReadinessSubscriptionAcceptedPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: r})
			}
			readinessSubscriptionWait(t, f.c.ctx.Done(), "invalid frame did not close subscription")
			f.quiet(t)
		})
	}
}

func TestAccountMessagingReadinessSubscriptionResetFencesBlockedWork(t *testing.T) {
	for _, block := range []string{"lookup", "keyring", "writer"} {
		for _, change := range []string{"reset", "revocation", "local", "expiry"} {
			t.Run(block+"/"+change, func(t *testing.T) {
				f := newReadinessSubscriptionFixture(t)
				entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				t.Cleanup(func() { once.Do(func() { close(release) }) })
				if block == "lookup" {
					lookup := f.c.lookup
					f.c.lookup = func(id string) (*InstanceRow, bool, error) {
						close(entered)
						<-release
						defer close(finished)
						return lookup(id)
					}
				} else if block == "keyring" {
					loadKeyring := f.c.loadKeyring
					f.c.loadKeyring = func(network string) (*crypto.Keyring, error) {
						close(entered)
						<-release
						defer close(finished)
						return loadKeyring(network)
					}
				} else {
					write := f.c.write
					f.c.write = func(raw []byte, guard func() bool) error {
						var env transport.Envelope
						if err := json.Unmarshal(raw, &env); err != nil {
							return err
						}
						if env.Type == transport.MsgAccountMessagingReadinessAck {
							close(entered)
							<-release
							defer close(finished)
						}
						return write(raw, guard)
					}
				}
				readinessSubscriptionAdmit(t, f)
				if change == "expiry" {
					f.route.OfferDeadline = time.Now().Add(200 * time.Millisecond)
				}
				frame := readinessSubscriptionFrame()
				readinessSubscriptionReset(t, f, frame)
				readinessSubscriptionOffer(t, f, frame, f.route)
				readinessSubscriptionComplete(t, f, frame, 1)
				readinessSubscriptionWait(t, entered, "worker did not reach blocked operation")
				switch change {
				case "reset":
					frame.Version = "2"
					readinessSubscriptionReset(t, f, frame)
					readinessSubscriptionComplete(t, f, frame, 0)
				case "revocation":
					env, err := transport.NewEnvelope(transport.MsgNetworkCrypto, transport.NetworkCryptoPayload{TenantID: f.session.TenantID, NetworkID: f.route.NetworkID.String(), Status: "degraded", EpochID: f.route.EpochID})
					if err != nil {
						t.Fatal(err)
					}
					f.c.network(env)
				case "local":
					f.c.localEvidenceChanged()
				case "expiry":
					deadline := time.Now().Add(2 * time.Second)
					for {
						f.c.subscription.mu.Lock()
						invalidated := f.c.subscription.awaitingReset
						f.c.subscription.mu.Unlock()
						if invalidated {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("expiry did not invalidate blocked work")
						}
						time.Sleep(time.Millisecond)
					}
				}
				once.Do(func() { close(release) })
				readinessSubscriptionWait(t, finished, "blocked operation did not finish")
				readinessSubscriptionIdle(t, f)
				if change != "reset" && change != "expiry" {
					e := f.expect(t, transport.MsgAccountMessagingReadinessHello)
					var hello transport.AccountMessagingReadinessSubscriptionHelloPayload
					if json.Unmarshal(e.Payload, &hello) != nil || !hello.Reset {
						t.Fatal("invalidation did not request reset")
					}
				}
				f.quiet(t)
				select {
				case <-f.c.ctx.Done():
					t.Fatal("valid reset closed subscription")
				default:
				}
			})
		}
	}
}

func TestAccountMessagingReadinessSubscriptionAcceptanceExpiry(t *testing.T) {
	f := newReadinessSubscriptionFixture(t)
	readinessSubscriptionAdmit(t, f)
	f.route.OfferDeadline = time.Now().Add(200 * time.Millisecond)
	f.route.ExpiresAt = f.route.OfferDeadline.Add(150 * time.Millisecond)
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	f.expect(t, transport.MsgAccountMessagingReadinessAck)
	r := f.route
	r.Status, r.AckedAt = "ready", &r.OfferedAt
	accepted := transport.AccountMessagingReadinessSubscriptionAcceptedPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: r}
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, accepted)
	a := f.c.subscription
	a.mu.Lock()
	count := len(a.accepted)
	a.mu.Unlock()
	if count != 1 {
		t.Fatal("valid acceptance was not recorded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		a.mu.Lock()
		expired := a.awaitingReset
		a.mu.Unlock()
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted evidence did not expire")
		}
		time.Sleep(time.Millisecond)
	}
	f.quiet(t) // Expiry cannot request an unacknowledged reoffer loop.
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, accepted)
	a.mu.Lock()
	count = len(a.accepted) + len(a.pending)
	a.mu.Unlock()
	if count != 0 {
		t.Fatal("expired acceptance restored evidence")
	}
	frame.Version = "2"
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionComplete(t, f, frame, 0)
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, accepted)
	readinessSubscriptionIdle(t, f)
	a.mu.Lock()
	count = len(a.accepted)
	a.mu.Unlock()
	if count != 0 {
		t.Fatal("old version acceptance restored evidence")
	}
	f.quiet(t)
}

func TestAccountMessagingReadinessSubscriptionLegacyIgnoresV2(t *testing.T) {
	f := newReadinessFixture(t)
	if f.c.subscription != nil {
		t.Fatal("v2 enabled on default connection")
	}
	f.c.admitted()
	e := f.expect(t, transport.MsgAccountMessagingReadinessHello)
	var hello transport.AccountMessagingReadinessHelloPayload
	if json.Unmarshal(e.Payload, &hello) != nil || hello.V != 1 || hello.Protocol != transport.AccountMessagingReadinessProtocol {
		t.Fatal("default connection did not use v1")
	}
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
}

func TestAccountMessagingReadinessSubscriptionDefaultOffServerQuiet(t *testing.T) {
	f := newReadinessSubscriptionFixture(t)
	f.c.admitted()
	e := f.expect(t, transport.MsgAccountMessagingReadinessHello)
	var hello transport.AccountMessagingReadinessSubscriptionHelloPayload
	if json.Unmarshal(e.Payload, &hello) != nil || hello.V != 2 || hello.Reset {
		t.Fatal("invalid initial hello")
	}
	// A server with subscriptions disabled sends no readiness response.
	// The client must remain quiet instead of polling or falling back to v1.
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
	select {
	case <-f.c.ctx.Done():
		t.Fatal("silent server closed readiness connection")
	default:
	}
}

func TestAccountMessagingReadinessSubscriptionRequiresServerFeature(t *testing.T) {
	f := newReadinessFixture(t)
	f.c.subscription = &accountMessagingReadinessSubscription{c: f.c}
	f.c.admitted()
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
	f.network()
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	for _, message := range []struct {
		kind    string
		payload any
	}{
		{transport.MsgAccountMessagingReadinessReset, transport.AccountMessagingReadinessSubscriptionResetPayload{AccountMessagingReadinessSubscriptionFrame: frame, Reason: "initial"}},
		{transport.MsgAccountMessagingReadinessOffer, transport.AccountMessagingReadinessSubscriptionOfferPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: f.route}},
		{transport.MsgAccountMessagingReadinessSnapshotComplete, transport.AccountMessagingReadinessSubscriptionCompletePayload{AccountMessagingReadinessSubscriptionFrame: frame, OfferCount: 1, Status: "complete"}},
	} {
		env, err := transport.NewEnvelope(message.kind, message.payload)
		if err != nil {
			t.Fatal(err)
		}
		f.c.subscription.handle(env)
	}
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
	f.c.subscription.mu.Lock()
	count := len(f.c.subscription.offers) + len(f.c.subscription.pending) + len(f.c.subscription.accepted)
	f.c.subscription.mu.Unlock()
	if count != 0 {
		t.Fatal("unnegotiated frames established subscription evidence")
	}
}

func TestAccountMessagingReadinessSubscriptionResetFencesContendedWriter(t *testing.T) {
	f := newReadinessFixture(t)
	f.session.ProtocolFeatures = []string{transport.AccountMessagingReadinessSubscriptionProtocol}
	f.c.native.mu.Lock()
	f.c.native.session.ProtocolFeatures = f.session.ProtocolFeatures
	f.c.native.mu.Unlock()
	f.c.subscription = &accountMessagingReadinessSubscription{c: f.c}
	entered, finished := make(chan struct{}), make(chan struct{})
	write := f.c.write
	f.c.write = func(raw []byte, guard func() bool) error {
		var env transport.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		if env.Type == transport.MsgAccountMessagingReadinessAck {
			close(entered)
			defer close(finished)
		}
		return write(raw, guard)
	}
	readinessSubscriptionAdmit(t, f)
	f.c.d.writeMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			f.c.d.writeMu.Unlock()
		}
	})
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	readinessSubscriptionWait(t, entered, "ACK did not reach shared writer contention")
	frame.Version = "2"
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionComplete(t, f, frame, 0)
	f.c.d.writeMu.Unlock()
	locked = false
	readinessSubscriptionWait(t, finished, "guarded shared writer did not finish")
	readinessSubscriptionIdle(t, f)
	f.quiet(t)
}

func TestAccountMessagingReadinessSubscriptionReplacementIgnoresOldAccepted(t *testing.T) {
	f := newReadinessSubscriptionFixture(t)
	readinessSubscriptionAdmit(t, f)
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	f.expect(t, transport.MsgAccountMessagingReadinessAck)
	r := f.route
	r.Status, r.AckedAt = "ready", &r.OfferedAt
	old := transport.AccountMessagingReadinessSubscriptionAcceptedPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: r}
	f.c.close()
	replacement := NewNativeObservationConnection("https://example.test", f.session.HostID, "replacement", nil)
	replacement.session = &f.session
	f.c.d.connMu.Lock()
	f.c.d.nativeConn = replacement
	f.c.d.connMu.Unlock()
	next := newAccountMessagingReadinessSubscriptionConnection(f.c.d, f.c.socket, replacement)
	t.Cleanup(next.close)
	next.write = f.c.write
	f.c = next
	readinessSubscriptionAdmit(t, f)
	readinessSubscriptionReset(t, f, readinessSubscriptionFrame())
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, old)
	readinessSubscriptionIdle(t, f)
	next.subscription.mu.Lock()
	count := len(next.subscription.accepted) + len(next.subscription.pending)
	next.subscription.mu.Unlock()
	if count != 0 {
		t.Fatal("replacement inherited old acceptance")
	}
	select {
	case <-next.ctx.Done():
		t.Fatal("old acceptance closed replacement")
	default:
	}
	f.quiet(t)
}

func TestAccountMessagingReadinessSubscriptionLocalMutationGate(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		t.Run(fmt.Sprint(reconnect), func(t *testing.T) {
			f := newReadinessSubscriptionFixture(t)
			readinessSubscriptionAdmit(t, f)
			f.c.d.connMu.Lock()
			f.c.d.accountReadiness = f.c
			f.c.d.connMu.Unlock()
			finish := f.c.d.beginAccountMessagingMutation()
			var once sync.Once
			t.Cleanup(func() { once.Do(finish) })
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			if reconnect {
				f.c.close()
				replacement := NewNativeObservationConnection("https://example.test", f.session.HostID, "replacement", nil)
				replacement.session = &f.session
				next := newAccountMessagingReadinessSubscriptionConnection(f.c.d, f.c.socket, replacement)
				t.Cleanup(next.close)
				next.write = f.c.write
				f.c.d.connMu.Lock()
				f.c.d.nativeConn = replacement
				f.c.d.accountReadiness = next
				f.c.d.connMu.Unlock()
				f.c = next
				readinessSubscriptionAdmit(t, f)
			}
			frame := readinessSubscriptionFrame()
			readinessSubscriptionReset(t, f, frame)
			readinessSubscriptionOffer(t, f, frame, f.route)
			readinessSubscriptionComplete(t, f, frame, 1)
			readinessSubscriptionIdle(t, f)
			f.quiet(t)
			once.Do(finish)
			e := f.expect(t, transport.MsgAccountMessagingReadinessHello)
			var hello transport.AccountMessagingReadinessSubscriptionHelloPayload
			if json.Unmarshal(e.Payload, &hello) != nil || !hello.Reset {
				t.Fatal("mutation commit did not request reset")
			}
			frame.Version = "2"
			readinessSubscriptionReset(t, f, frame)
			readinessSubscriptionOffer(t, f, frame, f.route)
			readinessSubscriptionComplete(t, f, frame, 1)
			f.expect(t, transport.MsgAccountMessagingReadinessAck)
			readinessSubscriptionIdle(t, f)
			f.quiet(t)
		})
	}
}

func TestAccountMessagingReadinessSubscriptionCapacityExceeded(t *testing.T) {
	f := newReadinessSubscriptionFixture(t)
	readinessSubscriptionAdmit(t, f)
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	f.expect(t, transport.MsgAccountMessagingReadinessAck)
	r := f.route
	r.Status, r.AckedAt = "ready", &r.OfferedAt
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessAccepted, transport.AccountMessagingReadinessSubscriptionAcceptedPayload{AccountMessagingReadinessSubscriptionFrame: frame, Route: r})
	frame.Version = "2"
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionSend(t, f, transport.MsgAccountMessagingReadinessSnapshotComplete, transport.AccountMessagingReadinessSubscriptionCompletePayload{AccountMessagingReadinessSubscriptionFrame: frame, OfferCount: 0, Status: "capacity_exceeded"})
	a := f.c.subscription
	a.mu.Lock()
	retained := len(a.offers) + len(a.pending) + len(a.accepted)
	a.mu.Unlock()
	if retained != 0 {
		t.Fatal("capacity snapshot retained evidence")
	}
	f.quiet(t)
}
