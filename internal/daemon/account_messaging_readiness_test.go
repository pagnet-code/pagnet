package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

type readinessFixture struct {
	c       *accountMessagingReadinessConnection
	session transport.HostSessionPayload
	route   transport.AccountMessagingReadinessRoute
	frames  chan transport.Envelope
}

func newReadinessFixture(t *testing.T) readinessFixture {
	t.Helper()
	frames := make(chan transport.Envelope, 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var e transport.Envelope
			if conn.ReadJSON(&e) != nil {
				return
			}
			frames <- e
		}
	}))
	t.Cleanup(server.Close)
	socket, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	dir := t.TempDir()
	state, err := OpenState(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.db.Close() })
	id := func() domain.ID { return domain.NewID() }
	now := time.Now().UTC()
	s := transport.HostSessionPayload{TenantID: id().String(), AccountID: id().String(), OwnershipScope: "personal", HostID: id().String(), RunnerID: id().String(), RunnerEpoch: now.Add(-time.Minute)}
	d := &Daemon{HostID: s.HostID, StateDir: dir, state: state, writeTimeout: time.Second}
	n := NewNativeObservationConnection("https://example.test", s.HostID, "boot", nil)
	n.session = &s
	d.curConn = socket
	d.nativeConn = n
	network := id()
	kr := crypto.NewKeyring(network.String())
	epoch, err := kr.Activate(now)
	if err != nil {
		t.Fatal(err)
	}
	if err = crypto.SaveKeyring(dir, kr); err != nil {
		t.Fatal(err)
	}
	r := transport.AccountMessagingReadinessRoute{AccountMessagingReadinessCandidate: transport.AccountMessagingReadinessCandidate{ConnectionID: id(), NetworkID: network, TargetPrincipalID: id(), HostID: domain.ID(s.HostID)}, LogicalSenderID: id(), Generation: 1, ConsentID: id(), ResourceID: "resource", IdentityIncarnationID: domain.NewID().String(), DesiredRevision: 1, TargetDefinitionID: id(), TargetInstanceID: id(), RunnerID: domain.ID(s.RunnerID), RunnerConnectedAt: s.RunnerEpoch, ServerInstanceID: "server", HostConnectionGeneration: 1, KeyHolderID: id(), EpochID: epoch.ID, OfferID: id(), Digest: strings.Repeat("ab", 32), OfferedAt: now.Add(-time.Second), OfferDeadline: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), Status: "offered"}
	if err = state.UpsertInstance(InstanceRow{InstanceID: r.TargetInstanceID.String(), DefinitionID: r.TargetDefinitionID.String(), NetworkID: r.NetworkID.String(), AgentPrincipalID: r.TargetPrincipalID.String(), Status: "idle"}); err != nil {
		t.Fatal(err)
	}
	c := newAccountMessagingReadinessConnection(d, socket, n)
	t.Cleanup(c.close)
	return readinessFixture{c, s, r, frames}
}
func (f readinessFixture) network() {
	e, _ := transport.NewEnvelope(transport.MsgNetworkCrypto, transport.NetworkCryptoPayload{TenantID: f.session.TenantID, NetworkID: f.route.NetworkID.String(), Status: "active", EpochID: f.route.EpochID})
	f.c.network(e)
}
func (f readinessFixture) offer() {
	e, _ := transport.NewEnvelope(transport.MsgAccountMessagingReadinessOffer, transport.AccountMessagingReadinessOfferPayload{V: 1, Protocol: transport.AccountMessagingReadinessProtocol, Route: f.route})
	f.c.offer(e)
}
func (f readinessFixture) expect(t *testing.T, typ string) transport.Envelope {
	t.Helper()
	select {
	case e := <-f.frames:
		if e.Type != typ {
			t.Fatalf("got %s want %s", e.Type, typ)
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("missing frame")
	}
	return transport.Envelope{}
}
func (f readinessFixture) quiet(t *testing.T) {
	t.Helper()
	select {
	case e := <-f.frames:
		t.Fatalf("unexpected frame %s", e.Type)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestAccountMessagingReadinessConnection(t *testing.T) {
	f := newReadinessFixture(t)
	f.offer()
	f.quiet(t)
	f.c.admitted()
	f.expect(t, transport.MsgAccountMessagingReadinessHello)
	f.offer()
	f.quiet(t) // persisted crypto state cannot stand in for this socket
	f.network()
	f.expect(t, transport.MsgAccountMessagingReadinessHello)
	f.network()
	f.quiet(t)
	f.offer()
	e := f.expect(t, transport.MsgAccountMessagingReadinessAck)
	var ack transport.AccountMessagingReadinessAckPayload
	if json.Unmarshal(e.Payload, &ack) != nil || ack.OfferID != f.route.OfferID || ack.Digest != f.route.Digest || ack.Generation != f.route.Generation || ack.ConnectionID != f.route.ConnectionID {
		t.Fatal("ACK did not echo offer")
	}
	f.offer()
	f.quiet(t)
	// A replacement connection cannot inherit this controller's network evidence.
	replacement := NewNativeObservationConnection("https://example.test", f.session.HostID, "boot", nil)
	replacement.session = &f.session
	f.c.d.connMu.Lock()
	f.c.d.nativeConn = replacement
	f.c.d.connMu.Unlock()
	f.route.OfferID = domain.NewID()
	f.offer()
	f.quiet(t)
	next := newAccountMessagingReadinessConnection(f.c.d, f.c.socket, replacement)
	defer next.close()
	next.admitted()
	f.expect(t, transport.MsgAccountMessagingReadinessHello)
	e, _ = transport.NewEnvelope(transport.MsgAccountMessagingReadinessOffer, transport.AccountMessagingReadinessOfferPayload{V: 1, Protocol: transport.AccountMessagingReadinessProtocol, Route: f.route})
	next.offer(e)
	f.quiet(t)
	replacement.Close()
	next.admitted()
	f.quiet(t)
}

func TestAccountMessagingReadinessRejectsMismatches(t *testing.T) {
	for _, name := range []string{"host", "runner", "runnerEpoch", "tenant", "epoch", "instance", "definition", "principal", "expired", "future", "stopped", "revoked", "missingKey", "ownership", "dedupeBound"} {
		t.Run(name, func(t *testing.T) {
			f := newReadinessFixture(t)
			f.c.admitted()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			f.network()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			switch name {
			case "host":
				f.route.HostID = domain.NewID()
			case "runner":
				f.route.RunnerID = domain.NewID()
			case "runnerEpoch":
				f.route.RunnerConnectedAt = f.route.RunnerConnectedAt.Add(time.Nanosecond)
			case "tenant":
				f.c.mu.Lock()
				n := f.c.networks[f.route.NetworkID.String()]
				n.TenantID = domain.NewID().String()
				f.c.networks[f.route.NetworkID.String()] = n
				f.c.mu.Unlock()
			case "epoch":
				f.route.EpochID = "other"
			case "instance":
				f.route.TargetInstanceID = domain.NewID()
			case "definition":
				f.route.TargetDefinitionID = domain.NewID()
			case "principal":
				f.route.TargetPrincipalID = domain.NewID()
			case "expired":
				f.route.OfferedAt = time.Now().Add(-time.Hour)
				f.route.OfferDeadline = time.Now().Add(-time.Minute)
			case "future":
				f.route.OfferedAt = time.Now().Add(time.Second)
			case "stopped":
				row, _, _ := f.c.d.state.GetInstance(f.route.TargetInstanceID.String())
				row.Status = "stopped"
				if err := f.c.d.state.UpsertInstance(*row); err != nil {
					t.Fatal(err)
				}
			case "missingKey":
				f.route.EpochID = "missing"
				f.c.mu.Lock()
				n := f.c.networks[f.route.NetworkID.String()]
				n.EpochID = "missing"
				f.c.networks[f.route.NetworkID.String()] = n
				f.c.mu.Unlock()
			case "revoked":
				kr, err := crypto.LoadKeyring(f.c.d.StateDir, f.route.NetworkID.String())
				if err != nil {
					t.Fatal(err)
				}
				if name == "revoked" {
					kr.Epochs[0].State = crypto.EpochRevoked
				} else {
					kr.Epochs = nil
				}
				if err = crypto.SaveKeyring(f.c.d.StateDir, kr); err != nil {
					t.Fatal(err)
				}
			case "ownership":
				f.c.native.mu.Lock()
				f.c.native.session.OwnershipScope = "organization"
				f.c.native.mu.Unlock()
			case "dedupeBound":
				f.c.enqueue(func() {
					for i := 0; i < 4096; i++ {
						f.c.seen[domain.NewID().String()] = true
					}
				})
			}
			f.offer()
			f.quiet(t)
		})
	}
}

func TestAccountMessagingReadinessSlowIO(t *testing.T) {
	for _, change := range []string{"disconnect", "revocation", "expiry", "overflow"} {
		t.Run(change, func(t *testing.T) {
			f := newReadinessFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			lookup := f.c.lookup
			f.c.lookup = func(id string) (*InstanceRow, bool, error) { close(entered); <-release; return lookup(id) }
			f.c.admitted()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			f.network()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			if change == "expiry" {
				f.route.OfferDeadline = time.Now().Add(80 * time.Millisecond)
			}
			f.offer()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("worker did not enter local I/O")
			}
			returned := make(chan struct{})
			go func() {
				switch change {
				case "disconnect":
					f.c.close()
				case "revocation":
					e, _ := transport.NewEnvelope(transport.MsgNetworkCrypto, transport.NetworkCryptoPayload{TenantID: f.session.TenantID, NetworkID: f.route.NetworkID.String(), Status: "degraded", EpochID: f.route.EpochID})
					f.c.network(e)
				case "overflow":
					for i := 0; i < 40; i++ {
						f.offer()
					}
				}
				close(returned)
			}()
			select {
			case <-returned:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("local I/O blocked read-loop event")
			}
			if change == "expiry" {
				time.Sleep(100 * time.Millisecond)
			}
			close(release)
			f.quiet(t)
		})
	}
}

func TestAccountMessagingReadinessSlowWrite(t *testing.T) {
	f := newReadinessFixture(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.c.write = func(raw []byte, guard func() bool) error { close(entered); <-release; close(finished); return nil }
	f.c.admitted()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not enter write")
	}
	returned := make(chan struct{})
	go func() { f.network(); f.offer(); f.c.close(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("write blocked read loop or cleanup")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("write did not finish")
	}
	f.quiet(t)
}

// The final guard must run after the daemon writer lock, not before waiting on
// it: unrelated traffic can hold that lock beyond revocation or offer expiry.
func TestAccountMessagingReadinessContendedWriter(t *testing.T) {
	for _, change := range []string{"revocation", "expiry", "disconnect", "stalledPersistence"} {
		t.Run(change, func(t *testing.T) {
			f := newReadinessFixture(t)
			entered, finished := make(chan struct{}), make(chan struct{})
			write := f.c.write
			f.c.write = func(raw []byte, guard func() bool) error {
				var e transport.Envelope
				if err := json.Unmarshal(raw, &e); err != nil {
					t.Fatal(err)
				}
				if e.Type == transport.MsgAccountMessagingReadinessAck {
					close(entered)
					defer close(finished)
				}
				return write(raw, guard)
			}
			f.c.admitted()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			f.network()
			f.expect(t, transport.MsgAccountMessagingReadinessHello)
			if change == "expiry" {
				f.route.OfferDeadline = time.Now().Add(80 * time.Millisecond)
			}
			f.c.d.writeMu.Lock()
			locked := true
			defer func() {
				if locked {
					f.c.d.writeMu.Unlock()
				}
			}()
			f.offer()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("ACK did not reach writer contention")
			}
			var persistenceDone chan struct{}
			switch change {
			case "disconnect":
				f.c.close()
			case "expiry":
				time.Sleep(100 * time.Millisecond)
			case "revocation", "stalledPersistence":
				e, _ := transport.NewEnvelope(transport.MsgNetworkCrypto, transport.NetworkCryptoPayload{TenantID: f.session.TenantID, NetworkID: f.route.NetworkID.String(), Status: "degraded", EpochID: f.route.EpochID})
				if change == "revocation" {
					f.c.network(e)
				} else {
					// Occupy SQLite's only connection after validation reaches the writer.
					// The real handleNetworkCrypto persistence now stalls, while readiness
					// must already have invalidated the pending ACK.
					f.c.d.state.db.SetMaxOpenConns(1)
					dbConn, err := f.c.d.state.db.Conn(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer dbConn.Close()
					persistenceDone = make(chan struct{})
					go func() { f.c.networkCrypto(e); close(persistenceDone) }()
					deadline := time.Now().Add(time.Second)
					for f.c.networkMatches(f.route.NetworkID.String(), f.session.TenantID, f.route.EpochID) {
						if time.Now().After(deadline) {
							t.Fatal("readiness invalidation waited for persistence")
						}
						time.Sleep(time.Millisecond)
					}
					select {
					case <-persistenceDone:
						t.Fatal("persistence did not stall")
					default:
					}
					defer func() {
						dbConn.Close()
						select {
						case <-persistenceDone:
						case <-time.After(time.Second):
							t.Error("persistence did not finish")
						}
					}()
				}
			}
			f.c.d.writeMu.Unlock()
			locked = false
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("guarded writer did not finish")
			}
			f.quiet(t)
		})
	}
}
