package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// A bounded worker owns all handshake state and local I/O for one socket.
// No ACK is interpreted as server acceptance or authority.
type accountMessagingReadinessConnection struct {
	d        *Daemon
	socket   *websocket.Conn
	native   *NativeObservationConnection
	networks map[string]transport.NetworkCryptoPayload
	seen     map[string]bool
	hello    bool
	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan func()
	// Captured socket writer; injectable for connection-boundary tests.
	write        func([]byte, func() bool) error
	lookup       func(string) (*InstanceRow, bool, error)
	mu           sync.Mutex
	subscription *accountMessagingReadinessSubscription
	loadKeyring  func(string) (*crypto.Keyring, error)
}

func newAccountMessagingReadinessConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *accountMessagingReadinessConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &accountMessagingReadinessConnection{d: d, socket: socket, native: native, networks: make(map[string]transport.NetworkCryptoPayload), seen: make(map[string]bool), ctx: ctx, cancel: cancel, queue: make(chan func(), 32), write: func(raw []byte, guard func() bool) error { return d.writeGuarded(socket, raw, guard) }}
	c.lookup = d.state.GetInstance
	c.loadKeyring = func(network string) (*crypto.Keyring, error) { return crypto.LoadKeyring(d.StateDir, network) }
	go c.run()
	return c
}

// Overflow disables this handshake for the socket rather than losing an ordered
// invalidation and later ACKing against stale network evidence.
func (c *accountMessagingReadinessConnection) enqueue(f func()) {
	select {
	case <-c.ctx.Done():
		return
	default:
	}
	select {
	case c.queue <- f:
	default:
		c.close()
	}
}

// Cancellation never waits for filesystem/SQLite calls. A blocked local read
// may retain this one worker until the OS/database returns; subsequent checks
// suppress its writes, and it never migrates to a replacement connection.
func (c *accountMessagingReadinessConnection) close() {
	c.cancel()
	if c.subscription != nil {
		c.subscription.clear()
	}
}
func (c *accountMessagingReadinessConnection) run() {
	defer func() { c.mu.Lock(); clear(c.networks); c.mu.Unlock(); clear(c.seen) }()
	for {
		select {
		case <-c.ctx.Done():
			return
		case f := <-c.queue:
			select {
			case <-c.ctx.Done():
				return
			default:
				f()
			}
		}
	}
}
func (c *accountMessagingReadinessConnection) admitted() { c.enqueue(c.handleAdmission) }
func (c *accountMessagingReadinessConnection) network(env transport.Envelope) {
	if len(env.Payload) > 4096 {
		return
	}
	c.handleNetwork(env)
}
func (c *accountMessagingReadinessConnection) offer(env transport.Envelope) {
	if c.subscription != nil {
		c.subscription.handle(env)
		return
	}
	if len(env.Payload) > transport.AccountMessagingReadinessMaxPayload {
		return
	}
	env.Payload = append(json.RawMessage(nil), env.Payload...)
	c.enqueue(func() { c.handleOffer(env) })
}

func (c *accountMessagingReadinessConnection) session() (transport.HostSessionPayload, bool) {
	select {
	case <-c.ctx.Done():
		return transport.HostSessionPayload{}, false
	default:
	}
	s, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || s.OwnershipScope != "personal" || s.HostID != c.d.HostID || s.TenantID == "" || s.AccountID == "" || s.RunnerID == "" || s.RunnerEpoch.IsZero() {
		return s, false
	}
	c.d.connMu.Lock()
	active := c.d.curConn == c.socket && c.d.nativeConn == c.native
	c.d.connMu.Unlock()
	return s, active
}

func (c *accountMessagingReadinessConnection) send(typ string, p any, guards ...func() bool) {
	if _, ok := c.session(); !ok {
		return
	}
	env, err := transport.NewEnvelope(typ, p)
	if err != nil {
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return
	}
	_ = c.write(raw, func() bool {
		if _, ok := c.session(); !ok {
			return false
		}
		for _, guard := range guards {
			if !guard() {
				return false
			}
		}
		return true
	})
}

func (c *accountMessagingReadinessConnection) handleAdmission() {
	s, ok := c.session()
	if !ok || c.hello {
		return
	}
	c.hello = true
	if c.subscription != nil {
		for _, feature := range s.ProtocolFeatures {
			if feature == transport.AccountMessagingReadinessSubscriptionProtocol {
				c.subscription.enabled.Store(true)
				break
			}
		}
	}
	if c.subscription != nil && !c.usesSubscription() {
		return
	}
	if c.usesSubscription() {
		c.send(transport.MsgAccountMessagingReadinessHello, transport.AccountMessagingReadinessSubscriptionHelloPayload{V: 2, Protocol: transport.AccountMessagingReadinessSubscriptionProtocol, Reset: false})
		return
	}
	c.send(transport.MsgAccountMessagingReadinessHello, transport.AccountMessagingReadinessHelloPayload{V: 1, Protocol: transport.AccountMessagingReadinessProtocol})
}

func (c *accountMessagingReadinessConnection) handleNetwork(env transport.Envelope) {
	var p transport.NetworkCryptoPayload
	if json.Unmarshal(env.Payload, &p) != nil || p.NetworkID == "" {
		return
	}
	c.mu.Lock()
	old, exists := c.networks[p.NetworkID]
	if !exists && len(c.networks) >= 256 {
		c.mu.Unlock()
		c.close()
		return
	}
	c.networks[p.NetworkID] = p
	c.mu.Unlock()
	if exists && old == p {
		return
	}
	if c.subscription != nil {
		if c.usesSubscription() {
			c.localEvidenceChanged()
		}
		return
	}
	c.enqueue(func() {
		s, ok := c.session()
		if !ok || !c.hello || p.TenantID != s.TenantID || p.Status != "active" || p.EpochID == "" || !c.networkMatches(p.NetworkID, p.TenantID, p.EpochID) {
			return
		}
		c.send(transport.MsgAccountMessagingReadinessHello, transport.AccountMessagingReadinessHelloPayload{V: 1, Protocol: transport.AccountMessagingReadinessProtocol})
	})
}

func (c *accountMessagingReadinessConnection) handleOffer(env transport.Envelope) {
	r, err := transport.ParseAccountMessagingReadinessOffer(env.Payload)
	if err != nil || !c.hello {
		return
	}
	s, ok := c.session()
	now := time.Now()
	if !ok || r.HostID.String() != s.HostID || r.RunnerID.String() != s.RunnerID || !r.RunnerConnectedAt.Equal(s.RunnerEpoch) || now.Before(r.OfferedAt) || !now.Before(r.OfferDeadline) || !now.Before(r.ExpiresAt) {
		return
	}
	if !c.networkMatches(r.NetworkID.String(), s.TenantID, r.EpochID) {
		return
	}
	if c.d.state == nil {
		return
	}
	row, found, err := c.lookup(r.TargetInstanceID.String())
	if err != nil || !found || row.DefinitionID != r.TargetDefinitionID.String() || row.AgentPrincipalID != r.TargetPrincipalID.String() || row.NetworkID != r.NetworkID.String() || (row.Status != "idle" && row.Status != "working") {
		return
	}
	kr, err := crypto.LoadKeyring(c.d.StateDir, r.NetworkID.String())
	if err != nil {
		return
	}
	epoch, ok := kr.EpochByID(r.EpochID)
	if !ok || (epoch.State != crypto.EpochActive && epoch.State != crypto.EpochRotated) {
		return
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return
	}
	clear(key[:])
	// Local I/O may have raced a network revocation, expiry or disconnect.
	s, ok = c.session()
	if !ok || !time.Now().Before(r.OfferDeadline) || !time.Now().Before(r.ExpiresAt) || !c.networkMatches(r.NetworkID.String(), s.TenantID, r.EpochID) {
		return
	}
	id := r.OfferID.String()
	if c.seen[id] || len(c.seen) >= 4096 {
		return
	}
	c.seen[id] = true
	c.send(transport.MsgAccountMessagingReadinessAck, transport.AccountMessagingReadinessAckPayload{V: 1, Protocol: transport.AccountMessagingReadinessProtocol, AccountMessagingReadinessAck: transport.AccountMessagingReadinessAck{AccountMessagingReadinessCandidate: r.AccountMessagingReadinessCandidate, OfferID: r.OfferID, Generation: r.Generation, Digest: r.Digest}}, func() bool {
		return time.Now().Before(r.OfferDeadline) && time.Now().Before(r.ExpiresAt) && c.networkMatches(r.NetworkID.String(), s.TenantID, r.EpochID)
	})
}

func (c *accountMessagingReadinessConnection) networkMatches(network, tenant, epoch string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.networks[network]
	return ok && n.TenantID == tenant && n.Status == "active" && n.EpochID == epoch
}

// Update readiness before the pre-existing synchronous crypto-state persistence:
// a stalled database must not preserve an old active state for queued ACKs.
func (c *accountMessagingReadinessConnection) networkCrypto(env transport.Envelope) {
	c.network(env)
	c.d.handleNetworkCrypto(env)
}
