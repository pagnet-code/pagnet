package daemon

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const ownerMailboxMaxSessions = 32
const ownerMailboxMaxRemembered = 4096

// A ready binding exists only after an endpoint and its encrypted mailbox are
// available under a successful controller lease. It never supplies authority
// independently of the live host socket.
type sharingBridgeActiveBinding struct {
	binding    sharingMailboxBinding
	generation int64
	session    transport.HostSessionPayload
	endpoint   sharingBridgeEndpoint
	lease      time.Time
}

func sameOwnerMailboxAuthority(a, b transport.HostSessionPayload) bool {
	return a.TenantID == b.TenantID && a.AccountID == b.AccountID &&
		a.OwnershipScope == b.OwnershipScope && a.HostID == b.HostID &&
		a.HostCredentialID == b.HostCredentialID && a.RunnerID == b.RunnerID &&
		a.RunnerEpoch.Equal(b.RunnerEpoch) && a.NativeAdmissionID == b.NativeAdmissionID && a.BootID == b.BootID
}

func (s *sharingBridgeSupervisor) ownerMailboxReady(d e2ee.OwnerMailboxDescriptor, p transport.HostSessionPayload, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ownerMailboxReadyLocked(d, p, now)
}

func (s *sharingBridgeSupervisor) ownerMailboxReadyLocked(d e2ee.OwnerMailboxDescriptor, p transport.HostSessionPayload, now time.Time) bool {
	active, ok := s.active[d.InstallationID]
	if !ok || s.session == nil || !sameOwnerMailboxAuthority(*s.session, p) ||
		!sameOwnerMailboxAuthority(active.session, p) || active.binding.InstallationID != d.InstallationID ||
		active.binding.ServiceID != d.ServiceID || active.binding.HostID != d.HostID ||
		active.binding.TenantID != d.TenantID || active.generation <= 0 || uint64(active.generation) != d.Generation ||
		active.endpoint == nil || !now.Before(active.lease) {
		return false
	}
	select {
	case <-active.endpoint.Done():
		return false
	default:
		return true
	}
}

type ownerMailboxSession struct {
	descriptor     e2ee.OwnerMailboxDescriptor
	keys           e2ee.OwnerMailboxKeys
	timer          *time.Timer
	authority      transport.HostSessionPayload
	ctx            context.Context
	cancel         context.CancelFunc
	clientSequence uint64
	hostSequence   uint64
	busy           bool
}

// Each instance belongs to one socket. Timers only erase memory; there is no
// polling or durable owner-session state.
type ownerMailboxConnection struct {
	daemon   *Daemon
	native   *NativeObservationConnection
	send     func(string, any) error
	mu       sync.Mutex
	closed   bool
	sessions map[string]*ownerMailboxSession
}

func newOwnerMailboxConnection(d *Daemon, native *NativeObservationConnection, send func(string, any) error) *ownerMailboxConnection {
	return &ownerMailboxConnection{daemon: d, native: native, send: send, sessions: map[string]*ownerMailboxSession{}}
}

func (c *ownerMailboxConnection) erase(id string) {
	session := c.sessions[id]
	if session == nil {
		return
	}
	if session.cancel != nil {
		session.cancel()
	}
	if session.timer != nil {
		session.timer.Stop()
	}
	clear(session.keys.ClientToHost[:])
	clear(session.keys.HostToClient[:])
	session.descriptor = e2ee.OwnerMailboxDescriptor{}
	delete(c.sessions, id)
}

func (c *ownerMailboxConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for id := range c.sessions {
		c.erase(id)
	}
}

func (c *ownerMailboxConnection) handle(env transport.Envelope, wireBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if wireBytes > transport.OwnerMailboxMaxWireBytes {
		for id := range c.sessions {
			c.erase(id)
		}
		return
	}
	if c.closed {
		return
	}
	p, err := c.native.AuthenticatedNativeHostSession()
	if err != nil || p.OwnershipScope != "personal" || p.HostCredentialID == "" {
		for id := range c.sessions {
			c.erase(id)
		}
		return
	}
	switch env.Type {
	case transport.MsgOwnerMailboxOperation:
		c.operation(env, p)
	case transport.MsgOwnerMailboxOpen:
		var open transport.OwnerMailboxOpenPayload
		if env.DecodePayload(&open) != nil || open.Protocol != transport.OwnerMailboxProtocolV1 {
			return
		}
		c.open(open.Descriptor, p, time.Now())
	case transport.MsgOwnerMailboxClose:
		var close transport.OwnerMailboxClosePayload
		if env.DecodePayload(&close) != nil || close.Protocol != transport.OwnerMailboxProtocolV1 || !close.Code.IsValid() {
			return
		}
		if session := c.sessions[close.SessionID]; session != nil && ownerMailboxMatches(session.descriptor, p) {
			c.erase(close.SessionID)
		}
	}
}

func ownerMailboxMatches(d e2ee.OwnerMailboxDescriptor, p transport.HostSessionPayload) bool {
	return p.OwnershipScope == "personal" && p.HostCredentialID != "" &&
		d.TenantID == p.TenantID && d.OwnerUserID == p.AccountID && d.HostID == p.HostID &&
		d.HostCredentialID == p.HostCredentialID && d.RunnerID == p.RunnerID && d.RunnerEpoch.Equal(p.RunnerEpoch)
}

// remember prevents a closed or disconnected session from being opened again.
// Its bounded tombstones contain only IDs and public expiry times, never keys.
func (d *Daemon) rememberOwnerMailbox(id string, expiry, now time.Time) bool {
	d.ownerMailboxMu.Lock()
	defer d.ownerMailboxMu.Unlock()
	if d.ownerMailboxUsed == nil {
		d.ownerMailboxUsed = map[string]time.Time{}
	}
	for id, until := range d.ownerMailboxUsed {
		if !now.Before(until) {
			delete(d.ownerMailboxUsed, id)
		}
	}
	if _, used := d.ownerMailboxUsed[id]; used || len(d.ownerMailboxUsed) >= ownerMailboxMaxRemembered {
		return false
	}
	d.ownerMailboxUsed[id] = expiry
	return true
}

func (c *ownerMailboxConnection) open(d e2ee.OwnerMailboxDescriptor, p transport.HostSessionPayload, now time.Time) {
	if _, err := e2ee.EncodeOwnerMailboxDescriptor(d); err != nil {
		return
	}
	if !ownerMailboxMatches(d, p) || now.Unix() < 0 || uint64(now.Unix()) < d.IssuedAtUnixSeconds || uint64(now.Unix()) >= d.ExpiresAtUnixSeconds {
		return
	}
	for id, session := range c.sessions {
		if uint64(now.Unix()) >= session.descriptor.ExpiresAtUnixSeconds {
			c.erase(id)
		}
	}
	if len(c.sessions) >= ownerMailboxMaxSessions || c.daemon.sharingBridges == nil || !c.daemon.sharingBridges.ownerMailboxReady(d, p, now) {
		return
	}
	identity, err := c.daemon.cryptoManager().hostIdentity()
	if err != nil || !bytes.Equal(identity.X25519Pub, d.HostX25519Pub) || !bytes.Equal(identity.Ed25519Pub, d.HostEd25519Pub) {
		return
	}
	expiry := time.Unix(int64(d.ExpiresAtUnixSeconds), 0)
	if !c.daemon.rememberOwnerMailbox(d.SessionID, expiry, now) {
		return
	}
	bootstrap, keys, err := e2ee.CreateOwnerMailboxBootstrap(d, identity.Ed25519Priv)
	if err != nil {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), expiry)
	session := &ownerMailboxSession{descriptor: d, keys: keys, authority: p, ctx: ctx, cancel: cancel}
	clear(keys.ClientToHost[:])
	clear(keys.HostToClient[:])
	c.sessions[d.SessionID] = session
	session.timer = time.AfterFunc(time.Until(expiry), func() { c.mu.Lock(); defer c.mu.Unlock(); c.erase(d.SessionID) })
	go func() {
		select {
		case <-ctx.Done():
		case <-c.native.closed:
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessions[d.SessionID] == session {
			c.erase(d.SessionID)
		}
	}()
	if c.send(transport.MsgOwnerMailboxReady, transport.OwnerMailboxReadyPayload{Protocol: transport.OwnerMailboxProtocolV1, Descriptor: d, Bootstrap: bootstrap}) != nil {
		c.erase(d.SessionID)
	}
}
