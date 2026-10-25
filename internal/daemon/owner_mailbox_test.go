package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

type ownerMailboxFixture struct {
	d          *Daemon
	c          *ownerMailboxConnection
	p          transport.HostSessionPayload
	descriptor e2ee.OwnerMailboxDescriptor
	browser    []byte
	ready      []transport.OwnerMailboxReadyPayload
}

func newOwnerMailboxFixture(t *testing.T) *ownerMailboxFixture {
	t.Helper()
	id := func() string { return domain.NewID().String() }
	f := &ownerMailboxFixture{d: &Daemon{Config: Config{StateDir: t.TempDir()}}}
	identity, err := f.d.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.browser = browser.Bytes()
	f.p = transport.HostSessionPayload{TenantID: id(), AccountID: id(), OwnershipScope: "personal", NativeAdmissionID: id(), HostID: id(), HostCredentialID: id(), RunnerID: id(), RunnerEpoch: time.Now().UTC(), BootID: id(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	f.descriptor = e2ee.OwnerMailboxDescriptor{TenantID: f.p.TenantID, OwnerUserID: f.p.AccountID, HostID: f.p.HostID, HostCredentialID: f.p.HostCredentialID, RunnerID: f.p.RunnerID, RunnerEpoch: f.p.RunnerEpoch, InstallationID: id(), ServiceID: id(), SessionID: id(), Generation: 1, BrowserX25519Pub: browser.PublicKey().Bytes(), HostX25519Pub: identity.X25519Pub, HostEd25519Pub: identity.Ed25519Pub, IssuedAtUnixSeconds: uint64(time.Now().Unix()), ExpiresAtUnixSeconds: uint64(time.Now().Unix()) + 900}
	f.d.sharingBridges = newSharingBridgeSupervisor(f.d)
	f.d.sharingBridges.admit(f.p)
	f.d.sharingBridges.active = map[string]sharingBridgeActiveBinding{f.descriptor.InstallationID: {sharingMailboxBinding{f.descriptor.InstallationID, f.descriptor.ServiceID, f.p.TenantID, f.p.HostID}, 1, f.p, &bridgeTestEndpoint{done: make(chan struct{})}, time.Now().Add(time.Hour)}}
	f.c = f.connection(t, f.p)
	t.Cleanup(f.c.close)
	return f
}
func (f *ownerMailboxFixture) connection(t *testing.T, p transport.HostSessionPayload) *ownerMailboxConnection {
	t.Helper()
	n := NewNativeObservationConnection("https://example.test", p.HostID, p.BootID, func(context.Context, string, any) error { return nil })
	if err := n.Admit(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return newOwnerMailboxConnection(f.d, n, func(typ string, payload any) error {
		if typ != transport.MsgOwnerMailboxReady {
			t.Errorf("unexpected reply %s", typ)
		}
		f.ready = append(f.ready, payload.(transport.OwnerMailboxReadyPayload))
		return nil
	})
}
func (f *ownerMailboxFixture) open(t *testing.T, d e2ee.OwnerMailboxDescriptor) {
	t.Helper()
	env, err := transport.NewEnvelope(transport.MsgOwnerMailboxOpen, transport.OwnerMailboxOpenPayload{Protocol: transport.OwnerMailboxProtocolV1, Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	f.c.handle(env, 1024)
}
func (f *ownerMailboxFixture) closeSession(t *testing.T, c *ownerMailboxConnection, id string) {
	t.Helper()
	env, err := transport.NewEnvelope(transport.MsgOwnerMailboxClose, transport.OwnerMailboxClosePayload{Protocol: transport.OwnerMailboxProtocolV1, SessionID: id, Code: transport.OwnerMailboxCloseClosed})
	if err != nil {
		t.Fatal(err)
	}
	c.handle(env, 256)
}
func TestOwnerMailboxBootstrapSignatureAndClose(t *testing.T) {
	f := newOwnerMailboxFixture(t)
	f.open(t, f.descriptor)
	if len(f.ready) != 1 {
		t.Fatal("missing ready")
	}
	keys, err := e2ee.VerifyOwnerMailboxBootstrap(f.ready[0].Descriptor, f.ready[0].Bootstrap, f.browser)
	if err != nil {
		t.Fatal(err)
	}
	session := f.c.sessions[f.descriptor.SessionID]
	tampered := f.ready[0].Bootstrap
	tampered.Signature = append([]byte(nil), tampered.Signature...)
	tampered.Signature[0] ^= 1
	if _, err := e2ee.VerifyOwnerMailboxBootstrap(f.ready[0].Descriptor, tampered, f.browser); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if session.keys != keys {
		t.Fatal("wrong session keys")
	}
	f.open(t, f.descriptor)
	if len(f.ready) != 1 {
		t.Fatal("duplicate open replied")
	}
	other := f.connection(t, f.p)
	defer other.close()
	f.closeSession(t, other, f.descriptor.SessionID)
	if len(f.c.sessions) != 1 {
		t.Fatal("another socket closed session")
	}
	f.closeSession(t, f.c, f.descriptor.SessionID)
	if len(f.c.sessions) != 0 || session.keys != (e2ee.OwnerMailboxKeys{}) || session.descriptor.SessionID != "" {
		t.Fatal("close retained keys")
	}
	f.open(t, f.descriptor)
	if len(f.ready) != 1 {
		t.Fatal("closed session reused")
	}
}
func TestOwnerMailboxRejectsMismatches(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ownerMailboxFixture)
	}{
		{"owner", func(f *ownerMailboxFixture) { f.descriptor.OwnerUserID = domain.NewID().String() }},
		{"tenant", func(f *ownerMailboxFixture) { f.descriptor.TenantID = domain.NewID().String() }},
		{"host", func(f *ownerMailboxFixture) { f.descriptor.HostID = domain.NewID().String() }},
		{"credential", func(f *ownerMailboxFixture) { f.descriptor.HostCredentialID = domain.NewID().String() }},
		{"runner", func(f *ownerMailboxFixture) { f.descriptor.RunnerID = domain.NewID().String() }},
		{"epoch", func(f *ownerMailboxFixture) { f.descriptor.RunnerEpoch = f.descriptor.RunnerEpoch.Add(time.Second) }},
		{"generation", func(f *ownerMailboxFixture) { f.descriptor.Generation++ }},
		{"installation", func(f *ownerMailboxFixture) { f.descriptor.InstallationID = domain.NewID().String() }},
		{"service", func(f *ownerMailboxFixture) { f.descriptor.ServiceID = domain.NewID().String() }},
		{"host encryption key", func(f *ownerMailboxFixture) { f.descriptor.HostX25519Pub = make([]byte, 32) }},
		{"host signing key", func(f *ownerMailboxFixture) { f.descriptor.HostEd25519Pub = make([]byte, 32) }},
		{"browser key", func(f *ownerMailboxFixture) { f.descriptor.BrowserX25519Pub = make([]byte, 32) }},
		{"canonical ID", func(f *ownerMailboxFixture) { f.descriptor.SessionID = "invalid" }},
		{"lifetime", func(f *ownerMailboxFixture) { f.descriptor.ExpiresAtUnixSeconds++ }},
		{"future", func(f *ownerMailboxFixture) {
			f.descriptor.IssuedAtUnixSeconds += 100
			f.descriptor.ExpiresAtUnixSeconds += 100
		}},
		{"expired", func(f *ownerMailboxFixture) {
			f.descriptor.IssuedAtUnixSeconds -= 900
			f.descriptor.ExpiresAtUnixSeconds -= 900
		}},
		{"no credential", func(f *ownerMailboxFixture) {
			f.c.native.mu.Lock()
			f.c.native.session.HostCredentialID = ""
			f.c.native.mu.Unlock()
		}},
		{"organization", func(f *ownerMailboxFixture) {
			f.c.native.mu.Lock()
			f.c.native.session.OwnershipScope = "organization"
			f.c.native.mu.Unlock()
		}},
		{"endpoint closed", func(f *ownerMailboxFixture) {
			_ = f.d.sharingBridges.active[f.descriptor.InstallationID].endpoint.Close()
		}},
		{"lease expired", func(f *ownerMailboxFixture) {
			s := f.d.sharingBridges.active[f.descriptor.InstallationID]
			s.lease = time.Now()
			f.d.sharingBridges.active[f.descriptor.InstallationID] = s
		}},
		{"binding admission", func(f *ownerMailboxFixture) {
			s := f.d.sharingBridges.active[f.descriptor.InstallationID]
			s.session.AccountID = domain.NewID().String()
			f.d.sharingBridges.active[f.descriptor.InstallationID] = s
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newOwnerMailboxFixture(t)
			test.change(f)
			f.open(t, f.descriptor)
			if len(f.ready) != 0 || len(f.c.sessions) != 0 {
				t.Fatal("mismatch accepted")
			}
		})
	}
}
func TestOwnerMailboxDisconnectAndReconnect(t *testing.T) {
	f := newOwnerMailboxFixture(t)
	f.open(t, f.descriptor)
	session := f.c.sessions[f.descriptor.SessionID]
	f.c.close()
	if session.keys != (e2ee.OwnerMailboxKeys{}) {
		t.Fatal("disconnect retained keys")
	}
	old := f.c
	f.c = f.connection(t, f.p)
	defer f.c.close()
	f.open(t, f.descriptor)
	if len(f.ready) != 1 {
		t.Fatal("reconnected session reused")
	}
	old.handle(transport.Envelope{Type: transport.MsgOwnerMailboxOpen}, 0)
	fresh := f.descriptor
	fresh.SessionID = domain.NewID().String()
	f.p.RunnerEpoch = f.p.RunnerEpoch.Add(time.Second)
	f.d.sharingBridges.admit(f.p)
	f.open(t, fresh)
	if len(f.ready) != 1 {
		t.Fatal("stale connection accepted")
	}
}
func TestOwnerMailboxExpiryErasesKeys(t *testing.T) {
	f := newOwnerMailboxFixture(t)
	f.descriptor.IssuedAtUnixSeconds = uint64(time.Now().Unix()) - 899
	f.descriptor.ExpiresAtUnixSeconds = f.descriptor.IssuedAtUnixSeconds + 900
	f.open(t, f.descriptor)
	session := f.c.sessions[f.descriptor.SessionID]
	if session == nil {
		t.Fatal("missing session")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("expiry retained keys")
		case <-ticker.C:
			f.c.mu.Lock()
			erased := session.keys == (e2ee.OwnerMailboxKeys{}) && len(f.c.sessions) == 0
			f.c.mu.Unlock()
			if erased {
				return
			}
		}
	}
}
func TestOwnerMailboxBoundsAndWireProtocol(t *testing.T) {
	f := newOwnerMailboxFixture(t)
	for i := 0; i < ownerMailboxMaxSessions+1; i++ {
		d := f.descriptor
		d.SessionID = domain.NewID().String()
		f.open(t, d)
	}
	if len(f.ready) != ownerMailboxMaxSessions {
		t.Fatal("session bound not enforced")
	}
	f.c.close()
	f = newOwnerMailboxFixture(t)
	env, _ := transport.NewEnvelope(transport.MsgOwnerMailboxOpen, transport.OwnerMailboxOpenPayload{Protocol: transport.OwnerMailboxProtocolV1, Descriptor: f.descriptor})
	f.c.handle(env, transport.OwnerMailboxMaxWireBytes+1)
	bad, _ := transport.NewEnvelope(transport.MsgOwnerMailboxOpen, transport.OwnerMailboxOpenPayload{Protocol: "unknown", Descriptor: f.descriptor})
	f.c.handle(bad, 1024)
	f.c.native.Close()
	f.c.handle(env, 1024)
	if len(f.ready) != 0 {
		t.Fatal("invalid protocol or unauthenticated socket accepted")
	}
}
func TestOwnerMailboxSendFailureErasesKeys(t *testing.T) {
	f := newOwnerMailboxFixture(t)
	f.c.send = func(string, any) error { return errors.New("socket closed") }
	f.open(t, f.descriptor)
	if len(f.c.sessions) != 0 {
		t.Fatal("failed reply retained session")
	}
}

func TestOwnerMailboxBridgeSnapshotLifecycle(t *testing.T) {
	f, s := newBridgeFixture(t)
	s.mu.Lock()
	p := *s.session
	s.mu.Unlock()
	p.AccountID = domain.NewID().String()
	p.HostCredentialID = domain.NewID().String()
	p.OwnershipScope = "personal"
	s.admit(p)
	cancel, done := startBridgeTest(t, s)
	var descriptor e2ee.OwnerMailboxDescriptor
	awaitBridge(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		a, ok := s.active[f.installation.ID]
		if ok {
			descriptor = e2ee.OwnerMailboxDescriptor{InstallationID: a.binding.InstallationID, ServiceID: a.binding.ServiceID, TenantID: a.binding.TenantID, HostID: a.binding.HostID, Generation: uint64(a.generation)}
		}
		return ok
	})
	if !s.ownerMailboxReady(descriptor, p, time.Now()) {
		t.Fatal("ready binding unavailable")
	}
	s.disconnect()
	if s.ownerMailboxReady(descriptor, p, time.Now()) {
		t.Fatal("disconnected binding accepted")
	}
	p.RunnerEpoch = p.RunnerEpoch.Add(time.Second)
	s.admit(p)
	awaitBridge(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		a, ok := s.active[f.installation.ID]
		if ok {
			descriptor.Generation = uint64(a.generation)
		}
		return ok
	})
	if !s.ownerMailboxReady(descriptor, p, time.Now()) {
		t.Fatal("renewed binding unavailable")
	}
	cancel()
	<-done
	if s.ownerMailboxReady(descriptor, p, time.Now()) {
		t.Fatal("stopped binding accepted")
	}
}

func TestOwnerMailboxReplayMemoryBound(t *testing.T) {
	d := &Daemon{}
	now := time.Now()
	expiry := now.Add(time.Minute)
	for i := 0; i < ownerMailboxMaxRemembered; i++ {
		if !d.rememberOwnerMailbox(domain.NewID().String(), expiry, now) {
			t.Fatal("premature replay bound")
		}
	}
	if d.rememberOwnerMailbox(domain.NewID().String(), expiry, now) {
		t.Fatal("unbounded replay memory")
	}
	if !d.rememberOwnerMailbox(domain.NewID().String(), expiry.Add(time.Minute), expiry) {
		t.Fatal("expired replay memory retained")
	}
}
