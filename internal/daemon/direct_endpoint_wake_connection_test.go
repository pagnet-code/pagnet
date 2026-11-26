package daemon

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
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
	lane := newDirectEndpointWakeConnection(nil, socket, c)
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
	nextLane := newDirectEndpointWakeConnection(nil, new(websocket.Conn), next)
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

func wakeAttachmentFixture(t *testing.T, source bool) (*Daemon, *directEndpointWakeConnection, *DirectEndpointSubscription) {
	t.Helper()
	native, session := wakeNative(t, wakeOffer(source))
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{Config: Config{ServerURL: "https://example.test"}}
	socket := new(websocket.Conn)
	d.curConn, d.nativeConn = socket, native
	lane := newDirectEndpointWakeConnection(d, socket, native)
	lane.write = func(time.Time, []byte) error { return nil }
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	role := "P"
	if source {
		role = "S"
	}
	handle := d.directSubscriptions.add(directEndpointBinding{socket: socket, native: native, sessionIdentity: string(raw), metadata: DirectEndpointSubscriptionMetadata{
		InstallationID: domain.NewID(), IntentID: domain.NewID(), CredentialID: domain.NewID(), Role: role, ServerOrigin: "https://example.test", Deadline: time.Now().Add(time.Hour),
	}})
	t.Cleanup(func() { lane.close(); native.Close(); d.directSubscriptions.close() })
	return d, lane, handle
}

func dormantWakeReconcile(context.Context) error {
	panic("local wake attachment invoked reconciliation")
}

func TestDirectEndpointWakeAttachExplicitSubscription(t *testing.T) {
	for _, source := range []bool{false, true} {
		t.Run(map[bool]string{true: "source", false: "target"}[source], func(t *testing.T) {
			_, lane, handle := wakeAttachmentFixture(t, source)
			assertRejected := func() {
				t.Helper()
				for _, typ := range []string{transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeOffer, transport.MsgDirectEndpointWakeACK, transport.MsgDirectEndpointWakeUnsubscribe, transport.MsgDirectEndpointWakeClosed} {
					if handled, err := lane.handle(transport.Envelope{Type: typ, Payload: []byte(`{}`)}); !handled || err != ErrNativeObservationConflict {
						t.Fatalf("reserved message %s accepted: %v", typ, err)
					}
				}
			}
			assertRejected()
			if _, err := lane.attach(handle, dormantWakeReconcile); err != nil {
				t.Fatal(err)
			}
			assertRejected()
			entry := lane.byHandle[handle]
			if entry == nil || lane.byID[entry.subscription.SubscriptionID] != entry || entry.handle != handle || entry.installationID != handle.Metadata().InstallationID {
				t.Fatal("exact attachment identity lost")
			}
			if _, err := entry.subscription.CanonicalBytes(); err != nil {
				t.Fatal(err)
			}
			wantRole := transport.DirectEndpointWakeRoleTargetV1
			if source {
				wantRole = transport.DirectEndpointWakeRoleSourceV2
			}
			if entry.subscription.EndpointRole != wantRole {
				t.Fatal("wrong wire role")
			}
			if _, err := lane.attach(handle, dormantWakeReconcile); err != ErrNativeObservationConflict || lane.byHandle[handle] != entry || len(lane.usedIDs) != 1 {
				t.Fatal("duplicate replaced attachment or consumed ID", err)
			}
		})
	}
}

func TestDirectEndpointWakeAttachRejectsInvalidBinding(t *testing.T) {
	for _, reason := range []string{"nil", "foreign", "stale", "expired", "socket", "native", "session", "server", "native-server", "configured-server", "unnormalized-server", "role", "suite", "wake", "wake-not-selected", "installation", "installation-zero", "intent", "credential", "nil-callback", "not-current-socket", "not-current-native", "closed", "native-closed", "replaced-lane"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			callback := dormantWakeReconcile
			switch reason {
			case "nil":
				handle = nil
			case "foreign":
				owner := &directEndpointSubscriptions{}
				handle = owner.add(handle.binding)
				defer owner.close()
			case "stale":
				handle.Remove()
			case "expired":
				handle.binding.metadata.Deadline = time.Now().Add(-time.Second)
			case "socket":
				handle.binding.socket = new(websocket.Conn)
			case "native":
				handle.binding.native = new(NativeObservationConnection)
			case "session":
				handle.binding.sessionIdentity = `{}`
			case "server":
				handle.binding.metadata.ServerOrigin = "https://other.test"
			case "native-server":
				lane.native.serverURL = "https://other.test"
			case "configured-server":
				d.ServerURL = "https://other.test"
			case "unnormalized-server":
				handle.binding.metadata.ServerOrigin += "/"
			case "role":
				handle.binding.metadata.Role = "source-v2"
			case "suite":
				handle.binding.metadata.Role = "P"
			case "wake":
				lane.native.offeredDirectEndpointWake = false
			case "wake-not-selected":
				features := lane.native.session.ProtocolFeatures
				lane.native.session.ProtocolFeatures = nil
				for _, feature := range features {
					if feature != transport.DirectEndpointWakeFeatureV1 {
						lane.native.session.ProtocolFeatures = append(lane.native.session.ProtocolFeatures, feature)
					}
				}
				raw, err := json.Marshal(lane.native.session)
				if err != nil {
					t.Fatal(err)
				}
				handle.binding.sessionIdentity = string(raw)
			case "installation":
				handle.binding.metadata.InstallationID = "bad"
			case "installation-zero":
				handle.binding.metadata.InstallationID = "00000000-0000-0000-0000-000000000000"
			case "intent":
				handle.binding.metadata.IntentID = "bad"
			case "credential":
				handle.binding.metadata.CredentialID = "bad"
			case "nil-callback":
				callback = nil
			case "not-current-socket":
				d.curConn = new(websocket.Conn)
			case "not-current-native":
				d.nativeConn = new(NativeObservationConnection)
			case "closed":
				lane.close()
			case "native-closed":
				lane.native.Close()
			case "replaced-lane":
				newDirectEndpointWakeConnection(d, lane.socket, lane.native).close()
			}
			if _, err := lane.attach(handle, callback); err != ErrNativeObservationConflict {
				t.Fatal("invalid attachment accepted", err)
			}
			if len(lane.byHandle) != 0 || len(lane.byID) != 0 || len(lane.usedIDs) != 0 {
				t.Fatal("failed attachment retained state")
			}
		})
	}
}

func waitWakeAttachmentRemoved(t *testing.T, lane *directEndpointWakeConnection, entry *directEndpointWakeAttachment) {
	t.Helper()
	select {
	case <-entry.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("attachment cancellation blocked")
	}
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.byHandle[entry.handle] != nil || lane.byID[entry.subscription.SubscriptionID] != nil {
		t.Fatal("cancelled attachment retained")
	}
}

func TestDirectEndpointWakeAttachLifecycle(t *testing.T) {
	for _, reason := range []string{"revoke", "owner-close", "lane-close", "native-close"} {
		t.Run(reason, func(t *testing.T) {
			d, lane, handle := wakeAttachmentFixture(t, true)
			if _, err := lane.attach(handle, dormantWakeReconcile); err != nil {
				t.Fatal(err)
			}
			entry := lane.byHandle[handle]
			switch reason {
			case "revoke":
				handle.Remove()
			case "owner-close":
				d.directSubscriptions.close()
			case "lane-close":
				lane.close()
				lane.close()
			case "native-close":
				lane.native.Close()
			}
			waitWakeAttachmentRemoved(t, lane, entry)
		})
	}
}

func TestDirectEndpointWakeAttachCapacity(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "lifetime"}[remove], func(t *testing.T) {
			d, lane, first := wakeAttachmentFixture(t, true)
			for i := 0; i < 65; i++ {
				handle := first
				if i != 0 {
					handle = d.directSubscriptions.add(first.binding)
				}
				_, err := lane.attach(handle, dormantWakeReconcile)
				if i == 64 {
					if err != ErrNativeObservationCapacity {
						t.Fatal("65th lifetime ID accepted", err)
					}
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				lane.mu.Lock()
				entry := lane.byHandle[handle]
				lane.mu.Unlock()
				if remove {
					handle.Remove()
					waitWakeAttachmentRemoved(t, lane, entry)
				}
			}
			if len(lane.usedIDs) != 64 {
				t.Fatal("lifetime IDs reused")
			}
		})
	}
}

func TestDirectEndpointWakeAttachReplacementSocket(t *testing.T) {
	d, old, stale := wakeAttachmentFixture(t, true)
	if _, err := old.attach(stale, dormantWakeReconcile); err != nil {
		t.Fatal(err)
	}
	entry := old.byHandle[stale]
	native, session := wakeNative(t, wakeOffer(true))
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	socket := new(websocket.Conn)
	next := newDirectEndpointWakeConnection(d, socket, native)
	next.write = func(time.Time, []byte) error { return nil }
	defer next.close()
	defer native.Close()
	d.connMu.Lock()
	d.directSubscriptions.revokeWhere(func(b directEndpointBinding) bool { return b.socket != socket || b.native != native })
	d.curConn, d.nativeConn = socket, native
	d.connMu.Unlock()
	waitWakeAttachmentRemoved(t, old, entry)
	if _, err := next.attach(stale, dormantWakeReconcile); err != ErrNativeObservationConflict {
		t.Fatal("replacement inherited stale attachment", err)
	}
	binding := stale.binding
	binding.socket, binding.native = socket, native
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	binding.sessionIdentity = string(raw)
	fresh := d.directSubscriptions.add(binding)
	if _, err := old.attach(fresh, dormantWakeReconcile); err != ErrNativeObservationConflict {
		t.Fatal("old lane accepted replacement handle", err)
	}
	if _, err := next.attach(fresh, dormantWakeReconcile); err != nil {
		t.Fatal(err)
	}
	nextEntry := next.byHandle[fresh]
	stale.Remove()
	old.close()
	select {
	case <-nextEntry.ctx.Done():
		t.Fatal("old close cancelled replacement")
	default:
	}
}

func TestDirectEndpointWakeAttachRemoveReplaceRace(t *testing.T) {
	for i := 0; i < 32; i++ {
		d, lane, handle := wakeAttachmentFixture(t, true)
		nextSocket := new(websocket.Conn)
		start := make(chan struct{})
		result := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			_, err := lane.attach(handle, dormantWakeReconcile)
			result <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			handle.Remove()
		}()
		go func() {
			defer wg.Done()
			<-start
			d.connMu.Lock()
			d.directSubscriptions.revokeWhere(func(b directEndpointBinding) bool { return b.socket != nextSocket })
			d.curConn, d.nativeConn = nextSocket, nil
			d.connMu.Unlock()
		}()
		close(start)
		wg.Wait()
		if err := <-result; err != nil && err != ErrNativeObservationConflict {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for {
			lane.mu.Lock()
			empty := len(lane.byHandle) == 0 && len(lane.byID) == 0
			lane.mu.Unlock()
			if empty {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("remove/replacement left a stale attachment")
			}
			time.Sleep(time.Millisecond)
		}
		if handle.Valid() {
			t.Fatal("remove/replacement left a valid stale handle")
		}
	}
}

func TestDirectEndpointWakeAttachExactRemoval(t *testing.T) {
	d, lane, old := wakeAttachmentFixture(t, true)
	fresh := d.directSubscriptions.add(old.binding)
	if _, err := lane.attach(old, dormantWakeReconcile); err != nil {
		t.Fatal(err)
	}
	oldEntry := lane.byHandle[old]
	if _, err := lane.attach(fresh, dormantWakeReconcile); err != nil {
		t.Fatal(err)
	}
	freshEntry := lane.byHandle[fresh]
	if oldEntry.subscription.SubscriptionID == freshEntry.subscription.SubscriptionID {
		t.Fatal("distinct handles reused a wire ID")
	}
	old.Remove()
	waitWakeAttachmentRemoved(t, lane, oldEntry)
	old.Remove()
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.byHandle[fresh] != freshEntry || lane.byID[freshEntry.subscription.SubscriptionID] != freshEntry || freshEntry.ctx.Err() != nil {
		t.Fatal("old generation removed the fresh attachment")
	}
}
