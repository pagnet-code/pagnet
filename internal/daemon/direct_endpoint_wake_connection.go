package daemon

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

// Wake is supported only for the source-v2 and target-v1 credential suites.
// The dial query has already been rebuilt from implementation readiness.
func directEndpointWakeSuiteOffered(q url.Values) bool {
	exact := func(key, protocol string) bool { values := q[key]; return len(values) == 1 && values[0] == protocol }
	source := true
	for i, key := range directManagedSourceQueryKeys {
		source = source && exact(key, directManagedSourceProtocolsV2[i])
	}
	target := exact("managed_endpoint_prepare", transport.ManagedEndpointPrepareProtocol) && exact("managed_endpoint_pop", transport.ManagedEndpointPoPProtocol) && exact("managed_direct_credential", transport.ManagedDirectCredentialProtocol)
	return source || target
}

func (c *NativeObservationConnection) captureDirectEndpointWakeOffer(q url.Values) {
	values := q[transport.DirectEndpointWakeQueryKey]
	c.offeredDirectEndpointWake = len(values) == 1 && values[0] == transport.DirectEndpointWakeProtocolV1 && directEndpointWakeSuiteOffered(q)
}

// Called after each credential suite's own offer and selection validation.
func (c *NativeObservationConnection) validDirectEndpointWakeSelection(features []string) bool {
	count, source, target := 0, false, false
	for _, feature := range features {
		switch feature {
		case transport.DirectEndpointWakeFeatureV1:
			count++
		case transport.DirectManagedSourceCredentialProtocolV2:
			source = true
		case transport.ManagedDirectCredentialProtocol:
			target = true
		}
	}
	return count == 0 || (count == 1 && c.offeredDirectEndpointWake && (source || target))
}

// directEndpointWakeConnection reserves the wake lane on one captured socket.
// Attachments are local only: no writers, HTTP work or replay are enabled.
type directEndpointWakeConnection struct {
	daemon   *Daemon
	mu       sync.Mutex
	byHandle map[*DirectEndpointSubscription]*directEndpointWakeAttachment
	byID     map[string]*directEndpointWakeAttachment
	usedIDs  map[string]struct{}
	socket   *websocket.Conn
	native   *NativeObservationConnection
	done     chan struct{}
	once     sync.Once
}

func newDirectEndpointWakeConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *directEndpointWakeConnection {
	c := &directEndpointWakeConnection{daemon: d, socket: socket, native: native, done: make(chan struct{}), byHandle: make(map[*DirectEndpointSubscription]*directEndpointWakeAttachment), byID: make(map[string]*directEndpointWakeAttachment), usedIDs: make(map[string]struct{})}
	native.mu.Lock()
	native.directWake = c
	select {
	case <-native.closed:
		c.close()
	default:
	}
	native.mu.Unlock()
	return c
}

func (c *directEndpointWakeConnection) close() {
	if c != nil {
		c.once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			close(c.done)
			for _, entry := range c.byHandle {
				c.removeLocked(entry)
			}
		})
	}
}

// The callback is retained for a later protocol phase and is never invoked here.
type directEndpointWakeAttachment struct {
	handle         *DirectEndpointSubscription
	subscription   transport.DirectEndpointWakeSubscribeV1
	installationID domain.ID
	ctx            context.Context
	cancel         context.CancelFunc
	reconcile      func(context.Context) error
}

// attach registers an exact admitted handle on its captured live socket. It
// does not subscribe on the wire, reconcile, or restore an earlier attachment.
func (c *directEndpointWakeConnection) attach(handle *DirectEndpointSubscription, reconcile func(context.Context) error) error {
	if c == nil || c.daemon == nil || handle == nil || handle.owner != &c.daemon.directSubscriptions || reconcile == nil || !handle.Valid() {
		return ErrNativeObservationConflict
	}
	d := c.daemon
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if c.socket == nil || c.native == nil || d.curConn != c.socket || d.nativeConn != c.native || handle.binding.socket != c.socket || handle.binding.native != c.native {
		return ErrNativeObservationConflict
	}
	c.native.mu.Lock()
	defer c.native.mu.Unlock()
	if c.native.directWake != c || c.native.session == nil {
		return ErrNativeObservationConflict
	}
	select {
	case <-c.native.closed:
		return ErrNativeObservationConflict
	default:
	}
	session, err := json.Marshal(c.native.session)
	if err != nil || string(session) != handle.binding.sessionIdentity {
		return ErrNativeObservationConflict
	}
	metadata := handle.binding.metadata
	role := ""
	normalize := managedDirectCredentialServerOrigin
	suite := []string{transport.ManagedEndpointPrepareProtocol, transport.ManagedEndpointPoPProtocol, transport.ManagedDirectCredentialProtocol}
	switch metadata.Role {
	case "S":
		role = transport.DirectEndpointWakeRoleSourceV2
		normalize = directManagedSourceV2ServerOrigin
		suite = directManagedSourceProtocolsV2[:]
	case "P":
		role = transport.DirectEndpointWakeRoleTargetV1
	default:
		return ErrNativeObservationConflict
	}
	if metadata.ServerOrigin == "" || normalize(metadata.ServerOrigin) != metadata.ServerOrigin || normalize(c.native.serverURL) != metadata.ServerOrigin || normalize(d.nativeServerURL()) != metadata.ServerOrigin {
		return ErrNativeObservationConflict
	}
	features := make(map[string]int)
	for _, feature := range c.native.session.ProtocolFeatures {
		features[feature]++
	}
	if !c.native.offeredDirectEndpointWake || features[transport.DirectEndpointWakeFeatureV1] != 1 {
		return ErrNativeObservationConflict
	}
	for _, feature := range suite {
		if features[feature] != 1 {
			return ErrNativeObservationConflict
		}
	}
	installation, err := uuid.Parse(metadata.InstallationID.String())
	if err != nil || installation == uuid.Nil || installation.String() != metadata.InstallationID.String() {
		return ErrNativeObservationConflict
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return ErrNativeObservationConflict
	default:
	}
	if c.byHandle[handle] != nil {
		return ErrNativeObservationConflict
	}
	if len(c.usedIDs) >= 64 {
		return ErrNativeObservationCapacity
	}
	id := domain.NewID().String()
	if _, used := c.usedIDs[id]; used {
		return ErrNativeObservationConflict
	}
	subscription := transport.DirectEndpointWakeSubscribeV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: id, DirectIntentID: metadata.IntentID.String(), EndpointRole: role, CredentialID: metadata.CredentialID.String()}
	if _, err := subscription.CanonicalBytes(); err != nil {
		return ErrNativeObservationConflict
	}
	ctx, cancel := context.WithCancel(context.Background())
	entry := &directEndpointWakeAttachment{handle: handle, subscription: subscription, installationID: metadata.InstallationID, ctx: ctx, cancel: cancel, reconcile: reconcile}
	// Match the admission fence order: connMu -> native.mu -> lane.mu ->
	// owner leaf lock. No lifecycle lock, I/O, callback or wait enters the
	// owner lock. Map insertion linearizes attachment with exact revocation.
	handle.owner.mu.Lock()
	if _, current := handle.owner.entries[handle]; !current || !time.Now().Before(metadata.Deadline) {
		handle.owner.mu.Unlock()
		cancel()
		return ErrNativeObservationConflict
	}
	c.byHandle[handle], c.byID[id] = entry, entry
	c.usedIDs[id] = struct{}{}
	handle.owner.mu.Unlock()
	go func() {
		select {
		case <-handle.Done():
		case <-ctx.Done():
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.removeLocked(entry)
	}()
	return nil
}

// Removal is exact and nonblocking; lifetime IDs remain reserved after removal.
func (c *directEndpointWakeConnection) removeLocked(entry *directEndpointWakeAttachment) {
	if c.byHandle[entry.handle] != entry || c.byID[entry.subscription.SubscriptionID] != entry {
		return
	}
	delete(c.byHandle, entry.handle)
	delete(c.byID, entry.subscription.SubscriptionID)
	entry.cancel()
}

// Local attachment does not implement the wake protocol. Every reserved wake
// message still violates this connection's protocol and closes it without ACK.
func (c *directEndpointWakeConnection) handle(env transport.Envelope) (bool, error) {
	switch env.Type {
	case transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeOffer, transport.MsgDirectEndpointWakeACK, transport.MsgDirectEndpointWakeUnsubscribe, transport.MsgDirectEndpointWakeClosed:
		return true, ErrNativeObservationConflict
	default:
		return false, nil
	}
}
