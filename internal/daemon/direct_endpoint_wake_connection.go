package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
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
// Only explicit attachments enable protocol traffic on the captured socket.
type directEndpointWakeConnection struct {
	daemon        *Daemon
	mu            sync.Mutex
	byHandle      map[*DirectEndpointSubscription]*directEndpointWakeAttachment
	byID          map[string]*directEndpointWakeAttachment
	usedIDs       map[string]*directEndpointWakeAttachment
	socket        *websocket.Conn
	native        *NativeObservationConnection
	done          chan struct{}
	once          sync.Once
	queue         chan *directEndpointWakeWrite
	pendingWrites map[*directEndpointWakeWrite]struct{}
	writerDone    chan struct{}
	watch         chan struct{}
	write         func(time.Time, []byte) error
	writeFailed   func()
}

func newDirectEndpointWakeConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *directEndpointWakeConnection {
	c := &directEndpointWakeConnection{daemon: d, socket: socket, native: native, done: make(chan struct{}), byHandle: make(map[*DirectEndpointSubscription]*directEndpointWakeAttachment), byID: make(map[string]*directEndpointWakeAttachment), usedIDs: make(map[string]*directEndpointWakeAttachment), queue: make(chan *directEndpointWakeWrite, 64), pendingWrites: make(map[*directEndpointWakeWrite]struct{}), writerDone: make(chan struct{}), watch: make(chan struct{}, 1)}
	c.write = func(deadline time.Time, raw []byte) error {
		err := socket.SetWriteDeadline(deadline)
		if err == nil {
			err = socket.WriteMessage(websocket.TextMessage, raw)
		}
		return err
	}
	// Close the captured socket directly on failure. The read loop performs
	// lifecycle invalidation; this worker must not wait on connMu afterward.
	c.writeFailed = func() { _ = socket.Close() }
	go c.runWriter()
	go c.runWatchdog()
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
			for _, entry := range c.byHandle {
				c.removeLocked(entry, true, context.Canceled)
			}
			close(c.done)
		})
	}
}

// Each registration owns one callback worker and one coalesced obligation.
type directEndpointWakeAttachment struct {
	handle            *DirectEndpointSubscription
	subscription      transport.DirectEndpointWakeSubscribeV1
	installationID    domain.ID
	ctx               context.Context
	cancel            context.CancelFunc
	reconcile         func(context.Context) error
	work              chan struct{}
	pending           bool
	latest, previous  *transport.DirectEndpointWakeOfferV1
	subscribeStarted  bool
	unsubscribeQueued bool
	err               error
}

// attach registers an exact admitted handle on its captured live socket. It
// never restores an earlier attachment or selects a replacement connection.
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
	entry := &directEndpointWakeAttachment{handle: handle, subscription: subscription, installationID: metadata.InstallationID, ctx: ctx, cancel: cancel, reconcile: reconcile, work: make(chan struct{}, 1)}
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
	c.usedIDs[id] = entry
	handle.owner.mu.Unlock()
	if !c.enqueueLocked(entry, transport.MsgDirectEndpointWakeSubscribe, subscription, time.Now()) {
		c.removeLocked(entry, false, ErrNativeObservationCapacity)
		return ErrNativeObservationCapacity
	}
	go c.runReconcile(entry)
	go func() {
		select {
		case <-handle.Done():
		case <-ctx.Done():
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.removeLocked(entry, true, context.Canceled)
	}()
	return nil
}

// Removal is exact and nonblocking; lifetime IDs remain reserved after removal.
func (c *directEndpointWakeConnection) removeLocked(entry *directEndpointWakeAttachment, unsubscribe bool, err error) {
	if c.byHandle[entry.handle] != entry || c.byID[entry.subscription.SubscriptionID] != entry {
		return
	}
	delete(c.byHandle, entry.handle)
	delete(c.byID, entry.subscription.SubscriptionID)
	entry.err = err
	entry.cancel()
	if unsubscribe && entry.subscribeStarted && !entry.unsubscribeQueued {
		entry.unsubscribeQueued = true
		c.enqueueLocked(entry, transport.MsgDirectEndpointWakeUnsubscribe, transport.DirectEndpointWakeUnsubscribeV1{Protocol: transport.DirectEndpointWakeProtocolV1, SubscriptionID: entry.subscription.SubscriptionID}, time.Now())
	}
}

func (c *directEndpointWakeConnection) runReconcile(entry *directEndpointWakeAttachment) {
	for {
		select {
		case <-entry.ctx.Done():
			return
		case <-entry.work:
		}
		for {
			c.mu.Lock()
			if entry.ctx.Err() != nil || !entry.pending || c.byHandle[entry.handle] != entry || !entry.handle.Valid() {
				c.mu.Unlock()
				break
			}
			entry.pending = false
			c.mu.Unlock()
			err := directEndpointWakeReconcile(entry)
			if err != nil {
				c.mu.Lock()
				c.removeLocked(entry, true, err)
				c.mu.Unlock()
				return
			}
		}
	}
}

func directEndpointWakeReconcile(entry *directEndpointWakeAttachment) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("direct endpoint wake reconciliation panicked")
		}
	}()
	return entry.reconcile(entry.ctx)
}

// The read loop belongs to the captured socket. Recheck that lifetime before
// accepting callback obligations or terminal frames from its registration.
func (c *directEndpointWakeConnection) lockRegistration(id string) (*directEndpointWakeAttachment, func()) {
	noop := func() {}
	if c.daemon == nil || c.native == nil {
		return nil, noop
	}
	c.daemon.connMu.Lock()
	if c.daemon.curConn != c.socket || c.daemon.nativeConn != c.native {
		c.daemon.connMu.Unlock()
		return nil, noop
	}
	c.native.mu.Lock()
	c.mu.Lock()
	unlock := func() {
		c.mu.Unlock()
		c.native.mu.Unlock()
		c.daemon.connMu.Unlock()
	}
	entry := c.byID[id]
	if entry == nil {
		entry = c.usedIDs[id]
		if entry == nil || !entry.subscribeStarted || !entry.unsubscribeQueued || entry.ctx.Err() == nil {
			return nil, unlock
		}
	} else if entry.ctx.Err() != nil || !entry.handle.Valid() {
		// Revocation can precede its asynchronous Done watcher. Retire the
		// exact entry here too, so an already queued server hint sees the
		// same local tombstone regardless of goroutine scheduling.
		c.removeLocked(entry, true, context.Canceled)
		if !entry.subscribeStarted || !entry.unsubscribeQueued {
			return nil, unlock
		}
	}
	if c.native.directWake != c {
		return nil, unlock
	}
	select {
	case <-c.done:
		return nil, unlock
	case <-c.native.closed:
		return nil, unlock
	default:
		return entry, unlock
	}
}

func directEndpointWakeOfferAdvances(entry *directEndpointWakeAttachment, offer transport.DirectEndpointWakeOfferV1) bool {
	latest := entry.latest
	if latest == nil {
		return true
	}
	revision, _ := strconv.ParseInt(offer.Revision, 10, 64)
	lastRevision, _ := strconv.ParseInt(latest.Revision, 10, 64)
	return offer.StreamID == latest.StreamID && offer.ContinuityID == latest.ContinuityID && offer.Generation == latest.Generation && revision > lastRevision && offer.OfferID != latest.OfferID && (entry.previous == nil || offer.OfferID != entry.previous.OfferID)
}

func (c *directEndpointWakeConnection) handle(env transport.Envelope) (bool, error) {
	received := time.Now()
	switch env.Type {
	case transport.MsgDirectEndpointWakeOffer:
		if env.ProtocolVersion != transport.ProtocolVersion {
			return true, ErrNativeObservationConflict
		}
		offer, err := transport.DecodeDirectEndpointWakeOfferV1(env.Payload)
		if err != nil {
			return true, ErrNativeObservationConflict
		}
		entry, unlock := c.lockRegistration(offer.SubscriptionID)
		defer unlock()
		if entry == nil {
			return true, ErrNativeObservationConflict
		}
		duplicate := (entry.latest != nil && *entry.latest == offer) || (entry.previous != nil && *entry.previous == offer)
		if !duplicate && !directEndpointWakeOfferAdvances(entry, offer) {
			return true, ErrNativeObservationConflict
		}
		if c.byID[offer.SubscriptionID] != entry {
			// An exact local tombstone may race a frame already on the socket.
			// It cannot create an ACK or revive a callback obligation. Pin a
			// late first tuple so later raced hints cannot change its stream.
			if entry.latest == nil {
				entry.latest = &offer
			}
			return true, nil
		}
		if !duplicate {
			entry.previous, entry.latest = entry.latest, &offer
			// Accept the obligation before admitting the ACK. A single worker
			// fulfills it independently of the captured-socket writer.
			entry.pending = true
			select {
			case entry.work <- struct{}{}:
			default:
			}
		}
		if !c.enqueueLocked(entry, transport.MsgDirectEndpointWakeACK, transport.DirectEndpointWakeACKV1(offer), received) {
			c.removeLocked(entry, true, ErrNativeObservationCapacity)
		}
		return true, nil
	case transport.MsgDirectEndpointWakeClosed:
		if env.ProtocolVersion != transport.ProtocolVersion {
			return true, ErrNativeObservationConflict
		}
		closed, err := transport.DecodeDirectEndpointWakeClosedV1(env.Payload)
		if err != nil {
			return true, ErrNativeObservationConflict
		}
		entry, unlock := c.lockRegistration(closed.SubscriptionID)
		defer unlock()
		if entry == nil {
			return true, ErrNativeObservationConflict
		}
		if c.byID[closed.SubscriptionID] != entry {
			if closed.Reason != transport.DirectEndpointWakeClosedRetryExhausted {
				return true, ErrNativeObservationConflict
			}
			return true, nil
		}
		c.removeLocked(entry, false, ErrNativeOriginAdmissionRejected)
		return true, nil
	case transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeACK, transport.MsgDirectEndpointWakeUnsubscribe:
		return true, ErrNativeObservationConflict
	default:
		return false, nil
	}
}
