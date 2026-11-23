package daemon

import (
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// The reader stages a bounded snapshot and fences the worker synchronously.
// Accepted routes are connection-local evidence, never messaging authority.
type accountMessagingReadinessSubscription struct {
	c                                                *accountMessagingReadinessConnection
	mu                                               sync.Mutex
	frame                                            transport.AccountMessagingReadinessSubscriptionFrame
	revision                                         uint64
	expiryGeneration                                 uint64
	offers                                           []transport.AccountMessagingReadinessRoute
	pending                                          map[string]transport.AccountMessagingReadinessRoute
	accepted                                         map[string]transport.AccountMessagingReadinessRoute
	complete, processing, resetQueued, awaitingReset bool
	timer                                            *time.Timer
	enabled                                          atomic.Bool
}

func newAccountMessagingReadinessSubscriptionConnection(d *Daemon, socket *websocket.Conn, native *NativeObservationConnection) *accountMessagingReadinessConnection {
	c := newAccountMessagingReadinessConnection(d, socket, native)
	c.subscription = &accountMessagingReadinessSubscription{c: c}
	return c
}

func (a *accountMessagingReadinessSubscription) invalidateLocked() {
	a.revision++
	a.expiryGeneration++
	a.offers = nil
	a.pending = nil
	a.accepted = nil
	a.complete = false
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
}
func (a *accountMessagingReadinessSubscription) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.invalidateLocked()
}

func (c *accountMessagingReadinessConnection) localEvidenceChanged() {
	a := c.subscription
	if !c.usesSubscription() {
		return
	}
	a.mu.Lock()
	a.invalidateLocked()
	a.awaitingReset = true
	if a.resetQueued {
		a.mu.Unlock()
		return
	}
	a.resetQueued = true
	a.mu.Unlock()
	c.enqueue(func() {
		a.mu.Lock()
		a.resetQueued = false
		a.mu.Unlock()
		if !c.hello {
			return
		}
		c.send(transport.MsgAccountMessagingReadinessHello, transport.AccountMessagingReadinessSubscriptionHelloPayload{V: 2, Protocol: transport.AccountMessagingReadinessSubscriptionProtocol, Reset: true})
	})
}

func (a *accountMessagingReadinessSubscription) matches(f transport.AccountMessagingReadinessSubscriptionFrame) bool {
	return a.frame == f && a.frame.Version != "" && !a.awaitingReset
}

func (a *accountMessagingReadinessSubscription) handle(env transport.Envelope) {
	if !a.c.usesSubscription() {
		return
	}
	if _, ok := a.c.session(); !ok {
		return
	}
	a.mu.Lock()
	if a.awaitingReset && env.Type != transport.MsgAccountMessagingReadinessReset {
		a.mu.Unlock()
		return
	}
	bad := false
	schedule := false
	switch env.Type {
	case transport.MsgAccountMessagingReadinessReset:
		p, err := transport.ParseAccountMessagingReadinessSubscriptionReset(env.Payload)
		if err != nil {
			bad = true
			break
		}
		f := p.AccountMessagingReadinessSubscriptionFrame
		if a.frame.SubscriptionID != "" {
			old, _ := strconv.ParseUint(a.frame.Version, 10, 64)
			next, _ := strconv.ParseUint(f.Version, 10, 64)
			if f.SubscriptionID != a.frame.SubscriptionID {
				bad = true
				break
			}
			if next <= old {
				break
			}
		}
		a.invalidateLocked()
		a.frame = f
		a.awaitingReset = false
	case transport.MsgAccountMessagingReadinessOffer:
		p, err := transport.ParseAccountMessagingReadinessSubscriptionOffer(env.Payload)
		if err != nil || !a.matches(p.AccountMessagingReadinessSubscriptionFrame) || a.complete || len(a.offers) >= 256 {
			bad = true
			break
		}
		for _, r := range a.offers {
			if r.OfferID == p.Route.OfferID || r.AccountMessagingReadinessCandidate == p.Route.AccountMessagingReadinessCandidate {
				bad = true
				break
			}
		}
		if !bad {
			a.offers = append(a.offers, p.Route)
		}
	case transport.MsgAccountMessagingReadinessSnapshotComplete:
		p, err := transport.ParseAccountMessagingReadinessSubscriptionComplete(env.Payload)
		if err != nil || !a.matches(p.AccountMessagingReadinessSubscriptionFrame) || a.complete || p.OfferCount != len(a.offers) {
			bad = true
			break
		}
		if p.Status == "capacity_exceeded" {
			a.invalidateLocked()
			a.awaitingReset = true
			break
		}
		a.complete = true
		a.armExpiryLocked()
		if !a.processing {
			a.processing = true
			schedule = true
		}
	case transport.MsgAccountMessagingReadinessAccepted:
		p, err := transport.ParseAccountMessagingReadinessSubscriptionAccepted(env.Payload)
		if err != nil {
			bad = true
			break
		}
		// Delayed acceptance from a reset snapshot has no effect.
		if !a.matches(p.AccountMessagingReadinessSubscriptionFrame) || a.c.d.accountMessagingMutationActive() {
			break
		}
		offered, ok := a.pending[p.Route.OfferID.String()]
		if !ok {
			break
		}
		r := p.Route
		r.Status, r.AckedAt = "offered", nil
		if !reflect.DeepEqual(r, offered) {
			bad = true
			break
		}
		if !time.Now().Before(offered.ExpiresAt) {
			break
		}
		if a.accepted == nil {
			a.accepted = make(map[string]transport.AccountMessagingReadinessRoute)
		}
		a.accepted[r.OfferID.String()] = p.Route
		a.armExpiryLocked()
	}
	a.mu.Unlock()
	if bad {
		a.c.close()
	} else if schedule {
		a.c.enqueue(a.process)
	}
}

func (a *accountMessagingReadinessSubscription) current(revision uint64, frame transport.AccountMessagingReadinessSubscriptionFrame, r transport.AccountMessagingReadinessRoute, tenant string) bool {
	a.mu.Lock()
	valid := a.revision == revision && a.matches(frame) && a.complete && !a.c.d.accountMessagingMutationActive()
	a.mu.Unlock()
	return a.c.usesSubscription() && valid && time.Now().Before(r.OfferDeadline) && time.Now().Before(r.ExpiresAt) && a.c.networkMatches(r.NetworkID.String(), tenant, r.EpochID)
}

// At most one job owns local I/O. New snapshots replace staged work instead of
// placing one task per offer in the command queue.
func (a *accountMessagingReadinessSubscription) process() {
	var processed uint64
	for {
		a.mu.Lock()
		if !a.complete || a.revision == processed {
			a.processing = false
			a.mu.Unlock()
			return
		}
		revision, frame := a.revision, a.frame
		processed = revision
		routes := append([]transport.AccountMessagingReadinessRoute(nil), a.offers...)
		a.mu.Unlock()
		for _, r := range routes {
			a.processOffer(revision, frame, r)
		}
	}
}

func (a *accountMessagingReadinessSubscription) processOffer(revision uint64, frame transport.AccountMessagingReadinessSubscriptionFrame, r transport.AccountMessagingReadinessRoute) {
	c := a.c
	s, ok := c.session()
	if !ok || r.HostID.String() != s.HostID || r.RunnerID.String() != s.RunnerID || !r.RunnerConnectedAt.Equal(s.RunnerEpoch) || time.Now().Before(r.OfferedAt) || !a.current(revision, frame, r, s.TenantID) || c.d.state == nil {
		return
	}
	row, found, err := c.lookup(r.TargetInstanceID.String())
	if err != nil || !found || row.DefinitionID != r.TargetDefinitionID.String() || row.AgentPrincipalID != r.TargetPrincipalID.String() || row.NetworkID != r.NetworkID.String() || (row.Status != "idle" && row.Status != "working") {
		return
	}
	kr, err := c.loadKeyring(r.NetworkID.String())
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
	if !a.current(revision, frame, r, s.TenantID) {
		return
	}

	c.send(transport.MsgAccountMessagingReadinessAck, transport.AccountMessagingReadinessSubscriptionAckPayload{AccountMessagingReadinessSubscriptionFrame: frame, AccountMessagingReadinessAck: transport.AccountMessagingReadinessAck{AccountMessagingReadinessCandidate: r.AccountMessagingReadinessCandidate, OfferID: r.OfferID, Generation: r.Generation, Digest: r.Digest}}, func() bool {
		if !a.current(revision, frame, r, s.TenantID) {
			return false
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.revision != revision || !a.matches(frame) || a.c.d.accountMessagingMutationActive() {
			return false
		}
		if a.pending == nil {
			a.pending = make(map[string]transport.AccountMessagingReadinessRoute)
		}
		a.pending[r.OfferID.String()] = r
		return true
	})
}

func (d *Daemon) setReadinessInstanceStatus(instanceID, status, sessionID string) error {
	finish := d.beginAccountMessagingMutation()
	defer finish()
	return d.state.SetInstanceStatus(instanceID, status, sessionID)
}

// Keep replacement snapshots from observing a local mutation before its commit.
// No controller lock is held during database or keyring work.
func (d *Daemon) beginAccountMessagingMutation() func() {
	d.connMu.Lock()
	d.accountReadinessMutations++
	c := d.accountReadiness
	d.connMu.Unlock()
	if c != nil {
		c.localEvidenceChanged()
	}
	return func() {
		d.connMu.Lock()
		d.accountReadinessMutations--
		current := d.accountReadiness
		d.connMu.Unlock()
		if current != nil {
			current.localEvidenceChanged()
		}
	}
}
func (d *Daemon) accountMessagingMutationActive() bool {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	return d.accountReadinessMutations != 0
}
func (c *accountMessagingReadinessConnection) usesSubscription() bool {
	return c.subscription != nil && c.subscription.enabled.Load()
}

// Expiry is a single timer for this snapshot, including when local I/O stalls.
func (a *accountMessagingReadinessSubscription) armExpiryLocked() {
	a.expiryGeneration++
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	var deadline time.Time
	for _, r := range a.offers {
		next := r.OfferDeadline
		if _, ok := a.accepted[r.OfferID.String()]; ok {
			next = r.ExpiresAt
		}
		if deadline.IsZero() || next.Before(deadline) {
			deadline = next
		}
	}
	if deadline.IsZero() {
		return
	}
	revision, expiry := a.revision, a.expiryGeneration
	a.timer = time.AfterFunc(time.Until(deadline), func() {
		a.mu.Lock()
		current := a.revision == revision && a.expiryGeneration == expiry
		if current {
			a.invalidateLocked()
			a.awaitingReset = true
		}
		a.mu.Unlock()
	})
}
