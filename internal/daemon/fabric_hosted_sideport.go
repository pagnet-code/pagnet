package daemon

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// HostedFabricSideports is the owner-administration association between one
// launched original worker's existing journal/controller IPC (the daemon's
// instance row + live native worker link) and the node's private socket,
// stable endpoint and original generation.
//
// The association is created only through Associate, which re-derives the
// EXACT installed profile from the node's selected-binding resolve port (the
// same authority the step-2 delivery guard verifies against) and re-probes
// the genuine original worker. It carries no nonce, principal or signing key
// — the worker's own per-activation nonce and kernel ancestry supply the
// proof when its bridge opens the second socket. A daemon without this
// composition advertises no sideport anywhere (fail-closed, like the
// delivery guard).
type HostedFabricSideports struct {
	resolve    func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error)
	mu         sync.RWMutex
	byInstance map[string]agentbridge.HostedFabricSideport
}

// NewHostedFabricSideports composes the association over the node's
// selected-binding resolve port. A nil resolve port yields nil: no
// association, no advertisement, no invented authority.
func NewHostedFabricSideports(resolve func(ctx context.Context, instanceID string) (registry.DescriptorBatchScope, fabricagent.HostedProfile, error)) *HostedFabricSideports {
	if resolve == nil {
		return nil
	}
	return &HostedFabricSideports{resolve: resolve, byInstance: map[string]agentbridge.HostedFabricSideport{}}
}

// Associate binds the sideport to the launched original worker. The genuine
// owner administration performs this call (the node composition runs it from
// under the owner session); the daemon side verifies the same facts the
// delivery guard verifies — never a delivery- or caller-supplied triple:
//
//  1. the sideport shape (private socket, stable non-offer endpoint, bounded
//     original generation);
//  2. the EXACT installed profile for the instance from the journal resolve
//     port (the signed association, not a descriptor description);
//  3. the sideport's stable endpoint and original generation matching that
//     profile's scope byte-for-byte;
//  4. the genuine original worker itself (the daemon's real registry,
//     controller and ownership probe).
//
// Any mismatch is a conflict — the association is refused, never partially
// stored, and a prior exact association for the instance is replaced only by
// another owner-administration act.
func (d *Daemon) AssociateHostedFabricSideport(ctx context.Context, instanceID string, sp agentbridge.HostedFabricSideport) error {
	if d == nil || ctx == nil || ctx.Err() != nil || d.HostedFabricSideports == nil {
		return ErrNativeObservationConflict
	}
	if err := sp.Validate(); err != nil {
		return err
	}
	// The strict advertisement contract (Phase A step 6d) requires a live
	// worker to push to: a sideport exists only to be advertised on the
	// worker's own bridge. Without a live link there is nothing to
	// advertise to — refuse before anything is stored. (After the re-probe
	// below the link cannot be absent — the probe itself requires it — but
	// the guard keeps the contract honest at the cheap end.)
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[instanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return ErrNativeObservationConflict
	}
	scope, profile, err := d.HostedFabricSideports.resolve(ctx, instanceID)
	if err != nil {
		return err
	}
	if profile.Validate() != nil || profile.Scope.InstanceID != instanceID ||
		sp.Endpoint != scope.Endpoint || sp.Generation != profile.Scope.Generation {
		return ErrNativeObservationConflict
	}
	// Private ownership binding is immutable and authenticated: inspection
	// of the existing dispatch lane, never a new native effect.
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return err
	}
	d.HostedFabricSideports.Store(instanceID, sp)
	// The owner administration succeeds iff the association is stored AND
	// advertised on the live worker. A stored-but-unadvertised association
	// is an unobservable dead state: roll back the just-stored value on
	// push failure and surface the error.
	if err := d.pushHostedSideportToWorker(ctx, instanceID, &sp); err != nil {
		d.HostedFabricSideports.Invalidate(instanceID)
		return err
	}
	return nil
}

// pushHostedSideportToWorker advertises (sp non-nil) or clears (sp nil) the
// instance's associated sideport on the live worker over the daemon's
// authenticated controller connection. On success it records the value in
// the link's tracked last-pushed state, which the pump's reconciliation
// compares against the registry (a wire frame is re-sent only on mismatch).
// No live link is an honest error: there is nothing to push to, and the
// caller decides whether that is transient (reconciled later) or final
// (the strict association refuses).
func (d *Daemon) pushHostedSideportToWorker(ctx context.Context, instanceID string, sp *agentbridge.HostedFabricSideport) error {
	if d == nil || instanceID == "" {
		return ErrNativeObservationConflict
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[instanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return ErrNativeObservationConflict
	}
	req := sessionworker.Request{Type: "hosted_sideport_clear"}
	if sp != nil {
		req = sessionworker.Request{Type: "hosted_sideport_set", HostedSideport: sp}
	}
	if _, err := link.proxy.call(ctx, req); err != nil {
		return err
	}
	link.mu.Lock()
	if sp == nil {
		link.sideportPushed = agentbridge.HostedFabricSideport{}
		link.sideportPushedPresent = false
	} else {
		link.sideportPushed = *sp
		link.sideportPushedPresent = true
	}
	link.mu.Unlock()
	return nil
}

// Store records (or replaces, under another owner-administration act) the
// instance's association.
func (s *HostedFabricSideports) Store(instanceID string, sp agentbridge.HostedFabricSideport) {
	if s == nil || instanceID == "" {
		return
	}
	s.mu.Lock()
	s.byInstance[instanceID] = sp
	s.mu.Unlock()
}

// For returns the instance's associated sideport, advertised ONLY in the
// instance's authenticated bridge handshake.
func (s *HostedFabricSideports) For(instanceID string) (agentbridge.HostedFabricSideport, bool) {
	if s == nil || instanceID == "" {
		return agentbridge.HostedFabricSideport{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sp, ok := s.byInstance[instanceID]
	return sp, ok
}

// Invalidate drops the instance's association at its process-death
// boundaries (stop, hibernate, activation reset, removal) — the same
// lifecycle as the per-activation bridge nonce, so a dead activation can
// never advertise a sideport again.
func (s *HostedFabricSideports) Invalidate(instanceID string) {
	if s == nil || instanceID == "" {
		return
	}
	s.mu.Lock()
	delete(s.byInstance, instanceID)
	s.mu.Unlock()
}

// hostedFabricSideportFor is the nil-safe advertisement lookup used by the
// bridge auth ack.
func (d *Daemon) hostedFabricSideportFor(instanceID string) (agentbridge.HostedFabricSideport, bool) {
	if d == nil || d.HostedFabricSideports == nil {
		return agentbridge.HostedFabricSideport{}, false
	}
	return d.HostedFabricSideports.For(instanceID)
}

// invalidateHostedSideport mirrors invalidateBridgeNonce at the instance's
// process-death boundaries. It drops the registry association and pushes the
// clear to the live worker's advertisement (best-effort: a dead link has
// nothing to clear — a fresh worker attaches clean and the pump's
// reconciliation has nothing to restore). Every existing call site
// (stop, forget, restart, native removal) gets both effects from this one
// helper.
func (d *Daemon) invalidateHostedSideport(instanceID string) {
	if d == nil || d.HostedFabricSideports == nil {
		return
	}
	d.HostedFabricSideports.Invalidate(instanceID)
	// Bounded: the controller call carries its own deadline; a dead worker
	// fails fast. The lifecycle paths this runs on are not latency-critical.
	if err := d.pushHostedSideportToWorker(d.turnCtx, instanceID, nil); err != nil {
		if d.Log != nil {
			d.Log.Warn("hosted sideport clear push failed at process-death boundary", "instance", instanceID, "err", err.Error())
		}
	}
}
