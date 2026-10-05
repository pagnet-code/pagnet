package daemon

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/internal/agentbridge"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/fabric/registry"
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
// process-death boundaries.
func (d *Daemon) invalidateHostedSideport(instanceID string) {
	if d == nil || d.HostedFabricSideports == nil {
		return
	}
	d.HostedFabricSideports.Invalidate(instanceID)
}
