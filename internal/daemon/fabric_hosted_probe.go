package daemon

import (
	"context"
	"encoding/hex"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/localpeer"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// ProbeHostedProfile inspects the genuine original CLOUD registry/bootstrap and
// authenticated worker. It never creates a local actor, launches/resumes a
// runtime, submits a prompt or infers provenance from a SID/database instance.
func (d *Daemon) ProbeHostedProfile(ctx context.Context, p fabricagent.HostedProfile) error {
	if d == nil || ctx == nil || ctx.Err() != nil || d.nativeRegistry == nil || d.state == nil || p.Validate() != nil {
		return ErrNativeObservationConflict
	}
	record, err := d.nativeRegistry.Lookup(p.Scope.InstanceID)
	if err != nil {
		return err
	}
	if record.Scope != p.Scope || record.Dir != p.WorkerDirectory || record.LaunchState != "launched" || record.ProfileFingerprint != hex.EncodeToString(p.NativeProfile[:]) || record.Ownership == nil || record.Ownership.ID != p.OwnershipID || record.Ownership.OwnershipGeneration != p.Scope.Generation {
		return ErrNativeObservationConflict
	}
	row, found, err := d.state.GetInstance(p.Scope.InstanceID)
	if err != nil {
		return err
	}
	if !found || row.DefinitionID != p.DefinitionID || row.AgentPrincipalID != p.PrincipalID || row.NetworkID != "" && row.NetworkID != p.NetworkID {
		return ErrNativeObservationConflict
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[p.Scope.InstanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return ErrNativeOriginAdmissionDeferred
	}
	proxy, err := d.nativeWorkerFor(link.conn, p.Scope.InstanceID)
	if err != nil {
		return err
	}
	if proxy != link.proxy || proxy.scope != p.Scope || proxy.profile != record.ProfileFingerprint {
		return ErrNativeObservationConflict
	}
	link.mu.Lock()
	ownership := link.ownership
	link.mu.Unlock()
	if ownership.ID != p.OwnershipID || ownership.OwnershipGeneration != p.Scope.Generation {
		return ErrNativeObservationConflict
	}
	// Private ownership binding is immutable and authenticated. It is inspection
	// of the existing dispatch lane, never a new native effect or fresh turn.
	return proxy.BindOwnership(ctx, ownership)
}

// ResolveHostedActivation is called only AFTER the node has loaded the exact
// signed current profile selected by its descriptor binding. The socket peer is
// captured by the node kernel listener. The original worker supplies physical
// realization; no identity, profile, SID, or authority is adopted from cloud DB.
func (d *Daemon) ResolveHostedActivation(ctx context.Context, p fabricagent.HostedProfile, endpoint fabric.EndpointRef, revision fabric.Revision, binding string, peer localpeer.ProcessSnapshot, nonce, generation string) (fabricauth.HostedActivation, error) {
	if endpoint.IsOffer() || endpoint.String() == "" || revision == "" || binding == "" {
		return fabricauth.HostedActivation{}, ErrNativeObservationConflict
	}
	if err := d.ProbeHostedProfile(ctx, p); err != nil {
		return fabricauth.HostedActivation{}, err
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[p.Scope.InstanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return fabricauth.HostedActivation{}, ErrNativeOriginAdmissionDeferred
	}
	proxy, err := d.nativeWorkerFor(link.conn, p.Scope.InstanceID)
	if err != nil || proxy != link.proxy || proxy.scope != p.Scope {
		return fabricauth.HostedActivation{}, ErrNativeObservationConflict
	}
	proof, err := proxy.HostedPeer(ctx, sessionworker.HostedPeerVerificationRequest{Peer: peer, Nonce: nonce, NativeGeneration: generation})
	if err != nil {
		return fabricauth.HostedActivation{}, err
	}
	scope, err := nativeauthority.NewCloudScope(p.Scope)
	if err != nil {
		return fabricauth.HostedActivation{}, err
	}
	return fabricauth.HostedActivation{Scope: scope, Endpoint: endpoint, DescriptorRevision: revision, BindingID: binding, RootPID: proof.RootPID, StartIdentity: proof.RootStart, Nonce: nonce, NativeGeneration: proof.NativeGeneration, NativeSessionID: proof.NativeSessionID}, nil
}

// VerifyHostedActivation rechecks the SAME original physical realization on
// every authenticated operation. A replacement generation requires an explicit
// fresh socket binding; it cannot inherit this connection's earlier authority.
func (d *Daemon) VerifyHostedActivation(ctx context.Context, p fabricagent.HostedProfile, peer fabricauth.HostedPeer) error {
	a := peer.Activation
	expected, err := nativeauthority.NewCloudScope(p.Scope)
	if err != nil || a.Scope != expected {
		return ErrNativeObservationConflict
	}
	actual, err := d.ResolveHostedActivation(ctx, p, a.Endpoint, a.DescriptorRevision, a.BindingID, peer.Process, a.Nonce, a.NativeGeneration)
	if err != nil {
		return err
	}
	if actual != a {
		return ErrNativeObservationConflict
	}
	return nil
}
