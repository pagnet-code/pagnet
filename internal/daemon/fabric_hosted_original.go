package daemon

import (
	"context"

	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// OriginalHostedWorker selects only the explicitly associated original worker.
// It authenticates current real controller ownership, never adopts an instance
// from a database row or manufactures a replacement local execution profile.
// The returned shared proxy belongs to the daemon; readers must never Close it.
func (d *Daemon) OriginalHostedWorker(ctx context.Context, profile fabricagent.HostedProfile) (*NativeWorkerProxy, error) {
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return nil, err
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[profile.Scope.InstanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return nil, ErrNativeOriginAdmissionDeferred
	}
	proxy, err := d.nativeWorkerFor(link.conn, profile.Scope.InstanceID)
	if err != nil {
		return nil, err
	}
	if proxy != link.proxy || proxy.scope != profile.Scope {
		return nil, ErrNativeObservationConflict
	}
	return proxy, nil
}

// WaitHostedOriginalSource waits on the actual original journal's notification
// lane. It does not submit, wake, retry or cancel paid work. The trusted caller
// must authorize the retained local root receipt before calling this read port.
// SID and native generation come ONLY from the committed original turn source.
func (d *Daemon) WaitHostedOriginalSource(ctx context.Context, profile fabricagent.HostedProfile, proof transport.NativeDispatchProof) (sessionworker.NativeTurnSource, error) {
	if proof.OwnershipID != profile.OwnershipID || proof.OwnershipGeneration != profile.Scope.Generation || proof.DispatchSequence <= 0 || proof.SourceCommandID == "" || proof.SourceAdmissionID == "" || proof.TaskSource != nil || proof.InvocationSource == nil || proof.InvocationSource.Validate() != nil || proof.InvocationSource.InputAAD.NetworkID != profile.NetworkID || proof.InvocationSource.InputAAD.Recipient != profile.Scope.InstanceID {
		return sessionworker.NativeTurnSource{}, ErrNativeObservationConflict
	}
	proxy, err := d.OriginalHostedWorker(ctx, profile)
	if err != nil {
		return sessionworker.NativeTurnSource{}, err
	}
	request := sessionworker.CloudInvocationSourceRequest{Sequence: proof.DispatchSequence, CommandID: proof.SourceCommandID, AdmissionID: proof.SourceAdmissionID, Invocation: *proof.InvocationSource}
	for {
		result, err := proxy.HostedInvocationSource(ctx, request)
		if err != nil {
			return sessionworker.NativeTurnSource{}, err
		}
		if result.Source != nil {
			return *result.Source, nil
		}
		if _, err = proxy.WaitHostedInvocationSource(ctx, profile.WorkerDirectory, result.Ready); err != nil {
			return sessionworker.NativeTurnSource{}, err
		}
	}
}

// OpenHostedOriginalProjection decrypts only the pinned source epoch, never a
// current/new epoch substitution. The worker's projection digest, complete
// source, original AAD and offset are checked by the shared decoder. The trusted
// adapter must additionally verify native origin/capture, monotonic cursors and
// terminal semantics before exposing content or reporting completion.
func (d *Daemon) OpenHostedOriginalProjection(profile fabricagent.HostedProfile, source sessionworker.NativeTurnSource, projection sessionworker.InvocationStreamProjection) (sessionworker.InvocationStreamRange, error) {
	if d == nil || profile.Validate() != nil || source.SourceInvocation == nil || source.SourceInvocation.Validate() != nil || source.SourceInvocation.InputAAD.NetworkID != profile.NetworkID || source.SourceInvocation.InputAAD.Recipient != profile.Scope.InstanceID || projection.AAD.NetworkID != profile.NetworkID || projection.AAD.KeyEpochID != source.SourceInvocation.InputAAD.KeyEpochID {
		return sessionworker.InvocationStreamRange{}, ErrNativeObservationConflict
	}
	keyring, err := crypto.LoadKeyring(d.StateDir, profile.NetworkID)
	if err != nil {
		return sessionworker.InvocationStreamRange{}, err
	}
	epoch, found := keyring.EpochByID(source.SourceInvocation.InputAAD.KeyEpochID)
	if !found {
		return sessionworker.InvocationStreamRange{}, ErrNativeObservationConflict
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return sessionworker.InvocationStreamRange{}, err
	}
	defer clear(key[:])
	return sessionworker.OpenInvocationStreamProjection(projection, source, profile.Scope.InstanceID, key)
}
