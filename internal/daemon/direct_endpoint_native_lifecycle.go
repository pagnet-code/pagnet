package daemon

import (
	"encoding/json"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// This observation fences local admission; it is not fresh execution authority.
// A future HTTP operation must reacquire custody and current worker authority.
type directEndpointNativeIdentity struct {
	generation, session, origin, start string
	pid                                int
	active                             bool
}

func directEndpointSnapshotIdentity(snapshot sessionworker.NativeSnapshot) directEndpointNativeIdentity {
	var origin transport.NativeObservationOrigin
	active := !snapshot.IdentityPending && snapshot.PID > 0 && snapshot.NativeGeneration != "" && snapshot.NativeSessionID != "" && snapshot.NativeStartIdentity != "" && json.Unmarshal(snapshot.Origin, &origin) == nil && origin.ID != "" && origin.InstanceID == snapshot.Scope.InstanceID && origin.TenantID == snapshot.Scope.TenantID && origin.HostID == snapshot.Scope.HostID && origin.Runtime == string(snapshot.ActualRuntime) && origin.NativeGeneration == snapshot.NativeGeneration && (origin.NativeSessionID == "" || origin.NativeSessionID == snapshot.NativeSessionID)
	return directEndpointNativeIdentity{snapshot.NativeGeneration, snapshot.NativeSessionID, origin.ID, snapshot.NativeStartIdentity, snapshot.PID, active}
}

func (i directEndpointNativeIdentity) matches(subject nativeManagedSubject) bool {
	return i.active && i.generation == subject.NativeGeneration && i.session == subject.NativeSessionID && i.origin == subject.OriginID.String()
}

// publicationMu serializes observation/explicit transitions with the admission
// fence. IPC completes before this leaf invalidation path acquires any locks.
func (p *NativeWorkerProxy) directEndpointObservationEpoch() uint64 {
	p.publicationMu.RLock()
	defer p.publicationMu.RUnlock()
	return p.directEndpointEpoch
}

func (p *NativeWorkerProxy) observeDirectEndpointSnapshot(snapshot sessionworker.NativeSnapshot, observationEpoch uint64) uint64 {
	identity := directEndpointSnapshotIdentity(snapshot)
	p.publicationMu.Lock()
	defer p.publicationMu.Unlock()
	// Replies that started before another observation/transition cannot replace
	// its baseline or lend its newer epoch to an older verification result.
	if observationEpoch != p.directEndpointEpoch {
		if identity != p.directEndpointIdentity || !identity.active {
			p.directEndpointEpoch++
			p.directInvalidations.revokeMatching(func(b directEndpointBinding) bool { return b.proxy == p })
		}
		return observationEpoch
	}
	if !p.directEndpointObserved || identity != p.directEndpointIdentity || !identity.active {
		p.directEndpointEpoch++
		p.directInvalidations.revokeMatching(func(b directEndpointBinding) bool { return b.proxy == p })
	}
	// A destructive operation remains fenced while the old endpoint is still
	// observed. Only observed inactivity or a changed endpoint ends that fence.
	if !identity.active || (p.directEndpointObserved && identity != p.directEndpointIdentity) {
		p.directEndpointTransition = false
	}
	p.directEndpointIdentity = identity
	p.directEndpointObserved = true
	return p.directEndpointEpoch
}

func (p *NativeWorkerProxy) beginDirectEndpointTransition() {
	p.publicationMu.Lock()
	defer p.publicationMu.Unlock()
	p.directEndpointEpoch++
	p.directEndpointTransition = true
	p.directInvalidations.revokeMatching(func(b directEndpointBinding) bool { return b.proxy == p })
}

func (p *NativeWorkerProxy) directEndpointAuthority(subject nativeManagedSubject) (uint64, bool) {
	p.publicationMu.RLock()
	defer p.publicationMu.RUnlock()
	return p.directEndpointEpoch, !p.directEndpointTransition && p.directEndpointObserved && p.directEndpointIdentity.matches(subject)
}
