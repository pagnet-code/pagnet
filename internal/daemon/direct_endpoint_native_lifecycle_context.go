//go:build linux || darwin

package daemon

import (
	"context"
	"sync"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func directEndpointTryWLock(ctx context.Context, mu *sync.RWMutex) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locked := mu.TryLock()
	if err := ctx.Err(); err != nil {
		if locked {
			mu.Unlock()
		}
		return nil, err
	}
	if !locked {
		return nil, errDirectEndpointLocalBusy
	}
	return mu.Unlock, nil
}

func (p *NativeWorkerProxy) directEndpointObservationEpochContext(ctx context.Context) (uint64, error) {
	unlock, err := directEndpointTryRLock(ctx, &p.publicationMu)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return p.directEndpointEpoch, nil
}

// Acquire every leaf owner before changing lifecycle state so a failed local
// acquisition cannot leave a partially revoked generation.
func (i *directEndpointInvalidations) lockDirectEndpointOwnersContext(ctx context.Context) (func(), error) {
	unlockIndex, err := directEndpointTryLock(ctx, &i.mu)
	if err != nil {
		return nil, err
	}
	unlocks := []func(){unlockIndex}
	unlock := func() {
		for n := len(unlocks) - 1; n >= 0; n-- {
			unlocks[n]()
		}
	}
	for o := range i.owners {
		unlockOwner, err := directEndpointTryLock(ctx, &o.mu)
		if err != nil {
			unlock()
			return nil, err
		}
		unlocks = append(unlocks, unlockOwner)
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// The publication, invalidation index, and all owner locks must be held.
func (p *NativeWorkerProxy) revokeDirectEndpointSubscriptionsLocked() {
	for o := range p.directInvalidations.owners {
		for s := range o.entries {
			if s.binding.proxy == p {
				o.removeLocked(s)
			}
		}
	}
}

func (p *NativeWorkerProxy) observeDirectEndpointSnapshotContext(ctx context.Context, snapshot sessionworker.NativeSnapshot, observationEpoch uint64) (uint64, error) {
	identity := directEndpointSnapshotIdentity(snapshot)
	unlock, err := directEndpointTryWLock(ctx, &p.publicationMu)
	if err != nil {
		return 0, err
	}
	defer unlock()
	unlockOwners, err := p.directInvalidations.lockDirectEndpointOwnersContext(ctx)
	if err != nil {
		return 0, err
	}
	defer unlockOwners()
	if observationEpoch != p.directEndpointEpoch {
		if identity != p.directEndpointIdentity || !identity.active {
			p.directEndpointEpoch++
			p.revokeDirectEndpointSubscriptionsLocked()
		}
		return observationEpoch, nil
	}
	if !p.directEndpointObserved || identity != p.directEndpointIdentity || !identity.active {
		p.directEndpointEpoch++
		p.revokeDirectEndpointSubscriptionsLocked()
	}
	if !identity.active || (p.directEndpointObserved && identity != p.directEndpointIdentity) {
		p.directEndpointTransition = false
	}
	p.directEndpointIdentity = identity
	p.directEndpointObserved = true
	return p.directEndpointEpoch, nil
}

func (p *NativeWorkerProxy) beginDirectEndpointTransitionContext(ctx context.Context) error {
	unlock, err := directEndpointTryWLock(ctx, &p.publicationMu)
	if err != nil {
		return err
	}
	defer unlock()
	unlockOwners, err := p.directInvalidations.lockDirectEndpointOwnersContext(ctx)
	if err != nil {
		return err
	}
	defer unlockOwners()
	p.directEndpointEpoch++
	p.directEndpointTransition = true
	p.revokeDirectEndpointSubscriptionsLocked()
	return nil
}

func (p *NativeWorkerProxy) directEndpointAuthorityContext(ctx context.Context, subject nativeManagedSubject) (uint64, bool, error) {
	if p.aborted() {
		return 0, false, nil
	}
	unlock, err := directEndpointTryRLock(ctx, &p.publicationMu)
	if err != nil {
		return 0, false, err
	}
	defer unlock()
	return p.directEndpointEpoch, !p.aborted() && !p.directEndpointTransition && p.directEndpointObserved && p.directEndpointIdentity.matches(subject), nil
}
