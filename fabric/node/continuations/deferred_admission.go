package continuations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
)

// SnapshotCommitment excludes only its own signed admission proof. All exact
// original bytes, allowed identities, plan configuration and pipeline state are
// committed before private Store.Create. No current execution permission follows.
func SnapshotCommitment(snapshot continuation.Snapshot) ([32]byte, error) {
	snapshot.DeferredAdmission = nil
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

type DeferredAdmissionWriter func(context.Context, fabric.ExecutionContext, continuation.Snapshot) ([]byte, error)

// ResumeClaim exists only after the recorder consumes a known durable fresh
// Store claim. It never survives recovery/retry and cannot be serialized. Its
// current resumer remains distinct from the historical original principal.
type ResumeClaim struct {
	mu       sync.Mutex
	used     bool
	snapshot continuation.Snapshot
	receipt  continuation.Receipt
	release  func()
	released bool
}

// OnRelease is private trusted composition; release owns no endpoint outcome.
// The recorder calls it on actual stream termination/Close or unary settlement.
func (p *ResumeClaim) OnRelease(next func()) error {
	if p == nil || next == nil {
		return stale()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released || p.release != nil {
		return stale()
	}
	p.release = next
	return nil
}
func (p *ResumeClaim) Release() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.released {
		p.mu.Unlock()
		return
	}
	p.released = true
	release := p.release
	p.release = nil
	p.mu.Unlock()
	if release != nil {
		release()
	}
}

func (*ResumeClaim) MarshalJSON() ([]byte, error) { return nil, stale() }
func (*ResumeClaim) UnmarshalJSON([]byte) error   { return stale() }
func (*ResumeClaim) String() string               { return "[private resume claim]" }
func (*ResumeClaim) GoString() string             { return "[private resume claim]" }
func (p *ResumeClaim) Consume(resumer fabric.ExecutionContext) (continuation.Snapshot, continuation.Receipt, error) {
	if p == nil {
		return continuation.Snapshot{}, continuation.Receipt{}, stale()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used || resumer.VerifyAuthenticated(p.receipt.Audience) != nil || resumer.PrincipalView() != p.receipt.Principal {
		return continuation.Snapshot{}, continuation.Receipt{}, stale()
	}
	raw, err := json.Marshal(p.snapshot)
	var owned continuation.Snapshot
	if err != nil || json.Unmarshal(raw, &owned) != nil {
		return owned, continuation.Receipt{}, stale()
	}
	p.used = true
	return owned, p.receipt, nil
}

// ResumeAuthority must verify an actual current permitted resumer and retained
// root admission, then install only its private purpose-scoped resume binding.
// A generic historical context is never an acceptable current session.
type ResumeAuthority func(context.Context, fabric.ExecutionContext, fabric.ExecutionContext, *ResumeClaim, func(context.Context, fabric.ExecutionContext) error) error

func runResumeAuthority(authority ResumeAuthority, ctx context.Context, resumer, original fabric.ExecutionContext, claim *ResumeClaim, next func(context.Context, fabric.ExecutionContext) error) error {
	var mu sync.Mutex
	active := true
	calls := 0
	misused := false
	var callbackError error
	err := authority(ctx, resumer, original, claim, func(c context.Context, o fabric.ExecutionContext) error {
		mu.Lock()
		defer mu.Unlock()
		if !active || calls != 0 {
			misused = true
			return stale()
		}
		calls++
		callbackError = next(c, o)
		return callbackError
	})
	mu.Lock()
	defer mu.Unlock()
	active = false
	if calls != 1 || misused {
		return errors.Join(err, callbackError, stale())
	}
	return errors.Join(err, callbackError)
}
