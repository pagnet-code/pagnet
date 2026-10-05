package continuation

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/pagnet-code/pagnet/fabric"
)

// FreshClaim is a private, once-only execution capability created only after
// Claim's durable transaction succeeds. A serialized receipt, a retry, or a
// recovered claimed row cannot manufacture it. It grants no endpoint permission.
type FreshClaim struct {
	mu                sync.Mutex
	store             *Store
	receipt, snapshot []byte
	used              bool
}

func (*FreshClaim) MarshalJSON() ([]byte, error) { return nil, stale() }
func (*FreshClaim) UnmarshalJSON([]byte) error   { return stale() }
func (*FreshClaim) String() string               { return "[private fresh continuation claim]" }
func (*FreshClaim) GoString() string             { return "[private fresh continuation claim]" }

// Consume verifies the exact live private store and durable receipt again and
// returns an owned snapshot once. Trusted composition must independently verify
// the genuinely current resumer and actual destination authority before effects.
func (p *FreshClaim) Consume(ctx context.Context, s *Store, resumer fabric.ExecutionContext, receipt Receipt) (Snapshot, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || s == nil {
		return Snapshot{}, stale()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used || p.store != s || s.authenticated(resumer) != nil || receipt.Principal != resumer.PrincipalView() || receipt.Audience != s.scope.Audience {
		return Snapshot{}, stale()
	}
	raw, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(raw, p.receipt) {
		return Snapshot{}, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.transaction(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	r, err := load(ctx, tx, receipt.ID)
	if err != nil {
		return Snapshot{}, err
	}
	if r.state != Claimed || !bytes.Equal(r.receipt, p.receipt) || !bytes.Equal(r.snapshot, p.snapshot) || r.digest != receipt.SnapshotDigest {
		return Snapshot{}, stale()
	}
	snapshot, err := s.snapshot(p.snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	p.used = true
	return snapshot, nil
}
