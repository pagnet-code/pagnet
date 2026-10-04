package sessionworker

import (
	"context"
	"sync"
	"time"
)

const maxReadinessCounter uint64 = (1 << 53) - 1
const localReadinessTimeout = 30 * time.Second

// ReadinessToken is ephemeral notification metadata, never a source receipt or
// permission. A worker restart changes Boot; counters never wrap or reset within
// that boot. Every wake must cross current source authorization before Page.
type ReadinessToken struct {
	Boot    string `json:"boot"`
	Counter uint64 `json:"counter,string"`
}

func (t ReadinessToken) valid() bool { return validNonce(t.Boot) && t.Counter <= maxReadinessCounter }

type localReadiness struct {
	mu      sync.Mutex
	token   ReadinessToken
	changed chan struct{}
	closed  bool
}

func newLocalReadiness() (*localReadiness, error) {
	boot, e := freshNonce()
	if e != nil {
		return nil, e
	}
	return &localReadiness{token: ReadinessToken{Boot: boot}, changed: make(chan struct{})}, nil
}
func (n *localReadiness) snapshot() ReadinessToken {
	if n == nil {
		return ReadinessToken{}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.token
}
func (n *localReadiness) pulse() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	close(n.changed)
	if n.token.Counter >= maxReadinessCounter {
		n.closed = true
		return
	}
	n.token.Counter++
	n.changed = make(chan struct{})
}
func (n *localReadiness) close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.closed {
		n.closed = true
		close(n.changed)
	}
}
func (n *localReadiness) wait(ctx context.Context, last ReadinessToken) (ReadinessToken, error) {
	if n == nil || ctx == nil || !last.valid() {
		return ReadinessToken{}, ErrFenced
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ReadinessToken{}, ErrFenced
	}
	token, ch := n.token, n.changed
	n.mu.Unlock()
	if token != last {
		return token, nil
	}
	timer := time.NewTimer(localReadinessTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ReadinessToken{}, ctx.Err()
	case <-timer.C:
	case <-ch:
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return ReadinessToken{}, ErrFenced
	}
	return n.token, nil
}
func (j *Journal) pulseLocalReady() {
	if j.isLocal() {
		j.localReadiness.pulse()
	}
}
