package fabricnode

import (
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// IndexPublisher consumes coalesced commit notices, not registry polling. Each
// pass publishes at most two indexed outbox pages; more schedules actual pending
// delta work. Descriptors and schemas are never scanned by discovery.
type IndexPublisher struct {
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	failure error
	passes  uint64
}

// NewIndexPublisher starts AFTER retained Node construction. A buffered notice
// channel may collect commits during setup. The initial pass includes commits
// that occurred between loading the retained index and starting this worker.
// observe runs outside Node locks; it reports actual passes, never effects.
func NewIndexPublisher(ctx context.Context, n *Node, notices <-chan struct{}, observe func(bool, error)) (*IndexPublisher, error) {
	if ctx == nil || ctx.Err() != nil || n == nil || notices == nil {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Missing retained index publication resources")
	}
	life, cancel := context.WithCancel(ctx)
	p := &IndexPublisher{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		pending := true
		for {
			if life.Err() != nil {
				return
			}
			if !pending {
				select {
				case <-life.Done():
					return
				case _, open := <-notices:
					if !open {
						return
					}
					pending = true
				}
			}
			pass, stop := context.WithTimeout(life, 5*time.Second)
			more, err := n.Synchronize(pass, 2)
			stop()
			p.mu.Lock()
			p.passes++
			if err != nil && life.Err() == nil {
				p.failure = err
			}
			p.mu.Unlock()
			if err != nil && life.Err() == nil {
				// A stopped publisher must not silently serve a stale catalog as
				// though committed descriptor changes had become searchable.
				n.mu.Lock()
				if !n.closed && n.quarantine == nil {
					n.quarantine = fabric.NewError(fabric.CodeTargetUnavailable, "Committed catalog updates require retained-index recovery")
				}
				n.mu.Unlock()
			}
			if observe != nil {
				observe(more, err)
			}
			if err != nil {
				return
			}
			pending = more
		}
	}()
	return p, nil
}

func (p *IndexPublisher) Status() (uint64, error) {
	if p == nil {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.passes, p.failure
}
func (p *IndexPublisher) CloseContext(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing index publication shutdown context")
	}
	p.cancel()
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *IndexPublisher) Close() error { return p.CloseContext(context.Background()) }
