package events

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
)

type Handler func(context.Context, event.Event) error

type Subscription struct {
	ID      string
	Types   []string
	Handler Handler
}

type LocalConfig struct {
	Subscriptions    []Subscription
	MaxSubscriptions int
	QueueDepth       int
	MaxQueueBytes    int64
	MaxEventBytes    int
	Timeout          time.Duration
	RetryDelay       time.Duration
	Retention        time.Duration
	MaxAttempts      int
}

type Stats struct {
	Accepted  uint64
	Rejected  uint64
	Delivered uint64
	Retries   uint64
	Expired   uint64
	Pending   uint64
	Bytes     int64
}

type delivery struct {
	raw     []byte
	expires time.Time
}

type observer struct {
	handler Handler
	queue   []*delivery
	head    int
	count   int
	wake    chan struct{}
}

// Local is explicitly volatile. It never claims fsync or crash durability.
// Each observer has one worker and bounded retained bytes, including retries.
// A handler ignoring cancellation occupies its existing worker; it cannot
// spawn unbounded goroutines or block invocation/publishing. Close has its own
// caller deadline because arbitrary Go code cannot be forcibly terminated.
type Local struct {
	mu       sync.Mutex
	config   LocalConfig
	byType   map[string][]*observer
	workers  []*observer
	stats    Stats
	closed   bool
	lifetime context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewLocal(config LocalConfig) (*Local, error) {
	if config.MaxSubscriptions < 1 || config.MaxSubscriptions > 100000 || len(config.Subscriptions) > config.MaxSubscriptions || config.QueueDepth < 1 || config.QueueDepth > 65536 || config.MaxEventBytes < 1 || config.MaxEventBytes > 1<<20 || config.MaxQueueBytes < int64(config.MaxEventBytes) || config.Timeout <= 0 || config.Timeout > time.Minute || config.RetryDelay <= 0 || config.RetryDelay > time.Minute || config.Retention <= 0 || config.Retention > 30*24*time.Hour || config.MaxAttempts < 1 || config.MaxAttempts > 100000 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid local event bus limits")
	}
	if int64(len(config.Subscriptions))*int64(config.QueueDepth)*8 > config.MaxQueueBytes {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Event queue slot allocation exceeds configured budget")
	}
	b := &Local{config: config, byType: make(map[string][]*observer), done: make(chan struct{})}
	seen := make(map[string]bool)
	for _, s := range config.Subscriptions {
		if !fabric.ValidNamespacedName(s.ID) || seen[s.ID] || s.Handler == nil || len(s.Types) < 1 || len(s.Types) > 64 {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid event subscription")
		}
		seen[s.ID] = true
		o := &observer{handler: s.Handler, queue: make([]*delivery, config.QueueDepth), wake: make(chan struct{}, 1)}
		seenTypes := make(map[string]bool)
		for _, kind := range s.Types {
			if !fabric.ValidNamespacedName(kind) || seenTypes[kind] {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid event subscription type")
			}
			seenTypes[kind] = true
			b.byType[kind] = append(b.byType[kind], o)
		}
		b.workers = append(b.workers, o)
	}
	b.config.Subscriptions = nil // no externally mutable configuration retained
	b.lifetime, b.cancel = context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, o := range b.workers {
		wg.Add(1)
		go func() { defer wg.Done(); b.consume(o) }()
	}
	go func() {
		wg.Wait()
		b.mu.Lock()
		for _, o := range b.workers {
			for i := range o.queue {
				o.queue[i] = nil
			}
			o.count = 0
		}
		b.stats.Expired += b.stats.Pending
		b.stats.Pending, b.stats.Bytes = 0, 0
		b.mu.Unlock()
		close(b.done)
	}()
	return b, nil
}

func (b *Local) TryPublish(ctx context.Context, e event.Event) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing event context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := Encode(e, b.config.MaxEventBytes)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fabric.NewError(fabric.CodeTargetUnavailable, "Event bus is closed")
	}
	matched := b.byType[e.Type()]
	// Admission is atomic across matching observers: no partial fan-out where
	// a producer retry would silently duplicate only successful subscriptions.
	needed := int64(len(raw)) * int64(len(matched))
	if needed > b.config.MaxQueueBytes-b.stats.Bytes {
		b.stats.Rejected++
		return fabric.NewError(fabric.CodeTargetUnavailable, "Event queue capacity exceeded")
	}
	for _, o := range matched {
		if o.count == len(o.queue) {
			b.stats.Rejected++
			return fabric.NewError(fabric.CodeTargetUnavailable, "Event queue capacity exceeded")
		}
	}
	d := &delivery{raw: raw, expires: time.Now().Add(b.config.Retention)}
	for _, o := range matched {
		o.queue[(o.head+o.count)%len(o.queue)] = d
		o.count++
		select {
		case o.wake <- struct{}{}:
		default:
		}
	}
	b.stats.Accepted++
	b.stats.Pending += uint64(len(matched))
	b.stats.Bytes += needed
	return nil
}

func (b *Local) Stats() Stats { b.mu.Lock(); defer b.mu.Unlock(); return b.stats }

func (b *Local) consume(o *observer) {
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return
		}
		if o.count == 0 {
			b.mu.Unlock()
			select {
			case <-b.lifetime.Done():
				return
			case <-o.wake:
				continue
			}
		}
		d := o.queue[o.head]
		b.mu.Unlock()
		delivered := false
		for attempt := 0; attempt < b.config.MaxAttempts && time.Now().Before(d.expires); attempt++ {
			if b.lifetime.Err() != nil {
				break
			}
			ctx, cancel := context.WithTimeout(b.lifetime, b.config.Timeout)
			e, err := Decode(d.raw, b.config.MaxEventBytes)
			if err == nil {
				err = callObserver(ctx, o.handler, e)
				if err == nil {
					err = ctx.Err()
				}
			}
			cancel()
			if err == nil {
				delivered = true
				break
			}
			if attempt+1 < b.config.MaxAttempts {
				b.mu.Lock()
				b.stats.Retries++
				b.mu.Unlock()
				timer := time.NewTimer(b.config.RetryDelay)
				select {
				case <-b.lifetime.Done():
					timer.Stop()
				case <-timer.C:
				}
			}
		}
		b.mu.Lock()
		o.queue[o.head] = nil
		o.head = (o.head + 1) % len(o.queue)
		o.count--
		b.stats.Pending--
		b.stats.Bytes -= int64(len(d.raw))
		if delivered {
			b.stats.Delivered++
		} else {
			b.stats.Expired++
		}
		b.mu.Unlock()
	}
}

func callObserver(ctx context.Context, handler Handler, e event.Event) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("event observer failed")
		}
	}()
	return handler(ctx, e)
}

func (b *Local) Close(ctx context.Context) error {
	if ctx == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Missing close context")
	}
	b.mu.Lock()
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ EventBus = (*Local)(nil)
