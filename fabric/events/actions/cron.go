package actions

import (
	"context"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
)

// SourceIssuer mints the exact signed event bytes and producer proof for one
// internal scheduled tick. It is a trusted infrastructure capability: the proof
// must verify against the store's SourceAuthority. The implementation derives a
// deterministic event identity from the scheduled tick so an identical retry is
// idempotent, never new work.
type SourceIssuer interface {
	Issue(context.Context, time.Time) (SourceInput, error)
}

// CronConfig selects one explicit, generic internal schedule. The schedule is
// configuration, never a core type switch.
type CronConfig struct {
	ID        string
	Store     *Store
	Mode      string // "trigger" or "emit"
	Target    fabric.EndpointRef
	Revision  fabric.Revision
	Issuer    SourceIssuer
	Interval  time.Duration
	Timeout   time.Duration
}

// Cron is a generic internal schedule provider. Each tick mints one signed
// event and translates it into new work through Store.Trigger or Store.Emit.
// Delivery is at-least-once: a tick whose durable commit is uncertain is
// retried with the same scheduled identity, which the queue deduplicates. It
// never claims exactly-once external effects.
type Cron struct {
	config CronConfig
	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
	done   chan struct{}
}

func NewCron(c CronConfig) (*Cron, error) {
	if c.Store == nil || c.Issuer == nil || c.ID == "" || len(c.ID) > 256 ||
		(c.Mode != "trigger" && c.Mode != "emit") ||
		(c.Mode == "emit" && (c.Target.String() == "" || c.Revision == "")) ||
		c.Interval < time.Millisecond || c.Interval > 24*time.Hour ||
		c.Timeout < time.Millisecond || c.Timeout > time.Minute {
		return nil, invalid()
	}
	return &Cron{config: c}, nil
}

// Start launches the bounded scheduler. It returns immediately; the schedule
// runs until Close. The first tick fires at the next interval boundary after
// start, so startup never runs a tick before the caller is ready.
func (c *Cron) Start(ctx context.Context) {
	c.mu.Lock()
	if c.closed || c.cancel != nil {
		c.mu.Unlock()
		return
	}
	lifetime, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})
	c.mu.Unlock()
	go c.run(lifetime)
}

func (c *Cron) run(lifetime context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return
		case next := <-ticker.C:
			c.tick(lifetime, next)
		}
	}
}

// tick translates one scheduled tick into new work. The scheduled time is the
// identity seed, so a retried tick recovers the same queued identity.
func (c *Cron) tick(lifetime context.Context, at time.Time) {
	callCtx, cancel := context.WithTimeout(lifetime, c.config.Timeout)
	defer cancel()
	input, err := c.config.Issuer.Issue(callCtx, at)
	if err != nil {
		return
	}
	if c.config.Mode == "emit" {
		decoded, err := events.Decode(input.ExactEvent, 1<<20)
		if err != nil {
			return
		}
		_, _ = c.config.Store.Emit(callCtx, input, EmitRequest{Target: c.config.Target, Revision: c.config.Revision, Input: decoded.Data()})
		return
	}
	_, _ = c.config.Store.Trigger(callCtx, input)
}

// Close stops the scheduler and joins the in-flight tick. A tick ignoring its
// timeout retains its slot until it truly returns; the lock is never released
// early.
func (c *Cron) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	done := c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
