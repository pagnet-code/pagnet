package durable

import (
	"context"
	"sync"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
)

type IngressConfig struct {
	QueueDepth    int
	MaxBytes      int64
	MaxEventBytes int
	WriteTimeout  time.Duration
}
type IngressStats struct {
	VolatileAccepted, Rejected, DurableCommitted, DuplicateCommitted, WriteFailed, ShutdownDiscarded uint64
	Pending                                                                                          int
	Bytes                                                                                            int64
}

// Ingress is finite and VOLATILE. TryPublish's nil means owned volatile queue
// admission only, never a durable receipt. One writer commits asynchronously;
// write/overflow/discard metrics expose loss without blocking node invocations.
type Ingress struct {
	mu        sync.Mutex
	config    IngressConfig
	publisher Publisher
	queue     chan []byte
	stats     IngressStats
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
}

// ValidateIngressConfig performs no IO and starts no background worker.
func ValidateIngressConfig(c IngressConfig) error {
	if c.QueueDepth < 1 || c.QueueDepth > 65536 || c.MaxBytes < 1 || c.MaxBytes > 1<<30 || c.MaxEventBytes < 1 || c.MaxEventBytes > 1<<20 || c.MaxBytes < int64(c.MaxEventBytes) || int64(c.QueueDepth)*24+int64(c.MaxEventBytes) > c.MaxBytes || c.WriteTimeout < time.Millisecond || c.WriteTimeout > time.Minute {
		return invalid("Invalid volatile event ingress limits")
	}
	return nil
}
func NewIngress(ctx context.Context, p Publisher, c IngressConfig) (*Ingress, error) {
	if ctx == nil || p == nil || ValidateIngressConfig(c) != nil {
		return nil, invalid("Invalid volatile event ingress limits")
	}
	lifetime, cancel := context.WithCancel(ctx)
	i := &Ingress{config: c, publisher: p, queue: make(chan []byte, c.QueueDepth), ctx: lifetime, cancel: cancel, done: make(chan struct{})}
	go i.write()
	return i, nil
}
func (i *Ingress) TryPublish(ctx context.Context, e event.Event) error {
	if ctx == nil {
		return invalid("Missing event context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := events.Encode(e, i.config.MaxEventBytes)
	if err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if ctx.Err() != nil {
		clear(raw)
		i.stats.Rejected++
		return ctx.Err()
	}
	if i.closed || i.ctx.Err() != nil || int64(len(raw)) > i.config.MaxBytes-int64(i.config.QueueDepth)*24-i.stats.Bytes {
		clear(raw)
		i.stats.Rejected++
		return fabric.NewError(fabric.CodeTargetUnavailable, "Volatile event ingress unavailable")
	}
	select {
	case i.queue <- raw:
		i.stats.VolatileAccepted++
		i.stats.Pending++
		i.stats.Bytes += int64(len(raw))
		return nil
	default:
		clear(raw)
		i.stats.Rejected++
		return fabric.NewError(fabric.CodeTargetUnavailable, "Volatile event ingress capacity exceeded")
	}
}
func (i *Ingress) write() {
	defer close(i.done)
	defer func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		for {
			select {
			case raw := <-i.queue:
				i.stats.ShutdownDiscarded++
				i.stats.Pending--
				i.stats.Bytes -= int64(len(raw))
				clear(raw)
			default:
				return
			}
		}
	}()
	for {
		if i.ctx.Err() != nil {
			return
		}
		select {
		case <-i.ctx.Done():
			return
		case raw := <-i.queue:
			if i.ctx.Err() != nil {
				i.mu.Lock()
				i.stats.ShutdownDiscarded++
				i.stats.Pending--
				i.stats.Bytes -= int64(len(raw))
				i.mu.Unlock()
				clear(raw)
				return
			}
			e, err := events.Decode(raw, i.config.MaxEventBytes)
			var receipt Receipt
			if err == nil {
				ctx, cancel := context.WithTimeout(i.ctx, i.config.WriteTimeout)
				receipt, err = i.publisher.Publish(ctx, e)
				cancel()
			}
			i.mu.Lock()
			i.stats.Pending--
			i.stats.Bytes -= int64(len(raw))
			if err != nil {
				i.stats.WriteFailed++
			} else {
				i.stats.DurableCommitted++
				if receipt.Duplicate {
					i.stats.DuplicateCommitted++
				}
			}
			i.mu.Unlock()
			clear(raw)
		}
	}
}
func (i *Ingress) Stats() IngressStats { i.mu.Lock(); defer i.mu.Unlock(); return i.stats }
func (i *Ingress) Close(ctx context.Context) error {
	if ctx == nil {
		return invalid("Missing ingress close context")
	}
	i.mu.Lock()
	i.closed = true
	i.mu.Unlock()
	i.cancel()
	select {
	case <-i.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
