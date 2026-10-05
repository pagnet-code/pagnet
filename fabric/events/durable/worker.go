package durable

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
)

type WorkerConfig struct {
	Handlers     map[string]Handler
	Timeout      time.Duration
	PollInterval time.Duration
}
type WorkerStats struct{ Delivered, Retried, SettlementFailed, ClaimFailed uint64 }
type Workers struct {
	cancel                                            context.CancelFunc
	done                                              chan struct{}
	delivered, retried, settlementFailed, claimFailed atomic.Uint64
}

// StartWorkers starts one sequential worker per configured handler, never per
// event. An arbitrary Go handler ignoring cancellation can occupy only its own
// existing worker; Close uses a caller deadline rather than claiming to kill it.
func StartWorkers(ctx context.Context, s *Store, c WorkerConfig) (*Workers, error) {
	if ctx == nil || s == nil || len(c.Handlers) < 1 || len(c.Handlers) > s.config.MaxSubscriptions || c.Timeout < time.Millisecond || c.Timeout > time.Minute || c.PollInterval < time.Millisecond || c.PollInterval > time.Second {
		return nil, invalid("Invalid durable event workers")
	}
	known := map[string]bool{}
	for _, sub := range s.config.Subscriptions {
		known[sub.ID] = true
	}
	handlers := make(map[string]Handler, len(c.Handlers))
	for id, h := range c.Handlers {
		if !known[id] || h == nil {
			return nil, invalid("Unregistered durable event handler")
		}
		handlers[id] = h
	}
	lifetime, cancel := context.WithCancel(ctx)
	w := &Workers{cancel: cancel, done: make(chan struct{})}
	var wg sync.WaitGroup
	for sub, handler := range handlers {
		wg.Add(1)
		go func(sub string, h Handler) {
			defer wg.Done()
			worker := "events.worker." + claimHash(sub)[:32]
			for lifetime.Err() == nil {
				delivery, ok, err := s.Claim(lifetime, sub, worker, time.Now().UTC())
				if err != nil {
					w.claimFailed.Add(1)
				}
				if err != nil || !ok {
					timer := time.NewTimer(c.PollInterval)
					select {
					case <-lifetime.Done():
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						return
					case <-timer.C:
					}
					continue
				}
				until := time.Now().Add(c.Timeout)
				if delivery.LeaseUntil.Before(until) {
					until = delivery.LeaseUntil
				}
				callCtx, callCancel := context.WithDeadline(lifetime, until)
				// FULL claim IO may exhaust the lease before a callback can begin.
				// Never start an effect with an already-expired/cancelled context.
				err = callCtx.Err()
				if err == nil && !time.Now().Before(until) {
					err = context.DeadlineExceeded
				}
				if err == nil {
					err = callHandler(callCtx, h, delivery.Event)
				}
				// A handler ignoring its timeout cannot turn a late return into ACK.
				if err == nil {
					err = callCtx.Err()
					if err == nil && !time.Now().Before(until) {
						err = context.DeadlineExceeded
					}
				}
				callCancel()
				if err == nil {
					err = s.Ack(lifetime, delivery.Claim, time.Now().UTC())
					if err == nil {
						w.delivered.Add(1)
					}
				} else {
					err = s.Nack(lifetime, delivery.Claim, time.Now().UTC())
					if err == nil {
						w.retried.Add(1)
					}
				}
				if err != nil {
					w.settlementFailed.Add(1)
				}
			}
		}(sub, handler)
	}
	go func() { wg.Wait(); close(w.done) }()
	return w, nil
}

func callHandler(ctx context.Context, h Handler, e event.Event) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("event handler failed")
		}
	}()
	return h(ctx, e)
}
func (w *Workers) Stats() WorkerStats {
	return WorkerStats{w.delivered.Load(), w.retried.Load(), w.settlementFailed.Load(), w.claimFailed.Load()}
}
func (w *Workers) Close(ctx context.Context) error {
	if ctx == nil {
		return invalid("Missing worker close context")
	}
	w.cancel()
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
