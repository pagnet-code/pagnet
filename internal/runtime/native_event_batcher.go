package runtime

import (
	"encoding/json"
	"sync"

	"github.com/pagnet-code/pagnet/internal/session"
)

// Parsers stay single-consumer; concurrent native choice resolution shares this
// ordering gate. Only already parsed consecutive output can wait in the bounded
// batch. Control, source changes and idle/EOF force synchronous durable flush.
type nativeEventBatcher struct {
	mu      sync.Mutex
	observe session.NativeEventObserver
	batch   session.NativeEventBatchObserver
	publish func(session.SessionEvent) error
	pending []session.SessionEvent
	bytes   int
	err     error
}

func (b *nativeEventBatcher) push(event session.SessionEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if b.batch != nil && event.Type == session.EventTurnOutput && event.NativeOutput && event.Output != "" {
		raw, err := json.Marshal(event)
		if err != nil {
			b.err = err
			return err
		}
		size := len(raw)
		if len(b.pending) > 0 && (b.pending[0].SessionID != event.SessionID || b.pending[0].TurnID != event.TurnID || size > session.NativeOutputBatchMaxBytes-b.bytes) {
			if err = b.flushLocked(); err != nil {
				return err
			}
		}
		b.pending = append(b.pending, event)
		b.bytes += size
		if len(b.pending) >= session.NativeOutputBatchMaxEvents || b.bytes >= session.NativeOutputBatchMaxBytes {
			return b.flushLocked()
		}
		return nil
	}
	if err := b.flushLocked(); err != nil {
		return err
	}
	if b.observe != nil {
		if err := b.observe(event); err != nil {
			b.err = err
			return err
		}
	}
	if b.publish != nil {
		b.err = b.publish(event)
	}
	return b.err
}
func (b *nativeEventBatcher) flushLocked() error {
	if b.err != nil || len(b.pending) == 0 {
		return b.err
	}
	if len(b.pending) > 1 {
		b.err = b.batch(b.pending)
	} else if b.observe != nil {
		b.err = b.observe(b.pending[0])
	}
	if b.err != nil {
		return b.err
	}
	for _, event := range b.pending {
		if b.publish != nil {
			if err := b.publish(event); err != nil {
				b.err = err
				return err
			}
		}
	}
	clear(b.pending)
	b.pending = b.pending[:0]
	b.bytes = 0
	return nil
}
func (b *nativeEventBatcher) flush() error   { b.mu.Lock(); defer b.mu.Unlock(); return b.flushLocked() }
func (b *nativeEventBatcher) failure() error { b.mu.Lock(); defer b.mu.Unlock(); return b.err }
