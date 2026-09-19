package sdk

import (
	"container/list"
	"sync"
)

// DefaultSeenCap is the bound on the duplicate-delivery LRU (delivery ids,
// message ids and invocation ids share one set each). A redelivered id within
// the window is re-acked (events/messages) or not re-executed (invocations);
// beyond the window the server's own idempotency guards apply.
const DefaultSeenCap = 4096

// lruSet is a bounded last-recently-used set of string keys. It is the
// duplicate-delivery safety memory (plan §50, north-star §118): the server
// may redeliver a delivery after an uncertain failure or reconnect, and the
// SDK must recognize it instead of re-running the handler.
//
// Eviction is LRU: when the set is full, the least recently used key is
// dropped. An evicted id may be re-executed if redelivered much later — the
// server-side idempotency guards (delivery state, invocation state) are the
// backstop; the LRU only protects the common window (recent redeliveries).
type lruSet struct {
	mu    sync.Mutex
	cap   int
	order *list.List               // front = most recent
	items map[string]*list.Element // key → element (value is the key)
}

func newLRUSet(cap int) *lruSet {
	if cap <= 0 {
		cap = DefaultSeenCap
	}
	return &lruSet{
		cap:   cap,
		order: list.New(),
		items: make(map[string]*list.Element, cap),
	}
}

// Add inserts key and reports whether it was NEW (true) or already present
// (false — a duplicate; the caller re-acks or skips instead of re-running).
// Present keys are refreshed to most-recent.
func (s *lruSet) Add(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.order.MoveToFront(el)
		return false
	}
	el := s.order.PushFront(key)
	s.items[key] = el
	if s.order.Len() > s.cap {
		back := s.order.Back()
		if back != nil {
			s.order.Remove(back)
			delete(s.items, back.Value.(string))
		}
	}
	return true
}

// Contains reports whether key is in the set without refreshing recency.
func (s *lruSet) Contains(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[key]
	return ok
}

// Len returns the current number of entries.
func (s *lruSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}
