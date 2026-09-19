package sdk

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// eventSubs is the OnEvent → server-side subscription reconciliation shared
// by the participants that can react to events (Agent and Service). The
// server is the source of truth: subscriptions are re-checked on every
// (re)connect and created only when missing.
type eventSubs struct {
	client     *Client
	kind       string // "agent" or "service" (error messages)
	name       string
	mu         sync.Mutex
	networkID  string
	pending    []string // OnEvent patterns not yet subscribed server-side
	subscribed map[string]bool
}

func (s *eventSubs) addPattern(pattern string) {
	s.mu.Lock()
	s.pending = append(s.pending, pattern)
	s.mu.Unlock()
}

func (s *eventSubs) setNetwork(networkID string) {
	s.mu.Lock()
	s.networkID = networkID
	s.mu.Unlock()
}

// network resolves the participant's default network: the pinned one, else
// the principal's single active membership.
func (s *eventSubs) network(ctx context.Context) (string, error) {
	s.mu.Lock()
	nid := s.networkID
	s.mu.Unlock()
	if nid != "" {
		return nid, nil
	}
	id := s.client.cachedIdentity()
	if id == nil {
		var err error
		id, err = s.client.WhoAmI(ctx)
		if err != nil {
			return "", fmt.Errorf("sdk: %s %s: resolve network: %w", s.kind, s.name, err)
		}
	}
	var active []Membership
	for _, m := range id.Memberships {
		if m.Active() {
			active = append(active, m)
		}
	}
	switch len(active) {
	case 1:
		return active[0].NetworkID, nil
	case 0:
		return "", fmt.Errorf("sdk: %s %s: the principal has no active network membership (SetNetwork to pin one)", s.kind, s.name)
	default:
		return "", fmt.Errorf("sdk: %s %s: the principal has %d active memberships — SetNetwork to pick one", s.kind, s.name, len(active))
	}
}

// reconcile ensures a server-side subscription exists for every OnEvent
// pattern. Runs at Run/Serve and after every (re)connect; a failure is
// transient (the pattern stays pending and is retried on the next
// (re)connect).
func (s *eventSubs) reconcile() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nid, err := s.network(ctx)
	if err != nil {
		return // no resolvable network yet: retry on the next (re)connect
	}
	s.mu.Lock()
	pending := make([]string, len(s.pending))
	copy(pending, s.pending)
	s.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	subs, err := s.client.rest.listSubscriptions(ctx, nid)
	if err != nil {
		return // transient: retry on the next (re)connect
	}
	have := make(map[string]bool, len(subs))
	for _, sub := range subs {
		have[sub.EventPattern] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := s.pending[:0]
	for _, p := range s.pending {
		if have[p] || s.subscribed[p] {
			continue
		}
		if _, err := s.client.rest.createSubscription(ctx, nid, restSubscriptionRequest{
			EventPattern: p,
			DeliveryMode: "deliver",
		}); err == nil {
			s.subscribed[p] = true
		} else {
			remaining = append(remaining, p)
		}
	}
	s.pending = remaining
}
