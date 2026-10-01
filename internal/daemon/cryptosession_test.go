package daemon

import (
	"fmt"
	"testing"
	"time"
)

// TestSessionStoreTTLExpiry verifies an UNUSED session expires after its TTL
// and an expired session is dropped (a reused sessionId is gone). (get
// refreshes the TTL, so expiry is checked without an intervening use.)
func TestSessionStoreTTLExpiry(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-1", "user-1", "net-1", "pub", "epoch", now)
	// Past the TTL (no intervening use): gone.
	if _, ok := s.get("sess-1", now.Add(sessionTTL+time.Second)); ok {
		t.Fatal("session present past TTL, want gone")
	}
}

// TestSessionStoreRefreshOnUse verifies a use (get) refreshes the TTL, so an
// actively-used session does not expire.
func TestSessionStoreRefreshOnUse(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-1", "user-1", "net-1", "pub", "epoch", now)
	// Used just before the original expiry: the TTL is refreshed.
	if _, ok := s.get("sess-1", now.Add(sessionTTL-time.Second)); !ok {
		t.Fatal("session present on use, want ok")
	}
	// Now it should live until (use time + TTL), well past the original expiry.
	if _, ok := s.get("sess-1", now.Add(sessionTTL+time.Minute)); !ok {
		t.Fatal("refreshed session present, want ok")
	}
}

// Independent tabs must not force each other into repeated 410 recovery.
func TestSessionStoreBrowserTabsCoexist(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("tab-1", "user", "network", "pub-1", "epoch", now)
	s.create("tab-2", "user", "network", "pub-2", "epoch", now)
	for _, id := range []string{"tab-1", "tab-2"} {
		if _, ok := s.get(id, now); !ok {
			t.Fatalf("tab %s replaced", id)
		}
	}
	s.delete("tab-1")
	if sess, ok := s.get("tab-2", now); !ok || sess.BrowserPub != "pub-2" {
		t.Fatal("closing one tab closed the other")
	}
}

func TestSessionStoreBoundedPerAccountAndGlobal(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	for i := 0; i < maxBrowserSessionsPerAccount+1; i++ {
		s.create(fmt.Sprintf("tab-%03d", i), "user", "network", "pub", "epoch", now.Add(time.Duration(i)*time.Nanosecond))
	}
	if len(s.sessions) != maxBrowserSessionsPerAccount {
		t.Fatal("account bound exceeded")
	}
	if _, ok := s.get("tab-000", now); ok {
		t.Fatal("oldest account session not evicted")
	}
	for i := 0; i < maxBrowserSessions+1; i++ {
		s.create(fmt.Sprintf("global-%04d", i), fmt.Sprintf("user-%04d", i), "network", "pub", "epoch", now.Add(time.Duration(i+100)*time.Nanosecond))
	}
	if len(s.sessions) != maxBrowserSessions {
		t.Fatal("global bound exceeded")
	}
	for key, ids := range s.byUserNet {
		if len(ids) == 0 {
			t.Fatalf("empty owner index retained: %s", key)
		}
	}
}

// TestSessionStoreDifferentUserNet verifies sessions for different
// user+network pairs coexist (replacement is per user+network, not global).
func TestSessionStoreDifferentUserNet(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-a", "user-1", "net-1", "pub-a", "epoch", now)
	s.create("sess-b", "user-1", "net-2", "pub-b", "epoch", now)
	s.create("sess-c", "user-2", "net-1", "pub-c", "epoch", now)
	for _, id := range []string{"sess-a", "sess-b", "sess-c"} {
		if _, ok := s.get(id, now.Add(time.Second)); !ok {
			t.Fatalf("session %s does not resolve, want ok", id)
		}
	}
}

// TestSessionStoreDelete verifies explicit end drops a session (idempotent).
func TestSessionStoreDelete(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-1", "user-1", "net-1", "pub", "epoch", now)
	s.delete("sess-1")
	if _, ok := s.get("sess-1", now.Add(time.Second)); ok {
		t.Fatal("session present after delete, want gone")
	}
	// Idempotent: deleting again is a no-op (no panic).
	s.delete("sess-1")
	s.delete("unknown")
}

// TestSessionStoreSweep verifies sweep drops all expired sessions and keeps
// live ones.
func TestSessionStoreSweep(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-live", "user-1", "net-1", "pub", "epoch", now)
	s.create("sess-expired", "user-2", "net-2", "pub", "epoch", now.Add(-2*sessionTTL))
	s.sweep(now)
	if _, ok := s.get("sess-live", now); !ok {
		t.Fatal("live session dropped by sweep, want kept")
	}
	if _, ok := s.get("sess-expired", now); ok {
		t.Fatal("expired session kept by sweep, want dropped")
	}
}

// TestSessionStoreNetworkMismatch is covered by sessionValid (the handler
// gate): a session for one network must not authorize a command for another.
func TestSessionStoreNetworkMismatch(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-1", "user-1", "net-1", "pub", "epoch", now)
	sess, ok := s.get("sess-1", now.Add(time.Second))
	if !ok {
		t.Fatal("session does not resolve, want ok")
	}
	if sess.NetworkID != "net-1" {
		t.Fatalf("session network = %q, want net-1", sess.NetworkID)
	}
}
