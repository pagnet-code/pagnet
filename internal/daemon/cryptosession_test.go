package daemon

import (
	"testing"
	"time"
)

// TestSessionStoreTTLExpiry verifies an UNUSED session expires after its TTL
// and an expired session is dropped (a reused sessionId is gone). (get
// refreshes the TTL, so expiry is checked without an intervening use.)
func TestSessionStoreTTLExpiry(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-1", "user-1", "net-1", "pub", now)
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
	s.create("sess-1", "user-1", "net-1", "pub", now)
	// Used just before the original expiry: the TTL is refreshed.
	if _, ok := s.get("sess-1", now.Add(sessionTTL-time.Second)); !ok {
		t.Fatal("session present on use, want ok")
	}
	// Now it should live until (use time + TTL), well past the original expiry.
	if _, ok := s.get("sess-1", now.Add(sessionTTL+time.Minute)); !ok {
		t.Fatal("refreshed session present, want ok")
	}
}

// TestSessionStoreReplace verifies a new session for the same user+network
// replaces the previous one (single-flight): the old sessionId stops
// resolving, the new one resolves.
func TestSessionStoreReplace(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-old", "user-1", "net-1", "pub-old", now)
	s.create("sess-new", "user-1", "net-1", "pub-new", now)
	if _, ok := s.get("sess-old", now.Add(time.Second)); ok {
		t.Fatal("old session still resolves after replacement, want gone")
	}
	sess, ok := s.get("sess-new", now.Add(time.Second))
	if !ok {
		t.Fatal("new session does not resolve, want ok")
	}
	if sess.BrowserPub != "pub-new" {
		t.Fatalf("new session browserPub = %q, want pub-new", sess.BrowserPub)
	}
}

// TestSessionStoreDifferentUserNet verifies sessions for different
// user+network pairs coexist (replacement is per user+network, not global).
func TestSessionStoreDifferentUserNet(t *testing.T) {
	s := newSessionStore()
	now := time.Now().UTC()
	s.create("sess-a", "user-1", "net-1", "pub-a", now)
	s.create("sess-b", "user-1", "net-2", "pub-b", now)
	s.create("sess-c", "user-2", "net-1", "pub-c", now)
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
	s.create("sess-1", "user-1", "net-1", "pub", now)
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
	s.create("sess-live", "user-1", "net-1", "pub", now)
	s.create("sess-expired", "user-2", "net-2", "pub", now.Add(-2*sessionTTL))
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
	s.create("sess-1", "user-1", "net-1", "pub", now)
	sess, ok := s.get("sess-1", now.Add(time.Second))
	if !ok {
		t.Fatal("session does not resolve, want ok")
	}
	if sess.NetworkID != "net-1" {
		t.Fatalf("session network = %q, want net-1", sess.NetworkID)
	}
}
