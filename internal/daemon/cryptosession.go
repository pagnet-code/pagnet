package daemon

import (
	"os"
	"sync"
	"time"
)

// sessionTTL is the idle TTL of a browser key session (plan §13, p10). It is
// refreshed on every use (unwrap/wrap). A daemon restart drops ALL sessions
// (in-memory only — the same posture as the NKA challenge store): the
// documented recovery is a fresh session start, and a reused sessionId is a
// clean 410 crypto_session_gone.
//
// The default is 15 minutes. PAGNET_BROWSER_SESSION_TTL overrides it for
// tests (the e2e TTL-expiry scenario sets a short value); the production
// default is unchanged when the var is unset.
var sessionTTL = 15 * time.Minute

func init() {
	if v := os.Getenv("PAGNET_BROWSER_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			sessionTTL = d
		}
	}
}

// browserSession is one in-memory browser key session: the authorization
// record the daemon keeps for a browser that has started a key session on a
// private network. It is NOT durable — a daemon restart invalidates every
// session. The browserPub is the X25519 public key the daemon re-wraps read
// CEKs to (the browser's per-session static key).
type browserSession struct {
	SessionID  string
	UserID     string
	NetworkID  string
	EpochID    string // committed network write epoch at session admission
	BrowserPub string // base64 X25519 public key
	createdAt  time.Time
	expiresAt  time.Time
}

// sessionStore is the daemon's in-memory browser key-session store. It is
// keyed by sessionID. Independent browser tabs and devices coexist, bounded
// per account/network and globally; only expiry or explicit teardown ends them.
type sessionStore struct {
	mu        sync.Mutex
	sessions  map[string]*browserSession
	byUserNet map[string]map[string]struct{} // account/network -> session IDs
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions:  map[string]*browserSession{},
		byUserNet: map[string]map[string]struct{}{},
	}
}

func userNetKey(userID, networkID string) string { return userID + "\x00" + networkID }

const maxBrowserSessionsPerAccount = 64
const maxBrowserSessions = 4096

// create records a separate browser session, evicting the oldest session only
// at the configured resource bounds. Callers have already authorized its owner.
func (s *sessionStore) create(sessionID, userID, networkID, browserPub, epochID string, now time.Time) *browserSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.sessions[sessionID]; old != nil {
		s.dropLocked(old)
	}
	key := userNetKey(userID, networkID)
	if len(s.byUserNet[key]) >= maxBrowserSessionsPerAccount {
		s.dropOldestLocked(s.byUserNet[key])
	}
	if len(s.sessions) >= maxBrowserSessions {
		s.dropOldestLocked(nil)
	}
	if s.byUserNet[key] == nil {
		s.byUserNet[key] = map[string]struct{}{}
	}
	sess := &browserSession{
		SessionID:  sessionID,
		UserID:     userID,
		NetworkID:  networkID,
		EpochID:    epochID,
		BrowserPub: browserPub,
		createdAt:  now,
		expiresAt:  now.Add(sessionTTL),
	}
	s.sessions[sessionID] = sess
	s.byUserNet[key][sessionID] = struct{}{}
	return sess
}

// get returns the session, refreshing its TTL (refresh-on-use). ok=false when
// the session is unknown or expired (an expired session is dropped).
func (s *sessionStore) get(sessionID string, now time.Time) (*browserSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	if now.After(sess.expiresAt) {
		s.dropLocked(sess)
		return nil, false
	}
	sess.expiresAt = now.Add(sessionTTL)
	return sess, true
}

// delete drops a session (explicit end). Idempotent.
func (s *sessionStore) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	s.dropLocked(sess)
}

// sweep drops all expired sessions. Called lazily (on create) so an abandoned
// session leaves no residue past its TTL.
func (s *sessionStore) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			s.dropLocked(sess)
		}
	}
}

// dropOldestLocked makes pressure deterministic and bounded. A nil set means
// the global bound; otherwise examine only this account/network's sessions.
func (s *sessionStore) dropOldestLocked(set map[string]struct{}) {
	var oldest *browserSession
	consider := func(sess *browserSession) {
		if sess != nil && (oldest == nil || sess.createdAt.Before(oldest.createdAt) || sess.createdAt.Equal(oldest.createdAt) && sess.SessionID < oldest.SessionID) {
			oldest = sess
		}
	}
	if set == nil {
		for _, sess := range s.sessions {
			consider(sess)
		}
	} else {
		for id := range set {
			consider(s.sessions[id])
		}
	}
	if oldest != nil {
		s.dropLocked(oldest)
	}
}

// dropLocked removes only this tab's session and its index entry.
func (s *sessionStore) dropLocked(sess *browserSession) {
	delete(s.sessions, sess.SessionID)
	key := userNetKey(sess.UserID, sess.NetworkID)
	delete(s.byUserNet[key], sess.SessionID)
	if len(s.byUserNet[key]) == 0 {
		delete(s.byUserNet, key)
	}
}
