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
	BrowserPub string // base64 X25519 public key
	createdAt  time.Time
	expiresAt  time.Time
}

// sessionStore is the daemon's in-memory browser key-session store. It is
// keyed by sessionID, with a single-flight index by (userID, networkID): a
// new session for the same user+network REPLACES the previous one (the
// browser's keypair is per-session, so the old one is orphaned and its
// sessionId stops resolving).
type sessionStore struct {
	mu        sync.Mutex
	sessions  map[string]*browserSession
	byUserNet map[string]string // "userID\x00networkID" -> sessionID
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions:  map[string]*browserSession{},
		byUserNet: map[string]string{},
	}
}

func userNetKey(userID, networkID string) string { return userID + "\x00" + networkID }

// create records a new session, replacing any existing session for the same
// user+network (single-flight). It returns the recorded session.
func (s *sessionStore) create(sessionID, userID, networkID, browserPub string, now time.Time) *browserSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if oldID, ok := s.byUserNet[userNetKey(userID, networkID)]; ok && oldID != sessionID {
		delete(s.sessions, oldID)
	}
	sess := &browserSession{
		SessionID:  sessionID,
		UserID:     userID,
		NetworkID:  networkID,
		BrowserPub: browserPub,
		createdAt:  now,
		expiresAt:  now.Add(sessionTTL),
	}
	s.sessions[sessionID] = sess
	s.byUserNet[userNetKey(userID, networkID)] = sessionID
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

// dropLocked removes a session and, if it is still the current one for its
// user+network, its index entry. Callers hold s.mu.
func (s *sessionStore) dropLocked(sess *browserSession) {
	delete(s.sessions, sess.SessionID)
	if cur, ok := s.byUserNet[userNetKey(sess.UserID, sess.NetworkID)]; ok && cur == sess.SessionID {
		delete(s.byUserNet, userNetKey(sess.UserID, sess.NetworkID))
	}
}
