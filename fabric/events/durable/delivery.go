package durable

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"time"
)

// Claim uses indexed due/lease queues. A returned generation authorizes only
// this delivery lease. Reopen preserves leases; expiry can cause redelivery.
// A false result means no eligible delivery, or one exhausted delivery was
// durably failed; callers may try again without pretending it was acknowledged.
func (s *Store) Claim(ctx context.Context, subscription, worker string, now time.Time) (Delivery, bool, error) {
	if ctx == nil || !validText(subscription, 256) || !validText(worker, 256) || now.IsZero() || now.UnixNano() <= 0 || now.UnixNano() > math.MaxInt64-int64(s.config.LeaseTTL) {
		return Delivery{}, false, invalid("Invalid delivery claim")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Delivery{}, false, unavailable()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Delivery{}, false, unavailable()
	}
	defer tx.Rollback()
	// Two bounded index seeks avoid sorting/scanning a combined due backlog.
	type candidate struct {
		source, id string
		eligible   int64
		found      bool
	}
	var candidates [2]candidate
	for index, query := range []string{
		"SELECT source,id,due FROM deliveries WHERE subscription=? AND state='pending' AND due<=? ORDER BY due,source,id LIMIT 1",
		"SELECT source,id,lease FROM deliveries WHERE subscription=? AND state='claimed' AND lease<=? ORDER BY lease,source,id LIMIT 1",
	} {
		err = tx.QueryRowContext(ctx, query, subscription, now.UnixNano()).Scan(&candidates[index].source, &candidates[index].id, &candidates[index].eligible)
		if err == nil {
			candidates[index].found = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Delivery{}, false, unavailable()
		}
	}
	chosen := candidates[0]
	other := candidates[1]
	if other.found && (!chosen.found || other.eligible < chosen.eligible || (other.eligible == chosen.eligible && (other.source < chosen.source || (other.source == chosen.source && other.id < chosen.id)))) {
		chosen = other
	}
	if !chosen.found {
		return Delivery{}, false, nil
	}
	source, id := chosen.source, chosen.id
	var digest string
	var cipher []byte
	var expires, generation int64
	var attempts int
	if tx.QueryRowContext(ctx, "SELECT e.digest,CASE WHEN length(e.cipher)<=? THEN e.cipher ELSE NULL END,e.expires,d.generation,d.attempt FROM events e JOIN deliveries d ON e.source=d.source AND e.id=d.id WHERE d.subscription=? AND d.source=? AND d.id=?", s.config.MaxCipherBytes, subscription, source, id).Scan(&digest, &cipher, &expires, &generation, &attempts) != nil {
		return Delivery{}, false, unavailable()
	}
	if now.UnixNano() >= expires || attempts >= s.config.MaxAttempts {
		reason := "attempts_exhausted"
		if now.UnixNano() >= expires {
			reason = "delivery_expired"
		}
		if _, err = tx.ExecContext(ctx, "UPDATE deliveries SET state='failed',reason=?,worker='',token_hash='',lease=0 WHERE subscription=? AND source=? AND id=?", reason, subscription, source, id); err != nil {
			return Delivery{}, false, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET pending=pending-1 WHERE id=?", subscription); err != nil {
			return Delivery{}, false, unavailable()
		}
		if tx.Commit() != nil {
			return Delivery{}, false, unavailable()
		}
		return Delivery{}, false, nil
	}
	if generation < 0 || generation == math.MaxInt64 || attempts < 0 {
		return Delivery{}, false, unavailable()
	}
	original, err := s.decode(source, id, digest, cipher)
	if err != nil {
		return Delivery{}, false, err
	}
	var tokenBytes [24]byte
	if _, err = rand.Read(tokenBytes[:]); err != nil {
		return Delivery{}, false, unavailable()
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	tokenHash := claimHash(token)
	lease := now.Add(s.config.LeaseTTL)
	if lease.UnixNano() > expires {
		lease = time.Unix(0, expires)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE deliveries SET state='claimed',lease=?,attempt=attempt+1,generation=generation+1,worker=?,token_hash=?,reason='' WHERE subscription=? AND source=? AND id=? AND generation=?", lease.UnixNano(), worker, tokenHash, subscription, source, id, generation); err != nil {
		return Delivery{}, false, unavailable()
	}
	if tx.Commit() != nil {
		return Delivery{}, false, unavailable()
	}
	return Delivery{Claim: Claim{Subscription: subscription, Source: source, ID: id, Worker: worker, Generation: generation + 1, Token: token}, Event: original, Digest: digest, Attempt: attempts + 1, LeaseUntil: lease}, true, nil
}
func claimHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func validClaim(c Claim) bool {
	return validText(c.Subscription, 256) && validText(c.Source, 4096) && validText(c.ID, 256) && validText(c.Worker, 256) && c.Generation > 0 && len(c.Token) == 32
}
func (s *Store) Ack(ctx context.Context, c Claim, now time.Time) error {
	return s.settle(ctx, c, now, true)
}
func (s *Store) Nack(ctx context.Context, c Claim, now time.Time) error {
	return s.settle(ctx, c, now, false)
}
func (s *Store) settle(ctx context.Context, c Claim, now time.Time, ack bool) error {
	if ctx == nil || !validClaim(c) || now.IsZero() || now.UnixNano() <= 0 || now.UnixNano() > math.MaxInt64-int64(s.config.RetryDelay) {
		return invalid("Invalid delivery settlement")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return unavailable()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return unavailable()
	}
	defer tx.Rollback()
	var attempts int
	var expires int64
	err = tx.QueryRowContext(ctx, "SELECT d.attempt,e.expires FROM deliveries d JOIN events e ON e.source=d.source AND e.id=d.id WHERE d.subscription=? AND d.source=? AND d.id=? AND d.state='claimed' AND d.generation=? AND d.worker=? AND d.token_hash=? AND d.lease>?", c.Subscription, c.Source, c.ID, c.Generation, c.Worker, claimHash(c.Token), now.UnixNano()).Scan(&attempts, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return stale()
	}
	if err != nil {
		return unavailable()
	}
	state, reason, due := "acked", "", now.UnixNano()
	if !ack {
		state = "pending"
		due = now.Add(s.config.RetryDelay).UnixNano()
		if attempts >= s.config.MaxAttempts {
			state, reason = "failed", "attempts_exhausted"
		}
		if now.UnixNano() >= expires {
			state, reason = "failed", "delivery_expired"
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE deliveries SET state=?,reason=?,due=?,lease=0,worker='',token_hash='' WHERE subscription=? AND source=? AND id=? AND state='claimed' AND generation=?", state, reason, due, c.Subscription, c.Source, c.ID, c.Generation); err != nil {
		return unavailable()
	}
	if state != "pending" {
		if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET pending=pending-1 WHERE id=?", c.Subscription); err != nil {
			return unavailable()
		}
	}
	if tx.Commit() != nil {
		return unavailable()
	}
	return nil
}
func (s *Store) State(ctx context.Context) (State, error) {
	if ctx == nil {
		return State{}, invalid("Missing event context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return State{}, unavailable()
	}
	var st State
	if s.db.QueryRowContext(ctx, "SELECT rows,bytes FROM budget WHERE singleton=1").Scan(&st.Rows, &st.Bytes) != nil {
		return st, unavailable()
	}
	rows, err := s.db.QueryContext(ctx, "SELECT state,count(*) FROM deliveries GROUP BY state")
	if err != nil {
		return st, unavailable()
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int64
		if rows.Scan(&state, &n) != nil {
			return st, unavailable()
		}
		switch state {
		case "pending":
			st.Pending = n
		case "claimed":
			st.Claimed = n
		case "acked":
			st.Acknowledged = n
		case "failed":
			st.Failed = n
		default:
			return st, unavailable()
		}
	}
	if rows.Err() != nil {
		return st, unavailable()
	}
	return st, nil
}

// Purge explicitly forgets settled event identities only after configured dedup
// retention. Before that, even fully acknowledged identities consume budget.
// Missing/unknown claims never justify deleting a pending/claimed delivery.
func (s *Store) Purge(ctx context.Context, before time.Time, limit int) (int, error) {
	if ctx == nil || before.IsZero() || limit < 1 || limit > 1024 || before.After(time.Now()) {
		return 0, invalid("Invalid bounded event purge")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, unavailable()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, unavailable()
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT e.source,e.id,e.cost,(SELECT count(*) FROM deliveries d WHERE d.source=e.source AND d.id=e.id) FROM events e WHERE retain_until<=? AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.source=e.source AND d.id=e.id AND d.state IN ('pending','claimed')) ORDER BY retain_until,e.source,e.id LIMIT ?`, before.UnixNano(), limit)
	if err != nil {
		return 0, unavailable()
	}
	type purge struct {
		source, id string
		cost, n    int64
	}
	var candidates []purge
	for rows.Next() {
		var p purge
		if rows.Scan(&p.source, &p.id, &p.cost, &p.n) != nil {
			rows.Close()
			return 0, unavailable()
		}
		candidates = append(candidates, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, unavailable()
	}
	for _, p := range candidates {
		if _, err = tx.ExecContext(ctx, "DELETE FROM deliveries WHERE source=? AND id=?", p.source, p.id); err != nil {
			return 0, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM events WHERE source=? AND id=?", p.source, p.id); err != nil {
			return 0, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "UPDATE budget SET rows=rows-?,bytes=bytes-? WHERE singleton=1", 1+p.n, p.cost); err != nil {
			return 0, unavailable()
		}
	}
	if tx.Commit() != nil {
		return 0, unavailable()
	}
	return len(candidates), nil
}

// DeliveryStatus exposes bounded queue metadata, never event plaintext or claim tokens.
type DeliveryStatus struct {
	State                   string
	Attempt                 int
	Generation              int64
	LeaseUntil, NextAttempt time.Time
	Reason                  string
}

func (s *Store) Inspect(ctx context.Context, subscription, source, id string) (DeliveryStatus, error) {
	if ctx == nil || !validText(subscription, 256) || !validText(source, 4096) || !validText(id, 256) {
		return DeliveryStatus{}, invalid("Invalid event delivery identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return DeliveryStatus{}, unavailable()
	}
	var st DeliveryStatus
	var lease, due int64
	err := s.db.QueryRowContext(ctx, "SELECT state,attempt,generation,lease,due,reason FROM deliveries WHERE subscription=? AND source=? AND id=?", subscription, source, id).Scan(&st.State, &st.Attempt, &st.Generation, &lease, &due, &st.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return st, stale()
	}
	if err != nil {
		return st, unavailable()
	}
	if lease != 0 {
		st.LeaseUntil = time.Unix(0, lease).UTC()
	}
	st.NextAttempt = time.Unix(0, due).UTC()
	return st, nil
}

// Expire is explicit bounded queue administration for subscriptions with no
// active consumer. Expired records become truthful delivery failures and remain
// inspectable/deduplicated until explicit Purge; no native work is cancelled.
func (s *Store) Expire(ctx context.Context, before time.Time, limit int) (int, error) {
	if ctx == nil || before.IsZero() || before.After(time.Now()) || limit < 1 || limit > 1024 {
		return 0, invalid("Invalid bounded event expiry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, unavailable()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, unavailable()
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT e.source,e.id FROM events e WHERE e.expires<=? AND EXISTS(SELECT 1 FROM deliveries d WHERE d.source=e.source AND d.id=e.id AND d.state IN ('pending','claimed')) ORDER BY expires,source,id LIMIT ?`, before.UnixNano(), limit)
	if err != nil {
		return 0, unavailable()
	}
	type identity struct{ source, id string }
	var events []identity
	for rows.Next() {
		var id identity
		if rows.Scan(&id.source, &id.id) != nil {
			rows.Close()
			return 0, unavailable()
		}
		events = append(events, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, unavailable()
	}
	for _, id := range events {
		matched, err := tx.QueryContext(ctx, "SELECT subscription FROM deliveries WHERE source=? AND id=? AND state IN ('pending','claimed')", id.source, id.id)
		if err != nil {
			return 0, unavailable()
		}
		var subs []string
		for matched.Next() {
			var sub string
			if matched.Scan(&sub) != nil {
				matched.Close()
				return 0, unavailable()
			}
			subs = append(subs, sub)
		}
		err = matched.Err()
		matched.Close()
		if err != nil {
			return 0, unavailable()
		}
		if _, err = tx.ExecContext(ctx, "UPDATE deliveries SET state='failed',reason='delivery_expired',worker='',token_hash='',lease=0 WHERE source=? AND id=? AND state IN ('pending','claimed')", id.source, id.id); err != nil {
			return 0, unavailable()
		}
		for _, sub := range subs {
			if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET pending=pending-1 WHERE id=?", sub); err != nil {
				return 0, unavailable()
			}
		}
	}
	if tx.Commit() != nil {
		return 0, unavailable()
	}
	return len(events), nil
}
