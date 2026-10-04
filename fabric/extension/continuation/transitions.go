package continuation

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type row struct {
	snapshot         []byte
	digest           string
	expires          string
	hash             []byte
	revision         int64
	state            State
	receipt, outcome []byte
}

func load(ctx context.Context, tx *sql.Tx, id string) (row, error) {
	var r row
	e := tx.QueryRowContext(ctx, "SELECT snapshot,snapshot_digest,expires,cap_hash,cap_revision,state,receipt,outcome FROM continuations WHERE id=?", id).Scan(&r.snapshot, &r.digest, &r.expires, &r.hash, &r.revision, &r.state, &r.receipt, &r.outcome)
	if errors.Is(e, sql.ErrNoRows) {
		return r, stale()
	}
	if e != nil {
		return r, internal()
	}
	return r, nil
}
func (s *Store) transaction(ctx context.Context) (*sql.Tx, error) {
	if s.closed {
		return nil, internal()
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, internal()
	}
	return tx, nil
}

// Create commits the stable engine deferral identity and immutable snapshot.
// An exact ambiguous retry yields no new secret; recover lost delivery through
// authenticated pending-only RotatePendingCapability, never by executing again.
func (s *Store) Create(ctx context.Context, c fabric.ExecutionContext, v Snapshot, expires time.Time) (Issued, error) {
	if e := s.authenticated(c); e != nil {
		return Issued{}, e
	}
	if c.PrincipalView() != v.OriginalPrincipal {
		return Issued{}, fabric.NewError(fabric.CodeUnauthenticated, "Original principal mismatch")
	}
	if _, e := c.DecodeVerifiedEnvelope(v.OriginalEnvelope, s.scope.Audience); e != nil {
		return Issued{}, e
	}
	if len(v.Pipeline) > s.options.MaxSnapshotBytes || len(v.State) > s.options.MaxSnapshotBytes {
		return Issued{}, invalid("Snapshot exceeds capacity")
	}
	if e := s.validateSnapshot(v); e != nil {
		return Issued{}, e
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > s.options.MaxSnapshotBytes {
		return Issued{}, invalid("Snapshot exceeds capacity")
	}
	expiry := expires.UTC().Format(time.RFC3339Nano)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return Issued{}, e
	}
	defer tx.Rollback()
	prior, e := load(ctx, tx, v.DeferralID)
	if e == nil {
		if string(prior.snapshot) != string(b) || prior.expires != expiry {
			return Issued{}, stale()
		}
		return Issued{ID: v.DeferralID, CapabilityRevision: uint64(prior.revision)}, nil
	}
	var fe *fabric.Error
	if !errors.As(e, &fe) || fe.Code != fabric.CodeStaleContinuation {
		return Issued{}, e
	}
	now := time.Now()
	if expires.IsZero() || !expires.After(now) || expires.Sub(now) > s.options.MaxTTL {
		return Issued{}, invalid("Invalid continuation expiry")
	}
	cap, hash, e := mint(v.DeferralID)
	if e != nil {
		return Issued{}, e
	}
	if e = s.charge(ctx, tx, 1, int64(len(b))); e != nil {
		return Issued{}, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO continuations VALUES(?,?,?,?,?,1,'pending',NULL,NULL)", v.DeferralID, b, digest(b), expiry, hash); e != nil {
		return Issued{}, internal()
	}
	if e = tx.Commit(); e != nil {
		return Issued{}, internal()
	}
	return Issued{ID: v.DeferralID, CapabilityRevision: 1, Created: true, Capability: cap}, nil
}
func (s *Store) RotatePendingCapability(ctx context.Context, c fabric.ExecutionContext, id string, expected uint64) (Issued, error) {
	if e := s.authenticated(c); e != nil {
		return Issued{}, e
	}
	if !hexID(id) || expected == 0 || expected >= math.MaxInt64 {
		return Issued{}, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return Issued{}, e
	}
	defer tx.Rollback()
	r, e := load(ctx, tx, id)
	if e != nil {
		return Issued{}, e
	}
	v, e := s.snapshot(r.snapshot)
	if e != nil {
		return Issued{}, internal()
	}
	expiry, e := time.Parse(time.RFC3339Nano, r.expires)
	if e != nil {
		return Issued{}, internal()
	}
	if !allowed(v, c.PrincipalView()) || r.state != Pending || uint64(r.revision) != expected || !expiry.After(time.Now()) {
		return Issued{}, stale()
	}
	cap, hash, e := mint(id)
	if e != nil {
		return Issued{}, e
	}
	res, e := tx.ExecContext(ctx, "UPDATE continuations SET cap_hash=?,cap_revision=cap_revision+1 WHERE id=? AND state='pending' AND cap_revision=?", hash, id, r.revision)
	if e != nil {
		return Issued{}, internal()
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return Issued{}, stale()
	}
	if e = tx.Commit(); e != nil {
		return Issued{}, internal()
	}
	return Issued{ID: id, CapabilityRevision: expected + 1, Capability: cap}, nil
}
func (s *Store) Claim(ctx context.Context, c fabric.ExecutionContext, token string, claimID string) (ClaimResult, error) {
	if e := s.authenticated(c); e != nil {
		return ClaimResult{}, e
	}
	id, hash, e := parseToken(token)
	if e != nil {
		return ClaimResult{}, e
	}
	if !hexID(claimID) {
		return ClaimResult{}, invalid("Claim identity must be a stable 256-bit identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return ClaimResult{}, e
	}
	defer tx.Rollback()
	r, e := load(ctx, tx, id)
	if e != nil {
		return ClaimResult{}, e
	}
	v, e := s.snapshot(r.snapshot)
	if e != nil {
		return ClaimResult{}, internal()
	}
	if !allowed(v, c.PrincipalView()) || subtle.ConstantTimeCompare(hash, r.hash) != 1 {
		return ClaimResult{}, stale()
	}
	result := ClaimResult{Snapshot: v, State: r.state}
	if r.state != Pending {
		if e = decode(r.receipt, &result.Receipt, 16384); e != nil {
			return ClaimResult{}, internal()
		}
		if result.Receipt.ClaimID != claimID || result.Receipt.Principal != c.PrincipalView() || result.Receipt.Audience != s.scope.Audience {
			return ClaimResult{}, stale()
		}
		if len(r.outcome) > 0 {
			var out Outcome
			if e = decode(r.outcome, &out, s.options.MaxOutcomeBytes); e != nil {
				return ClaimResult{}, internal()
			}
			result.Outcome = &out
		}
		return result, nil
	}
	expiry, e := time.Parse(time.RFC3339Nano, r.expires)
	if e != nil {
		return ClaimResult{}, internal()
	}
	now := time.Now().UTC()
	if !expiry.After(now) {
		return ClaimResult{}, stale()
	}
	receipt := Receipt{ID: id, ClaimID: claimID, Principal: c.PrincipalView(), Audience: s.scope.Audience, SnapshotDigest: r.digest, PlanDigest: v.PlanDigest, CapabilityRevision: uint64(r.revision), ClaimedAt: now}
	b, e := json.Marshal(receipt)
	if e != nil || len(b) > 16384 {
		return ClaimResult{}, internal()
	}
	if e = s.charge(ctx, tx, 0, int64(len(b))); e != nil {
		return ClaimResult{}, e
	}
	res, e := tx.ExecContext(ctx, "UPDATE continuations SET state='claimed',receipt=? WHERE id=? AND state='pending' AND cap_revision=?", b, id, r.revision)
	if e != nil {
		return ClaimResult{}, internal()
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return ClaimResult{}, stale()
	}
	if e = tx.Commit(); e != nil {
		return ClaimResult{}, internal()
	}
	result.State = Claimed
	result.Fresh = true
	result.Receipt = receipt
	return result, nil
}

// Complete settles an already authenticated claim. Expiry prevents new claims,
// not truthful settlement of previously claimed endpoint effects.
func (s *Store) Complete(ctx context.Context, c fabric.ExecutionContext, receipt Receipt, out Outcome) (Outcome, error) {
	if e := s.authenticated(c); e != nil {
		return Outcome{}, e
	}
	if !hexID(receipt.ID) || !hexID(receipt.ClaimID) || !hexID(receipt.PlanDigest) || !hexID(receipt.SnapshotDigest) || receipt.CapabilityRevision == 0 || receipt.ClaimedAt.IsZero() || receipt.Principal != c.PrincipalView() || receipt.Audience != s.scope.Audience {
		return Outcome{}, stale()
	}
	if out.Effect != fabric.EffectUnknown && out.Effect != fabric.EffectNotStarted && out.Effect != fabric.EffectCompleted {
		return Outcome{}, invalid("Invalid effect evidence")
	}
	var data any
	if e := s.decodePrivate(out.Data, &data, s.options.MaxOutcomeBytes); e != nil {
		return Outcome{}, e
	}
	b, e := json.Marshal(out)
	if e != nil || len(b) > s.options.MaxOutcomeBytes {
		return Outcome{}, invalid("Outcome exceeds capacity")
	}
	want, e := json.Marshal(receipt)
	if e != nil {
		return Outcome{}, stale()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.transaction(ctx)
	if e != nil {
		return Outcome{}, e
	}
	defer tx.Rollback()
	r, e := load(ctx, tx, receipt.ID)
	if e != nil {
		return Outcome{}, e
	}
	if r.state == Pending || string(r.receipt) != string(want) {
		return Outcome{}, stale()
	}
	if r.state == Complete {
		if string(r.outcome) != string(b) {
			return Outcome{}, stale()
		}
		return out, nil
	}
	if e = s.charge(ctx, tx, 0, int64(len(b))); e != nil {
		return Outcome{}, e
	}
	res, e := tx.ExecContext(ctx, "UPDATE continuations SET state='complete',outcome=? WHERE id=? AND state='claimed'", b, receipt.ID)
	if e != nil {
		return Outcome{}, internal()
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return Outcome{}, stale()
	}
	if e = tx.Commit(); e != nil {
		return Outcome{}, internal()
	}
	return out, nil
}
