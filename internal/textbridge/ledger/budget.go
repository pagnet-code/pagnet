package ledger

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Limits are owner-approved provider allowances. They cannot change on reopen.
type Limits struct {
	CallsPerDay   int64
	MaxConcurrent int64
}

func (l Limits) valid() bool { return l.CallsPerDay > 0 && l.MaxConcurrent > 0 }

var ErrLimit = errors.New("text bridge provider budget exhausted")

// LimitError identifies the allowance that prevented a provider claim.
type LimitError struct{ Limit string }

func (e *LimitError) Error() string { return ErrLimit.Error() + ": " + e.Limit }
func (e *LimitError) Unwrap() error { return ErrLimit }

// StaleError identifies a stale job, claim token, or UTC clock observation.
type StaleError struct{ Reason string }

func (e *StaleError) Error() string { return ErrStale.Error() + ": " + e.Reason }
func (e *StaleError) Unwrap() error { return ErrStale }

type providerClaim struct{ ProjectID, AskID string }
type budgetState struct {
	Limits Limits
	Day    string
	Calls  int64
	Active map[string]providerClaim
}
type budgetAAD struct {
	Domain   string
	Binding  Binding
	Revision int64
}

func (s *Store) budgetAAD(revision int64) []byte {
	b, _ := json.Marshal(budgetAAD{"text-bridge-provider-budget-v1", s.binding, revision})
	return b
}
func (s *Store) encodeBudget(revision int64, b budgetState) ([]byte, error) {
	p, e := json.Marshal(b)
	if e != nil {
		return nil, e
	}
	return s.seal(p, s.budgetAAD(revision))
}

type budgetReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) readBudget(ctx context.Context, q budgetReader) (int64, budgetState, error) {
	var revision int64
	var sealed []byte
	var b budgetState
	if e := q.QueryRowContext(ctx, "SELECT revision,sealed FROM budget WHERE id=1").Scan(&revision, &sealed); e != nil {
		return 0, b, e
	}
	p, e := s.unseal(sealed, s.budgetAAD(revision))
	if e != nil {
		return 0, b, e
	}
	if e = json.Unmarshal(p, &b); e != nil {
		return 0, b, e
	}
	if revision < 1 || b.Limits != s.limits || !b.Limits.valid() || b.Calls < 0 || b.Calls > b.Limits.CallsPerDay || b.Active == nil || int64(len(b.Active)) > b.Limits.MaxConcurrent {
		return 0, b, ErrInvalid
	}
	if b.Day == "" {
		if b.Calls != 0 || len(b.Active) != 0 {
			return 0, b, ErrInvalid
		}
	} else if day, e := time.Parse("2006-01-02", b.Day); e != nil || day.Format("2006-01-02") != b.Day {
		return 0, b, ErrInvalid
	}
	seen := make(map[providerClaim]bool)
	for token, claim := range b.Active {
		raw, e := hex.DecodeString(token)
		if e != nil || len(raw) != 32 || claim.ProjectID == "" || claim.AskID == "" || seen[claim] {
			return 0, b, ErrInvalid
		}
		seen[claim] = true
	}
	return revision, b, nil
}

// immediate pins the connection so every operation belongs to the same SQLite
// write transaction. BEGIN IMMEDIATE serializes claims across independent stores.
func (s *Store) immediate(ctx context.Context, f func(*sql.Conn) error) error {
	c, e := s.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return e
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	if e = f(c); e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	return e
}
func (s *Store) writeBudget(ctx context.Context, c *sql.Conn, revision int64, b budgetState) error {
	sealed, e := s.encodeBudget(revision+1, b)
	if e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "UPDATE budget SET revision=?,sealed=? WHERE id=1", revision+1, sealed)
	return e
}
func (s *Store) writeProviderJob(ctx context.Context, c *sql.Conn, j Job) error {
	sealed, e := s.encode(j)
	if e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "UPDATE jobs SET revision=?,phase=?,revoked=?,sealed=? WHERE project_id=? AND ask_id=?", j.Revision, j.Phase, j.Revoked, sealed, j.ProjectID, j.AskID)
	return e
}

// ClaimProvider durably reserves both allowances before a provider call may be
// attempted. The opaque token must accompany completion. Time is observed in UTC;
// a day earlier than the durable high-water day is rejected without resetting it.
// Only a nil error authorizes dispatch. Any error, including an uncertain commit
// response, returns no token and must be handled through job recovery.
func (s *Store) ClaimProvider(ctx context.Context, expected Job, now time.Time) (Job, string, error) {
	var result Job
	var token string
	e := s.immediate(ctx, func(c *sql.Conn) error {
		revision, b, e := s.readBudget(ctx, c)
		if e != nil {
			return e
		}
		j, e := s.scan(c.QueryRowContext(ctx, "SELECT "+columns+" FROM jobs WHERE project_id=? AND ask_id=?", expected.ProjectID, expected.AskID))
		if e != nil {
			return e
		}
		if j.Revision != expected.Revision || j.Phase != expected.Phase || j.Revoked != expected.Revoked {
			return &StaleError{"job revision"}
		}
		if j.Phase != Queued || j.Revoked {
			return ErrInvalid
		}
		day := now.UTC().Format("2006-01-02")
		if _, e = time.Parse("2006-01-02", day); e != nil {
			return ErrInvalid
		}
		if day < b.Day {
			return &StaleError{"UTC day rollback"}
		}
		if day > b.Day {
			b.Day = day
			b.Calls = 0
		}
		if b.Calls >= b.Limits.CallsPerDay {
			return &LimitError{"calls per UTC day"}
		}
		if int64(len(b.Active)) >= b.Limits.MaxConcurrent {
			return &LimitError{"concurrent calls"}
		}
		raw := make([]byte, 32)
		if _, e = rand.Read(raw); e != nil {
			return e
		}
		token = hex.EncodeToString(raw)
		if _, exists := b.Active[token]; exists {
			return ErrInvalid
		}
		b.Active[token] = providerClaim{j.ProjectID, j.AskID}
		b.Calls++
		j.Revision++
		j.Phase = ProviderStarted
		if e = s.writeProviderJob(ctx, c, j); e != nil {
			return e
		}
		if e = s.writeBudget(ctx, c, revision, b); e != nil {
			return e
		}
		result = j
		return nil
	})
	if e != nil {
		return Job{}, "", e
	}
	return result, token, nil
}

// FinishProvider commits successful validated output and releases its active
// slot. An error or ambiguous result is terminal Unknown and retains the slot:
// neither process failure nor uncertainty refunds a possibly attempted call.
// Completion reads the current job so revocation wins even when it raced the call.
func (s *Store) FinishProvider(ctx context.Context, projectID, askID, token string, output []byte, succeeded bool) (Job, error) {
	var result Job
	e := s.immediate(ctx, func(c *sql.Conn) error {
		revision, b, e := s.readBudget(ctx, c)
		if e != nil {
			return e
		}
		claim, ok := b.Active[token]
		if !ok || claim.ProjectID != projectID || claim.AskID != askID {
			return &StaleError{"claim token"}
		}
		j, e := s.scan(c.QueryRowContext(ctx, "SELECT "+columns+" FROM jobs WHERE project_id=? AND ask_id=?", projectID, askID))
		if e != nil {
			return e
		}
		if j.Phase != ProviderStarted {
			return &StaleError{"provider already finished"}
		}
		j.Revision++
		j.Phase = Unknown
		if succeeded {
			if len(output) == 0 {
				return ErrInvalid
			}
			j.Phase = OutputReady
			j.Data.Output = append([]byte(nil), output...)
			delete(b.Active, token)
		}
		if e = s.writeProviderJob(ctx, c, j); e != nil {
			return e
		}
		if e = s.writeBudget(ctx, c, revision, b); e != nil {
			return e
		}
		result = j
		return nil
	})
	if e != nil {
		return Job{}, e
	}
	return result, nil
}
