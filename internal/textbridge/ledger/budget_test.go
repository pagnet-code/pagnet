package ledger

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var advanceTokens sync.Map

type advanceKey struct {
	store        *Store
	project, ask string
}

func advance(t *testing.T, s *Store, j Job, next Phase, d Data) Job {
	t.Helper()
	var err error
	key := advanceKey{s, j.ProjectID, j.AskID}
	switch next {
	case ProviderStarted:
		var token string
		j, token, err = s.ClaimProvider(ctx, j, time.Now())
		if err == nil {
			advanceTokens.Store(key, token)
			t.Cleanup(func() { advanceTokens.Delete(key) })
		}
	case OutputReady, Unknown:
		token, ok := advanceTokens.Load(key)
		if !ok {
			t.Fatal("missing provider token")
		}
		output := d.Output
		if len(output) == 0 {
			output = []byte("provider output")
		}
		j, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token.(string), output, next == OutputReady)
	default:
		j, err = s.CompareAndSwap(ctx, j, next, d)
	}
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func openBudget(t *testing.T, limits Limits) (*Store, *Store, string) {
	t.Helper()
	dir := filepath.Join(canonicalTempDir(t), "ledger")
	s, err := Open(dir, binding(), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	other, err := Open(dir, binding(), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	return s, other, dir
}

func budgetJob(t *testing.T, s *Store, ask string) Job {
	t.Helper()
	j, err := s.Insert(ctx, "project", ask, data())
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func requireLimit(t *testing.T, err error) {
	t.Helper()
	var typed *LimitError
	if !errors.Is(err, ErrLimit) || !errors.As(err, &typed) {
		t.Fatalf("want typed limit error, got %v", err)
	}
}

func requireStale(t *testing.T, err error) {
	t.Helper()
	var typed *StaleError
	if !errors.Is(err, ErrStale) || !errors.As(err, &typed) {
		t.Fatalf("want typed stale error, got %v", err)
	}
}

func TestBudgetDistinctJobsAcrossStores(t *testing.T) {
	for _, limits := range []Limits{{CallsPerDay: 1, MaxConcurrent: 10}, {CallsPerDay: 10, MaxConcurrent: 1}} {
		t.Run("limits", func(t *testing.T) {
			s, other, _ := openBudget(t, limits)
			jobs := []Job{budgetJob(t, s, "one"), budgetJob(t, s, "two")}
			stores := []*Store{s, other}
			start := make(chan struct{})
			results := make(chan error, 2)
			for i := range jobs {
				go func(i int) { <-start; _, _, err := stores[i].ClaimProvider(ctx, jobs[i], time.Now()); results <- err }(i)
			}
			close(start)
			successes := 0
			for range jobs {
				if err := <-results; err == nil {
					successes++
				} else {
					requireLimit(t, err)
				}
			}
			if successes != 1 {
				t.Fatalf("successful claims: %d", successes)
			}
		})
	}
}

func TestBudgetSameJobAcrossStores(t *testing.T) {
	s, other, _ := openBudget(t, Limits{CallsPerDay: 1, MaxConcurrent: 1})
	j := insert(t, s)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, store := range []*Store{s, other} {
		go func(s *Store) { <-start; _, _, err := s.ClaimProvider(ctx, j, time.Now()); results <- err }(store)
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else {
			requireStale(t, err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful claims: %d", successes)
	}
}

func TestBudgetLimitsPersistAndValidate(t *testing.T) {
	s, other, dir := openBudget(t, Limits{CallsPerDay: 2, MaxConcurrent: 1})
	s.Close()
	other.Close()
	for _, limits := range []Limits{{CallsPerDay: 3, MaxConcurrent: 1}, {CallsPerDay: 2, MaxConcurrent: 2}, {}, {CallsPerDay: -1, MaxConcurrent: 1}, {CallsPerDay: 1, MaxConcurrent: -1}} {
		if reopened, err := Open(dir, binding(), limits); err == nil {
			reopened.Close()
			t.Fatalf("accepted limits %+v", limits)
		}
	}
	reopened, err := Open(dir, binding(), Limits{CallsPerDay: 2, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestBudgetDayRolloverRetainsActiveAndRejectsRollback(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 1, MaxConcurrent: 1})
	day := time.Date(2026, 10, 25, 23, 0, 0, 0, time.UTC)
	one, token, err := s.ClaimProvider(ctx, budgetJob(t, s, "one"), day)
	if err != nil {
		t.Fatal(err)
	}
	two := budgetJob(t, s, "two")
	if _, _, err = s.ClaimProvider(ctx, two, day.Add(time.Hour)); err == nil {
		t.Fatal("active claim lost on rollover")
	} else {
		requireLimit(t, err)
	}
	if _, err = s.FinishProvider(ctx, one.ProjectID, one.AskID, token, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ClaimProvider(ctx, two, day.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "three"), day); err == nil {
		t.Fatal("day rollback accepted")
	} else {
		requireStale(t, err)
	}
}

func TestBudgetCompletionAndRevocation(t *testing.T) {
	for _, outcome := range []string{"success", "uncertain", "revoked", "wrong token", "empty output"} {
		t.Run(outcome, func(t *testing.T) {
			s, _, _ := openBudget(t, Limits{CallsPerDay: 10, MaxConcurrent: 1})
			j, token, err := s.ClaimProvider(ctx, insert(t, s), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			succeeded, output := true, []byte("output")
			switch outcome {
			case "uncertain":
				succeeded = false
			case "revoked":
				j, err = s.Revoke(ctx, j)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong token":
				token = "wrong"
			case "empty output":
				output = nil
			}
			got, err := s.FinishProvider(ctx, j.ProjectID, j.AskID, token, output, succeeded)
			switch outcome {
			case "success", "revoked":
				if err != nil || got.Phase != OutputReady || string(got.Data.Output) != "output" {
					t.Fatalf("finish: %+v %v", got, err)
				}
			case "uncertain":
				if err != nil || got.Phase != Unknown {
					t.Fatalf("uncertain: %+v %v", got, err)
				}
			case "wrong token":
				requireStale(t, err)
			default:
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("want invalid, got %v", err)
				}
			}
			_, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "next"), time.Now())
			if outcome == "revoked" {
				if !got.Revoked {
					t.Fatal("completion lost revocation")
				}
				if _, err := s.CompareAndSwap(ctx, got, ReplyPreparing, got.Data); !errors.Is(err, ErrInvalid) {
					t.Fatalf("revoked reply preparation: %v", err)
				}
			}
			if outcome == "success" || outcome == "revoked" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireLimit(t, err)
			}
		})
	}
}

func TestBudgetRevokeBeforeClaim(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 1, MaxConcurrent: 1})
	j, err := s.Revoke(ctx, insert(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ClaimProvider(ctx, j, time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "next"), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestBudgetTamperFailsClosed(t *testing.T) {
	for _, stmt := range []string{"UPDATE budget SET id=2", "UPDATE budget SET revision=revision+1", "UPDATE budget SET sealed=x'0001'", "DELETE FROM budget", "DROP TABLE budget"} {
		t.Run(stmt, func(t *testing.T) {
			s, other, dir := openBudget(t, Limits{CallsPerDay: 10, MaxConcurrent: 1})
			j := insert(t, s)
			if _, err := s.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			if _, _, err := other.ClaimProvider(ctx, j, time.Now()); err == nil {
				t.Fatal("claim accepted tampered budget")
			}
			s.Close()
			other.Close()
			if reopened, err := Open(dir, binding(), Limits{CallsPerDay: 10, MaxConcurrent: 1}); err == nil {
				reopened.Close()
				t.Fatal("reopened tampered budget")
			}
		})
	}
}

func TestBudgetGenericCASCannotBypassClaimOrCompletion(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 1, MaxConcurrent: 1})
	j := insert(t, s)
	if _, err := s.CompareAndSwap(ctx, j, ProviderStarted, j.Data); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	j, _, err := s.ClaimProvider(ctx, j, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []Phase{OutputReady, Unknown} {
		d := j.Data
		d.Output = []byte("output")
		if _, err := s.CompareAndSwap(ctx, j, next, d); !errors.Is(err, ErrInvalid) {
			t.Fatalf("generic completion to %s: %v", next, err)
		}
	}
}

func TestBudgetUsageSurvivesReopen(t *testing.T) {
	limits := Limits{CallsPerDay: 2, MaxConcurrent: 1}
	s, other, dir := openBudget(t, limits)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	j, token, err := s.ClaimProvider(ctx, insert(t, s), now)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty claim token")
	}
	s.Close()
	other.Close()
	s, err = Open(dir, binding(), limits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := budgetJob(t, s, "next")
	if _, _, err = s.ClaimProvider(ctx, next, now); err == nil {
		t.Fatal("active reservation lost on reopen")
	} else {
		requireLimit(t, err)
	}
	if _, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
	j, token, err = s.ClaimProvider(ctx, next, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, binding(), limits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "third"), now); err == nil {
		t.Fatal("daily usage lost on reopen")
	} else {
		requireLimit(t, err)
	}
}

func TestBudgetUsesUTCDay(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 1, MaxConcurrent: 1})
	zone := time.FixedZone("east", 2*60*60)
	before := time.Date(2026, 10, 26, 1, 30, 0, 0, zone)
	j, token, err := s.ClaimProvider(ctx, insert(t, s), before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
	next := budgetJob(t, s, "next")
	if _, _, err = s.ClaimProvider(ctx, next, before.Add(15*time.Minute)); err == nil {
		t.Fatal("same UTC day reset budget")
	} else {
		requireLimit(t, err)
	}
	if _, _, err = s.ClaimProvider(ctx, next, before.Add(30*time.Minute)); err != nil {
		t.Fatalf("UTC midnight failed to reset budget: %v", err)
	}
}

func TestBudgetTokenBindsJobAndCannotReplay(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 2, MaxConcurrent: 2})
	one, token, err := s.ClaimProvider(ctx, budgetJob(t, s, "one"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	two, secondToken, err := s.ClaimProvider(ctx, budgetJob(t, s, "two"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.FinishProvider(ctx, two.ProjectID, two.AskID, token, []byte("output"), true); err == nil {
		t.Fatal("wrong job token accepted")
	} else {
		requireStale(t, err)
	}
	if _, err = s.FinishProvider(ctx, one.ProjectID, one.AskID, token, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.FinishProvider(ctx, one.ProjectID, one.AskID, token, []byte("output"), true); err == nil {
		t.Fatal("completed token replay accepted")
	} else {
		requireStale(t, err)
	}
	if _, err = s.FinishProvider(ctx, two.ProjectID, two.AskID, secondToken, []byte("output"), true); err != nil {
		t.Fatal(err)
	}
}
