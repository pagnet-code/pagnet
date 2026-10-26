package ledger

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBudgetSnapshotRedactsAndAuthenticates(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 3, MaxConcurrent: 2})
	initial, err := s.BudgetSnapshot(ctx)
	if err != nil || !initial.Enabled || initial.Used != 0 || initial.HighWaterDay != "" || len(initial.Active) != 0 {
		t.Fatalf("initial snapshot: %+v %v", initial, err)
	}
	now := time.Now()
	j, token, err := s.ClaimProvider(ctx, budgetJob(t, s, "one"), now)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.BudgetSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Limits != s.limits || status.Used != 1 || status.HighWaterDay != now.UTC().Format("2006-01-02") || status.CurrentUTCDay != time.Now().UTC().Format("2006-01-02") || !reflect.DeepEqual(status.Active, []ProviderClaim{{j.ProjectID, j.AskID}}) {
		t.Fatalf("snapshot: %+v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{token, "Header", "Input", "Output", "PredecessorWire", "ProviderConfigFingerprint"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("snapshot exposes %s", forbidden)
		}
	}
	if _, err = s.db.Exec("UPDATE budget SET revision=revision+1"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BudgetSnapshot(ctx); err == nil {
		t.Fatal("snapshot accepted unauthenticated budget")
	}
}

func TestBudgetSnapshotRetainsHighWaterDay(t *testing.T) {
	s, _, _ := openBudget(t, Limits{CallsPerDay: 3, MaxConcurrent: 2})
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	if _, _, err := s.ClaimProvider(ctx, budgetJob(t, s, "one"), yesterday); err != nil {
		t.Fatal(err)
	}
	status, err := s.BudgetSnapshot(ctx)
	if err != nil || status.Used != 0 || status.HighWaterDay != yesterday.Format("2006-01-02") || len(status.Active) != 1 {
		t.Fatalf("snapshot: %+v %v", status, err)
	}
}

func TestDisableSerializesClaimsAcrossStores(t *testing.T) {
	for i := 0; i < 20; i++ {
		s, other, _ := openBudget(t, Limits{CallsPerDay: 100, MaxConcurrent: 100})
		j := budgetJob(t, s, "racing")
		start := make(chan struct{})
		claimResult := make(chan error, 1)
		disableResult := make(chan error, 1)
		go func() { <-start; _, _, err := other.ClaimProvider(ctx, j, time.Now()); claimResult <- err }()
		go func() { <-start; disableResult <- s.SetEnabled(ctx, false) }()
		close(start)
		if err := <-disableResult; err != nil {
			t.Fatal(err)
		}
		if err := <-claimResult; err != nil && !errors.Is(err, ErrDisabled) {
			t.Fatal(err)
		}
		for _, store := range []*Store{s, other} {
			if _, token, err := store.ClaimProvider(ctx, budgetJob(t, s, "after"), time.Now()); !errors.Is(err, ErrDisabled) || token != "" {
				t.Fatalf("post-disable claim: token present=%t error=%v", token != "", err)
			}
		}
		s.Close()
		other.Close()
	}
}

func TestAbandonProviderClaim(t *testing.T) {
	for _, phase := range []Phase{ProviderStarted, Unknown} {
		t.Run(string(phase), func(t *testing.T) {
			limits := Limits{CallsPerDay: 2, MaxConcurrent: 1}
			s, other, dir := openBudget(t, limits)
			j, token, err := s.ClaimProvider(ctx, insert(t, s), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if phase == Unknown {
				j, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token, nil, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.AbandonProviderClaim(ctx, j.ProjectID, j.AskID, j.Revision); !errors.Is(err, ErrInvalid) {
				t.Fatalf("enabled abandon: %v", err)
			}
			if err = s.SetEnabled(ctx, false); err != nil {
				t.Fatal(err)
			}
			if _, err = other.AbandonProviderClaim(ctx, j.ProjectID, j.AskID, j.Revision-1); err == nil {
				t.Fatal("stale revision accepted")
			} else {
				requireStale(t, err)
			}
			abandoned, err := other.AbandonProviderClaim(ctx, j.ProjectID, j.AskID, j.Revision)
			if err != nil || abandoned.Phase != Unknown || !reflect.DeepEqual(abandoned.Data, j.Data) {
				t.Fatalf("abandon: %+v %v", abandoned, err)
			}
			if phase == Unknown && !reflect.DeepEqual(abandoned, j) {
				t.Fatal("existing Unknown changed")
			}
			if _, err = s.FinishProvider(ctx, j.ProjectID, j.AskID, token, []byte("late output"), true); err == nil {
				t.Fatal("abandoned token accepted")
			} else {
				requireStale(t, err)
			}
			if _, err = s.AbandonProviderClaim(ctx, abandoned.ProjectID, abandoned.AskID, abandoned.Revision); err == nil {
				t.Fatal("abandon without active claim accepted")
			}
			s.Close()
			other.Close()
			s, err = Open(dir, binding(), limits)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			status, err := s.BudgetSnapshot(ctx)
			if err != nil || status.Enabled || status.Used != 1 || len(status.Active) != 0 {
				t.Fatalf("persisted snapshot: %+v %v", status, err)
			}
			replayed, err := s.Insert(ctx, j.ProjectID, j.AskID, j.Data)
			if err != nil || !reflect.DeepEqual(replayed, abandoned) {
				t.Fatalf("tombstone: %+v %v", replayed, err)
			}
			if err = s.SetEnabled(ctx, true); err != nil {
				t.Fatal(err)
			}
			if _, _, err = s.ClaimProvider(ctx, replayed, time.Now()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("replay: %v", err)
			}
			if _, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "next"), time.Now()); err != nil {
				t.Fatalf("released active slot: %v", err)
			}
			if _, _, err = s.ClaimProvider(ctx, budgetJob(t, s, "over-budget"), time.Now()); err == nil {
				t.Fatal("daily charge refunded")
			} else {
				requireLimit(t, err)
			}
		})
	}
}
