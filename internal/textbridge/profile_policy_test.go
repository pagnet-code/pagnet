package textbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const profileTestApproval = "70c33824-e6e8-4880-a6df-894b99914bd0"

func TestProfileFrozenSummarySelection(t *testing.T) {
	for _, selected := range []string{"", profileTestApproval} {
		t.Run(selected, func(t *testing.T) {
			_, dir, p := savedTestProfile(t)
			// Prepare first publication with the selected optional policy.
			if err := os.Remove(filepath.Join(dir, "profile.json")); err != nil {
				t.Fatal(err)
			}
			p.FrozenSummaryApprovalID = selected
			if err := SaveProfile(dir, p); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadProfile(dir, p.Service)
			if err != nil || loaded.FrozenSummaryApprovalID != selected {
				t.Fatalf("selection round trip: %v", err)
			}
			if err := SaveProfile(dir, loaded); err != nil {
				t.Fatal(err)
			}
			for _, replacement := range []string{"", profileTestApproval, "7d43a3e4-bbb9-47c5-a155-49314afec32b"} {
				if replacement == selected {
					continue
				}
				changed := loaded
				changed.FrozenSummaryApprovalID = replacement
				if err := SaveProfile(dir, changed); err == nil {
					t.Fatal("changed published selection")
				}
			}
			raw, err := ReadPrivate(filepath.Join(dir, "profile.json"), 32768)
			if err != nil {
				t.Fatal(err)
			}
			if selected == "" && bytes.Contains(raw, []byte("FrozenSummaryApprovalID")) {
				t.Fatal("legacy profile gained selection field")
			}
			// Generic profiles retain the old JSON shape; selected profiles include
			// an unknown field that strict older decoders must reject.
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			var legacy struct {
				ProjectContract, Role, Service, Server, Credential string
				ProviderOrigin, Model, KeyFile, Fingerprint        string
				Limits                                             ledger.Limits
				Disabled                                           bool
				Registration                                       *ProfileRegistration
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			legacyErr := decoder.Decode(&legacy)
			if (legacyErr != nil) != (selected != "") {
				t.Fatalf("older strict decoder compatibility: %v", legacyErr)
			}
			_, present := fields["FrozenSummaryApprovalID"]
			if present != (selected != "") {
				t.Fatal("unexpected selection encoding")
			}
		})
	}
}

func TestProfileRejectsInvalidFrozenSummarySelection(t *testing.T) {
	for _, change := range []func(*Profile){
		func(p *Profile) { p.FrozenSummaryApprovalID = "invalid" },
		func(p *Profile) { p.Role = "sender" },
		func(p *Profile) { p.ProjectContract = OwnerTextProjectContract },
	} {
		_, dir, p := savedTestProfile(t)
		p.FrozenSummaryApprovalID = profileTestApproval
		change(&p)
		if err := os.Remove(filepath.Join(dir, "profile.json")); err != nil {
			t.Fatal(err)
		}
		if err := SaveProfile(dir, p); err == nil {
			t.Fatal("saved invalid selection")
		}
		if err := SavePrivateJSON(dir, "profile.json", p); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(dir, p.Service); err == nil {
			t.Fatal("loaded invalid selection")
		}
	}
}

func TestDisableProfileWhileRunningFencesStaleMutation(t *testing.T) {
	_, dir, stale := savedTestProfile(t)
	unlock, err := LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx := context.Background()
	if err := DisableProfile(ctx, dir, stale.Service); err != nil {
		t.Fatal(err)
	}
	if err := DisableProfile(ctx, dir, stale.Service); err != nil {
		t.Fatal(err)
	}
	current, err := LoadProfile(dir, stale.Service)
	if err != nil || !current.Disabled {
		t.Fatalf("profile not disabled: %v", err)
	}
	if err := SaveProfile(dir, stale); err == nil {
		t.Fatal("stale save revived disabled profile")
	}
	store, err := OpenProfileLedger(dir, current)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	budget, err := store.BudgetSnapshot(ctx)
	if err != nil || budget.Enabled {
		t.Fatalf("ledger not disabled: %v", err)
	}
	if _, _, err := store.ClaimProvider(ctx, ledger.Job{}, time.Now()); !errors.Is(err, ledger.ErrDisabled) {
		t.Fatalf("provider claim after disable: %v", err)
	}
	current.Credential = "pgn_act_v1_retired"
	if err := SaveProfile(dir, current); err != nil {
		t.Fatal("disabled metadata update:", err)
	}
}

func TestApprovalDisableWaitsForProfilePolicy(t *testing.T) {
	dir, in, now := frozenSummaryFixture(t)
	approval, err := CreateFrozenSummaryApproval(dir, in, now)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := LockProfilePolicy(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := DisableFrozenSummaryApprovalContext(ctx, dir, approval.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("approval disable ignored policy lock: %v", err)
	}
	current, err := LoadFrozenSummaryApproval(dir, approval.ID)
	if err != nil || current.Disabled {
		t.Fatalf("approval mutated without policy lock: %v", err)
	}
	unlock()
	if err := DisableFrozenSummaryApprovalContext(context.Background(), dir, approval.ID); err != nil {
		t.Fatal(err)
	}
}
