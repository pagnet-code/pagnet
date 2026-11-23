package textbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
)

const frozenTestProject = "10000000-0000-4000-8000-000000000001"
const frozenTestOtherProject = "20000000-0000-4000-8000-000000000001"

func frozenSummaryFixture(t *testing.T) (string, FrozenSummaryInput, time.Time) {
	t.Helper()
	_, dir, p := savedTestProfile(t)
	file := filepath.Join(dir, "owner-summary.txt")
	if err := os.WriteFile(file, []byte("Historical summary supplied by the owner."), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	return dir, FrozenSummaryInput{Profile: p, ProjectIDs: []string{frozenTestProject}, InstructionFile: file, CallsPerDay: p.Limits.CallsPerDay, ExpiresAt: now.Add(time.Hour), HistoricalSourceLabel: "Historical source: example"}, now
}

func TestFrozenSummaryCapturesPrivateImmutableApproval(t *testing.T) {
	dir, in, now := frozenSummaryFixture(t)
	in.ProjectIDs = []string{frozenTestOtherProject, frozenTestProject}
	a, err := CreateFrozenSummaryApproval(dir, in, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.InstructionFile, []byte("Changed after approval"), 0600); err != nil {
		t.Fatal(err)
	}
	// The source can disappear entirely without affecting approved requests.
	if err := os.Remove(in.InstructionFile); err != nil {
		t.Fatal(err)
	}
	in.ProjectIDs[0] = "mutated caller slice"
	a.ProjectIDs[0] = "mutated returned slice"
	plan, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.approval.Instructions != "Historical summary supplied by the owner." {
		t.Fatal("source was not frozen")
	}
	if !plan.AllowsProject(frozenTestProject) || !plan.AllowsProject(frozenTestOtherProject) || plan.AllowsProject(strings.ToUpper(frozenTestProject)+" ") || plan.AllowsProject("unknown") {
		t.Fatal("project allowlist is not exact")
	}
	if plan.Limits() != (ledger.Limits{CallsPerDay: in.CallsPerDay, MaxConcurrent: 1}) {
		t.Fatal("limits changed")
	}
	again, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now.Add(time.Minute))
	if err != nil || again.Fingerprint() != plan.Fingerprint() {
		t.Fatal("dispatch fingerprint was unstable")
	}
	if _, err := plan.newProvider(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "frozen-summaries", a.ID+".json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("approval was not private")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), in.InstructionFile) || strings.Contains(string(raw), "provider-secret") {
		t.Fatal("approval persisted a source path or provider key")
	}
}

func TestFrozenSummaryRejectsInvalidOwnerInput(t *testing.T) {
	cases := []struct {
		name   string
		change func(*FrozenSummaryInput)
		raw    []byte
	}{
		{name: "empty projects", change: func(in *FrozenSummaryInput) { in.ProjectIDs = nil }},
		{name: "malformed project", change: func(in *FrozenSummaryInput) { in.ProjectIDs = []string{"../project"} }},
		{name: "nil project", change: func(in *FrozenSummaryInput) { in.ProjectIDs = []string{"00000000-0000-0000-0000-000000000000"} }},
		{name: "duplicate projects", change: func(in *FrozenSummaryInput) { in.ProjectIDs = []string{frozenTestProject, frozenTestProject} }},
		{name: "too many projects", change: func(in *FrozenSummaryInput) { in.ProjectIDs = make([]string, maxFrozenSummaryProjects+1) }},
		{name: "invalid UTF-8", raw: []byte{0xff}},
		{name: "empty instructions", raw: []byte(" \n")},
		{name: "oversized bytes", raw: []byte(strings.Repeat("x", MaxFrozenSummaryBytes+1))},
		{name: "oversized runes", raw: []byte(strings.Repeat("x", provider.MaxInputChars+1))},
		{name: "expired", change: func(in *FrozenSummaryInput) { in.ExpiresAt = time.Time{} }},
		{name: "bad label", change: func(in *FrozenSummaryInput) { in.HistoricalSourceLabel = "source\nagent" }},
		{name: "wrong project contract", change: func(in *FrozenSummaryInput) { in.Profile.ProjectContract = OwnerTextProjectContract }},
		{name: "different allowance", change: func(in *FrozenSummaryInput) { in.CallsPerDay++ }},
		{name: "provider fingerprint", change: func(in *FrozenSummaryInput) { in.Profile.Fingerprint = "changed" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, in, now := frozenSummaryFixture(t)
			if tc.change != nil {
				tc.change(&in)
			}
			if tc.raw != nil {
				if err := os.WriteFile(in.InstructionFile, tc.raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CreateFrozenSummaryApproval(dir, in, now); err == nil {
				t.Fatal("accepted invalid approval")
			}
		})
	}
}

func TestFrozenSummaryRejectsConfigChanges(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Profile)
	}{
		{"server", func(p *Profile) { p.Server = "https://other.example" }},
		{"service", func(p *Profile) { p.Service = frozenTestOtherProject }},
		{"origin", func(p *Profile) { p.ProviderOrigin = "https://other.example" }},
		{"model", func(p *Profile) { p.Model = "different" }},
		{"key file", func(p *Profile) { p.KeyFile = filepath.Join(filepath.Dir(p.KeyFile), "other-key") }},
		{"fingerprint", func(p *Profile) { p.Fingerprint = "changed" }},
		{"allowance", func(p *Profile) { p.Limits.CallsPerDay++ }},
		{"concurrency", func(p *Profile) { p.Limits.MaxConcurrent++ }},
		{"disabled", func(p *Profile) { p.Disabled = true }},
		{"sender", func(p *Profile) { p.Role = "sender" }},
		{"contract", func(p *Profile) { p.ProjectContract = OwnerTextProjectContract }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, in, now := frozenSummaryFixture(t)
			a, err := CreateFrozenSummaryApproval(dir, in, now)
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&in.Profile)
			if _, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now); err == nil {
				t.Fatal("accepted changed policy")
			}
		})
	}
	t.Run("rotated key", func(t *testing.T) {
		dir, in, now := frozenSummaryFixture(t)
		a, err := CreateFrozenSummaryApproval(dir, in, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(in.Profile.KeyFile, []byte("rotated-secret"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now); err == nil {
			t.Fatal("accepted rotated key")
		}
	})
}

func TestFrozenSummaryDisableExpiryAndNewApproval(t *testing.T) {
	dir, in, now := frozenSummaryFixture(t)
	a, err := CreateFrozenSummaryApproval(dir, in, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-time.Second), in.ExpiresAt, in.ExpiresAt.Add(time.Second)} {
		if _, err := ResolveFrozenSummary(dir, a.ID, in.Profile, at); err == nil {
			t.Fatal("accepted inactive time")
		}
	}
	if err := DisableFrozenSummaryApproval(dir, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := DisableFrozenSummaryApproval(dir, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now); err == nil {
		t.Fatal("accepted disabled approval")
	}
	disabled, err := LoadFrozenSummaryApproval(dir, a.ID)
	if err != nil || !disabled.Disabled {
		t.Fatal("disable was not durable")
	}
	b, err := CreateFrozenSummaryApproval(dir, in, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ResolveFrozenSummary(dir, b.ID, in.Profile, now)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == a.ID || next.Fingerprint() == plan.Fingerprint() {
		t.Fatal("new approval reused authority")
	}
}

func TestFrozenSummaryRejectsMalformedStorage(t *testing.T) {
	for _, kind := range []string{"unknown field", "trailing JSON", "wrong ID", "content digest", "version"} {
		t.Run(kind, func(t *testing.T) {
			dir, in, now := frozenSummaryFixture(t)
			a, err := CreateFrozenSummaryApproval(dir, in, now)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "frozen-summaries", a.ID+".json")
			switch kind {
			case "unknown field":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte(`{"Unknown":true,`), raw[1:]...)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "trailing JSON":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("{}")
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			default:
				if kind == "wrong ID" {
					a.ID = frozenTestOtherProject
				}
				if kind == "content digest" {
					a.Instructions = "tampered"
				}
				if kind == "version" {
					a.Version = "other"
				}
				if err := SavePrivateJSON(filepath.Dir(path), filepath.Base(path), a); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadFrozenSummaryApproval(dir, filepath.Base(path[:len(path)-len(".json")])); err == nil {
				t.Fatal("accepted malformed storage")
			}
		})
	}
}

func TestFrozenSummaryFingerprintBindsSavedSemantics(t *testing.T) {
	cases := []struct {
		name   string
		change func(*FrozenSummaryApproval, *Profile)
	}{
		{"instructions", func(a *FrozenSummaryApproval, _ *Profile) {
			a.Instructions = "A different approved summary."
			a.ContentDigest = frozenSummaryDigest([]byte(a.Instructions))
		}},
		{"projects", func(a *FrozenSummaryApproval, _ *Profile) {
			a.ProjectIDs = append(a.ProjectIDs, frozenTestOtherProject)
		}},
		{"label", func(a *FrozenSummaryApproval, _ *Profile) { a.HistoricalSourceLabel = "Another historical source" }},
		{"expiry", func(a *FrozenSummaryApproval, _ *Profile) { a.ExpiresAt = a.ExpiresAt.Add(time.Minute) }},
		{"allowance", func(a *FrozenSummaryApproval, p *Profile) { a.CallsPerDay++; p.Limits.CallsPerDay++ }},
		{"model", func(a *FrozenSummaryApproval, p *Profile) {
			a.Model = "new-model"
			p.Model = a.Model
			config := provider.Config{BaseURL: a.ProviderOrigin, Model: a.Model, APIKey: "provider-secret"}
			a.ProviderFingerprint = ProviderFingerprint(config)
			p.Fingerprint = a.ProviderFingerprint
		}},
		{"key", func(a *FrozenSummaryApproval, p *Profile) {
			if err := os.WriteFile(p.KeyFile, []byte("new-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			a.KeyFingerprint = frozenSummaryDigest([]byte("new-secret"))
			a.ProviderFingerprint = ProviderFingerprint(provider.Config{BaseURL: a.ProviderOrigin, Model: a.Model, APIKey: "new-secret"})
			p.Fingerprint = a.ProviderFingerprint
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, in, now := frozenSummaryFixture(t)
			a, err := CreateFrozenSummaryApproval(dir, in, now)
			if err != nil {
				t.Fatal(err)
			}
			before, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now)
			if err != nil {
				t.Fatal(err)
			}
			// Direct disk edits bypass the API's immutable-ID rule. Even if the private
			// state is changed this way, previously queued work must not match it.
			tc.change(&a, &in.Profile)
			if err := SavePrivateJSON(filepath.Join(dir, "frozen-summaries"), a.ID+".json", a); err != nil {
				t.Fatal(err)
			}
			after, err := ResolveFrozenSummary(dir, a.ID, in.Profile, now)
			if err != nil {
				t.Fatal(err)
			}
			if before.Fingerprint() == after.Fingerprint() {
				t.Fatal("changed semantics retained dispatch fingerprint")
			}
		})
	}
}
