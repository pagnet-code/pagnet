//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func testScope() Scope {
	return Scope{ServerURL: "https://control.invalid", TenantID: "tenant", AccountID: "account", HostID: "host", InstanceID: "instance", Generation: "generation"}
}
func testJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "worker")
	j, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, dir
}
func lease(t *testing.T, j *Journal) int64 {
	t.Helper()
	n, err := j.AdvanceLease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestJournalHandoffFencesControllerAndNeverRepeatsAdmission(t *testing.T) {
	ctx := context.Background()
	j, _ := testJournal(t)
	a := lease(t, j)
	payload := json.RawMessage(`{"input":"private prompt that must not persist"}`)
	out, run, err := j.Admit(ctx, a, 1, "command-one", "prompt", payload)
	if err != nil || !run || out.State != "admitted" {
		t.Fatalf("first admission: %+v %v %v", out, run, err)
	}
	b := lease(t, j)
	if b <= a {
		t.Fatal("controller lease did not advance")
	}
	if _, _, err = j.Admit(ctx, a, 2, "old-controller", "input", json.RawMessage(`{}`)); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale controller admitted: %v", err)
	}
	out, run, err = j.Admit(ctx, b, 1, "command-one", "prompt", payload)
	if err != nil || run || out.State != "admitted" {
		t.Fatalf("handoff replay repeated effect: %+v %v %v", out, run, err)
	}
	if _, _, err = j.Admit(ctx, b, 1, "command-one", "prompt", json.RawMessage(`{"input":"changed"}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed payload accepted: %v", err)
	}
	if err = j.Settle(ctx, 1, "completed", json.RawMessage(`{"session":"same-native-session"}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.Acknowledge(ctx, a, 1); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale receipt accepted: %v", err)
	}
	if err = j.Acknowledge(ctx, b, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Admit(ctx, b, 1, "command-one", "prompt", payload); !errors.Is(err, ErrRetired) {
		t.Fatalf("pruned intent reused: %v", err)
	}
}

func TestJournalConcurrentRetriesHaveOneNativeEffect(t *testing.T) {
	j, _ := testJournal(t)
	current := lease(t, j)
	var effects atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, run, err := j.Admit(context.Background(), current, 1, "one", "input", json.RawMessage(`{"data":"a"}`))
			if err != nil {
				t.Error(err)
			}
			if run {
				effects.Add(1)
			}
		})
	}
	wg.Wait()
	if effects.Load() != 1 {
		t.Fatalf("native effect admission count=%d", effects.Load())
	}
}

func TestJournalCrashIsUncertainAndOwnerExclusive(t *testing.T) {
	ctx := context.Background()
	j, dir := testJournal(t)
	a := lease(t, j)
	if _, run, err := j.Admit(ctx, a, 1, "uncertain", "approval", json.RawMessage(`{"answer":"proceed_once"}`)); err != nil || !run {
		t.Fatalf("admit: %v %v", run, err)
	}
	if other, err := OpenJournal(dir, testScope()); err == nil {
		_ = other.Close()
		t.Fatal("two workers opened one native owner journal")
	}
	if out, err := j.Outcome(ctx, 1); err != nil || out.State != "admitted" {
		t.Fatalf("failed competing owner modified live work: %+v %v", out, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(dir, testScope())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b := lease(t, reopened)
	if b <= a {
		t.Fatal("lease reset after worker crash")
	}
	out, run, err := reopened.Admit(ctx, b, 1, "uncertain", "approval", json.RawMessage(`{"answer":"proceed_once"}`))
	if err != nil || run || out.State != "uncertain" {
		t.Fatalf("uncertain approval replayed: %+v %v %v", out, run, err)
	}
}

func TestJournalBoundedUnacknowledgedBackpressureAndContiguousRetirement(t *testing.T) {
	ctx := context.Background()
	j, _ := testJournal(t)
	current := lease(t, j)
	for i := int64(1); i <= maxCommands; i++ {
		if _, run, err := j.Admit(ctx, current, i, fmt.Sprint(i), "input", json.RawMessage(`{}`)); err != nil || !run {
			t.Fatalf("admit %d: %v %v", i, run, err)
		}
		if err := j.Settle(ctx, i, "completed", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := j.Admit(ctx, current, maxCommands+1, "full", "input", json.RawMessage(`{}`)); !errors.Is(err, ErrFull) {
		t.Fatalf("unbounded outcomes: %v", err)
	}
	if err := j.Acknowledge(ctx, current, 2); err != nil {
		t.Fatal(err)
	}
	// A receipt for #2 cannot retire the missing receipt for #1.
	if _, run, err := j.Admit(ctx, current, 1, "1", "input", json.RawMessage(`{}`)); err != nil || run {
		t.Fatalf("ack gap lost prior outcome: %v %v", run, err)
	}
	if err := j.Acknowledge(ctx, current, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Admit(ctx, current, 2, "2", "input", json.RawMessage(`{}`)); !errors.Is(err, ErrRetired) {
		t.Fatalf("retirement floor missing: %v", err)
	}
	if _, run, err := j.Admit(ctx, current, maxCommands+1, "now-room", "input", json.RawMessage(`{}`)); err != nil || !run {
		t.Fatalf("backpressure never released: %v %v", run, err)
	}
}

func TestJournalScopePrivacyAndCorruptionRefuseActivation(t *testing.T) {
	_, dir := testJournal(t)
	for _, path := range []string{dir, filepath.Join(dir, "intents.sqlite"), filepath.Join(dir, "worker.lock")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s permissions %o", path, info.Mode().Perm())
		}
	}
	// Different account, instance, or generation can never adopt a journal.
	j, dir2 := testJournal(t)
	_ = j.Close()
	for _, mutate := range []func(*Scope){func(s *Scope) { s.AccountID = "other" }, func(s *Scope) { s.ServerURL = "https://other.invalid" }, func(s *Scope) { s.TenantID = "other" }, func(s *Scope) { s.Generation = "other" }} {
		wrong := testScope()
		mutate(&wrong)
		if other, err := OpenJournal(dir2, wrong); err == nil {
			_ = other.Close()
			t.Fatal("different authority inherited worker")
		}
	}
	if err := os.WriteFile(filepath.Join(dir2, "intents.sqlite"), []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenJournal(dir2, testScope()); err == nil {
		_ = other.Close()
		t.Fatal("corrupt journal accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenJournal(link, testScope()); err == nil {
		_ = other.Close()
		t.Fatal("symlink worker state accepted")
	}
}

func TestJournalNeverPersistsIntentBodyAndRefusesPartialHistory(t *testing.T) {
	ctx := context.Background()
	j, dir := testJournal(t)
	current := lease(t, j)
	body := json.RawMessage(`{"input":"do-not-journal-credentials-or-private-prompts-unique-marker"}`)
	if _, _, err := j.Admit(ctx, current, 1, "private-intent", "prompt", body); err != nil {
		t.Fatal(err)
	}
	var digest string
	if err := j.db.QueryRow(`SELECT digest FROM worker_intent WHERE sequence=1`).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest != intentDigest("prompt", body) {
		t.Fatal("intent did not store an exact digest")
	}
	// SQLite/WAL content must contain the digest rather than the prompt.
	for _, name := range []string{"intents.sqlite", "intents.sqlite-wal"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("do-not-journal-credentials-or-private-prompts-unique-marker")) {
			t.Fatal("private intent body persisted")
		}
	}
	if _, err := j.db.Exec(`DELETE FROM worker_intent WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if reopened, err := OpenJournal(dir, testScope()); err == nil {
		_ = reopened.Close()
		t.Fatal("lost durable intent was silently treated as replay-safe history")
	}
}
