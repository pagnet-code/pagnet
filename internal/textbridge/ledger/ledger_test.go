package ledger

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var ctx = context.Background()

func binding() Binding { return Binding{"https://EXAMPLE.com:443/", "principal"} }
func data() Data {
	return Data{Header: []byte(`{"kind":"ASK"}`), WireDigest: strings.Repeat("a", 64), Input: []byte("private input"), ProviderConfigFingerprint: "config-sha256"}
}
func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	s, e := Open(dir, binding())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func insert(t *testing.T, s *Store) Job {
	t.Helper()
	j, e := s.Insert(ctx, "project", "ask", data())
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func TestPermissionsBindingAndPersistence(t *testing.T) {
	s, dir := openTest(t)
	j := insert(t, s)
	for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "key"): 0600, filepath.Join(dir, "ledger.sqlite"): 0600} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != want {
			t.Fatalf("permissions %s: %v %v", path, info, e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	normalized := binding()
	normalized.ServiceOrigin = "https://example.com"
	s, e := Open(dir, normalized)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Get(ctx, j.ProjectID, j.AskID)
	if e != nil || string(got.Data.Input) != "private input" || got.Revision != 1 {
		t.Fatalf("restart: %+v %v", got, e)
	}
	for _, b := range []Binding{{"https://other.example", "principal"}, {"https://example.com", "other"}} {
		if other, e := Open(dir, b); e == nil {
			other.Close()
			t.Fatal("binding mismatch accepted")
		}
	}
	raw, e := os.ReadFile(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "private input") || strings.Contains(string(raw), "principal") {
		t.Fatal("plaintext leaked")
	}
}
func TestIdempotenceConflictAndTerminalRetention(t *testing.T) {
	s, _ := openTest(t)
	j := insert(t, s)
	again, e := s.Insert(ctx, j.ProjectID, j.AskID, data())
	if e != nil || again.Revision != j.Revision {
		t.Fatal(again, e)
	}
	conflicting := data()
	conflicting.WireDigest = strings.Repeat("b", 64)
	if _, e = s.Insert(ctx, j.ProjectID, j.AskID, conflicting); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	for _, phase := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted} {
		j, e = s.CompareAndSwap(ctx, j, phase, j.Data)
		if e != nil {
			t.Fatal(e)
		}
	}
	again, e = s.Insert(ctx, j.ProjectID, j.AskID, data())
	if e != nil || again.Phase != Admitted {
		t.Fatal(again, e)
	}
	rows, e := s.List(ctx, Admitted)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if _, e = s.CompareAndSwap(ctx, j, Queued, j.Data); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
func TestCASAcrossStoresAndRevocation(t *testing.T) {
	s, dir := openTest(t)
	j := insert(t, s)
	other, e := Open(dir, binding())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*Store{s, other} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			_, e := s.CompareAndSwap(ctx, j, ProviderStarted, j.Data)
			results <- e
		}(store)
	}
	wg.Wait()
	close(results)
	successes, stales := 0, 0
	for e := range results {
		switch {
		case e == nil:
			successes++
		case errors.Is(e, ErrStale):
			stales++
		default:
			t.Fatal(e)
		}
	}
	if successes != 1 || stales != 1 {
		t.Fatal(successes, stales)
	}
	j, e = s.Get(ctx, "project", "ask")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompareAndSwap(ctx, j, Queued, j.Data); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	j, e = s.Revoke(ctx, j)
	if e != nil || !j.Revoked {
		t.Fatal(j, e)
	}
	if _, e = s.CompareAndSwap(ctx, j, OutputReady, j.Data); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = other.Revoke(ctx, Job{ProjectID: "project", AskID: "ask", Revision: 1, Phase: Queued, Data: data()}); !errors.Is(e, ErrStale) {
		t.Fatal(e)
	}
}
func TestUncertaintyAndImmutableInput(t *testing.T) {
	s, _ := openTest(t)
	j := insert(t, s)
	d := data()
	d.Input = []byte("changed")
	if _, e := s.CompareAndSwap(ctx, j, ProviderStarted, d); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	j, e := s.CompareAndSwap(ctx, j, ProviderStarted, j.Data)
	if e != nil {
		t.Fatal(e)
	}
	j, e = s.CompareAndSwap(ctx, j, Unknown, j.Data)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompareAndSwap(ctx, j, Queued, j.Data); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
func TestTamperFailsClosed(t *testing.T) {
	for _, stmt := range []string{"UPDATE jobs SET phase='output_ready'", "UPDATE jobs SET revision=8", "UPDATE jobs SET revoked=1", "UPDATE jobs SET project_id='other'", "UPDATE jobs SET ask_id='other'", "UPDATE jobs SET sealed=x'0001'", "UPDATE binding SET sealed=x'0001'", "DELETE FROM binding"} {
		t.Run(stmt, func(t *testing.T) {
			s, dir := openTest(t)
			insert(t, s)
			if _, e := s.db.Exec(stmt); e != nil {
				t.Fatal(e)
			}
			s.Close()
			if reopened, e := Open(dir, binding()); e == nil {
				reopened.Close()
				t.Fatal("tampered database accepted")
			}
		})
	}
}
func TestMissingKeyAndCorruption(t *testing.T) {
	for _, kind := range []string{"missing key", "corrupt key", "corrupt database"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := openTest(t)
			insert(t, s)
			s.Close()
			var e error
			switch kind {
			case "missing key":
				e = os.Remove(filepath.Join(dir, "key"))
			case "corrupt key":
				e = os.WriteFile(filepath.Join(dir, "key"), make([]byte, 32), 0600)
			case "corrupt database":
				e = os.WriteFile(filepath.Join(dir, "ledger.sqlite"), []byte("not sqlite"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			if reopened, e := Open(dir, binding()); e == nil {
				reopened.Close()
				t.Fatal("corruption accepted")
			}
		})
	}
}
func TestPragmasAndMissingJob(t *testing.T) {
	s, _ := openTest(t)
	var mode string
	var sync int
	if e := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); e != nil || mode != "delete" {
		t.Fatal(mode, e)
	}
	if e := s.db.QueryRow("PRAGMA synchronous").Scan(&sync); e != nil || sync != 3 {
		t.Fatal(sync, e)
	}
	if _, e := s.Get(ctx, "none", "none"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal(e)
	}
}
