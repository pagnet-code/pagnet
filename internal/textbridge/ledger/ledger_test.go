package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func binding() Binding { return Binding{"https://EXAMPLE.com:443/", "principal"} }
func data() Data {
	wire := []byte("original ASK wire\n")
	digest := sha256.Sum256(wire)
	return Data{Header: []byte(`{"kind":"ASK"}`), PredecessorWire: wire, WireDigest: hex.EncodeToString(digest[:]), Input: []byte("private input"), ProviderConfigFingerprint: "config-sha256"}
}
func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	s, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
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
	s, e := Open(dir, normalized, Limits{CallsPerDay: 100, MaxConcurrent: 100})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.Get(ctx, j.ProjectID, j.AskID)
	if e != nil || string(got.Data.Input) != "private input" || got.Revision != 1 {
		t.Fatalf("restart: %+v %v", got, e)
	}
	for _, b := range []Binding{{"https://other.example", "principal"}, {"https://example.com", "other"}} {
		if other, e := Open(dir, b, Limits{CallsPerDay: 100, MaxConcurrent: 100}); e == nil {
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
func TestNestedPrivateDirectoryCreation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "private", "nested", "ledger")
	s, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
	if e != nil {
		t.Fatal(e)
	}
	insert(t, s)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	for path := dir; path != root; path = filepath.Dir(path) {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("permissions %s: %v %v", path, info, e)
		}
	}
	s, e = Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Get(ctx, "project", "ask"); e != nil {
		t.Fatal(e)
	}
}
func TestDirectorySyncRetryIncludesExistingAncestors(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "private")
	dir := filepath.Join(first, "nested", "ledger")
	interrupted := errors.New("interrupted after mkdir before parent sync")
	err := makePrivateDir(dir, func(path string) error {
		if path == root {
			return interrupted
		}
		return syncDir(path)
	})
	if !errors.Is(err, interrupted) {
		t.Fatal(err)
	}
	if info, err := os.Stat(first); err != nil || !info.IsDir() {
		t.Fatalf("interruption must leave the unsynced directory: %v %v", info, err)
	}
	// Retry once to finish creation, then again with every directory already
	// present. Both retries must sync every parent through the filesystem root.
	for attempt := 0; attempt < 2; attempt++ {
		synced := make(map[string]bool)
		if err := makePrivateDir(dir, func(path string) error {
			synced[path] = true
			return syncDir(path)
		}); err != nil {
			t.Fatal(err)
		}
		for path := filepath.Dir(dir); ; path = filepath.Dir(path) {
			if !synced[path] {
				t.Fatalf("retry %d skipped existing ancestor %s", attempt, path)
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}
	s, err := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	insert(t, s)
}
func TestRejectSymlinkDirectory(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "link")
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
			if nested {
				dir = filepath.Join(dir, "ledger")
			}
			if s, err := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); err == nil {
				s.Close()
				t.Fatal("symlink ledger path accepted")
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatalf("symlink target changed: %v %v", entries, err)
			}
		})
	}
}
func TestMissingDatabaseAfterTerminalJobFailsClosed(t *testing.T) {
	s, dir := openTest(t)
	j := insert(t, s)
	for _, phase := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted} {
		j = advance(t, s, j, phase, j.Data)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "ledger.sqlite")
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if reopened, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); e == nil {
		reopened.Close()
		t.Fatal("lost terminal job history accepted; duplicate ASK could run again")
	}
	if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("missing database recreated: %v", e)
	}
}
func TestInitializationEvidenceWithoutDatabaseFailsClosed(t *testing.T) {
	for _, name := range []string{"key", ".key-incomplete", ".ledger-incomplete", "ledger.sqlite-journal", "ledger.sqlite-wal"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.WriteFile(filepath.Join(dir, name), []byte("initialization evidence"), 0600); e != nil {
				t.Fatal(e)
			}
			if s, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); e == nil {
				s.Close()
				t.Fatal("initialization evidence ignored")
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 1 || entries[0].Name() != name {
				t.Fatalf("failed open changed initialization evidence: %v %v", entries, e)
			}
		})
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
	conflicting.PredecessorWire = []byte("different ASK wire\n")
	digest := sha256.Sum256(conflicting.PredecessorWire)
	conflicting.WireDigest = hex.EncodeToString(digest[:])
	if _, e = s.Insert(ctx, j.ProjectID, j.AskID, conflicting); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	for _, phase := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted} {
		j = advance(t, s, j, phase, j.Data)
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
func TestPredecessorWireDigestValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Data)
	}{
		{"missing", func(d *Data) { d.PredecessorWire = nil }},
		{"empty", func(d *Data) {
			d.PredecessorWire = []byte{}
			digest := sha256.Sum256(d.PredecessorWire)
			d.WireDigest = hex.EncodeToString(digest[:])
		}},
		{"different bytes", func(d *Data) { d.PredecessorWire[0] ^= 1 }},
		{"trailing whitespace", func(d *Data) { d.PredecessorWire = append(d.PredecessorWire, ' ') }},
		{"wrong digest", func(d *Data) { d.WireDigest = strings.Repeat("a", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := openTest(t)
			d := data()
			tc.mutate(&d)
			if _, err := s.Insert(ctx, "project", "invalid", d); !errors.Is(err, ErrInvalid) {
				t.Fatalf("insert: %v", err)
			}
			j := insert(t, s)
			if _, err := s.CompareAndSwap(ctx, j, Rejected, d); !errors.Is(err, ErrInvalid) {
				t.Fatalf("transition: %v", err)
			}
			// Seal invalid plaintext directly to verify reopening validates the
			// stored wire and digest even when authentication succeeds.
			plaintext, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := s.seal(plaintext, s.jobAAD(j))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET sealed=? WHERE project_id=? AND ask_id=?", sealed, j.ProjectID, j.AskID); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); !errors.Is(err, ErrInvalid) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("reopen: %v", err)
			}
		})
	}
}

func TestPredecessorWireImmutable(t *testing.T) {
	s, _ := openTest(t)
	j := insert(t, s)
	for _, recompute := range []bool{false, true} {
		t.Run(strconv.FormatBool(recompute), func(t *testing.T) {
			expected := j
			expected.Data = data()
			expected.Data.PredecessorWire[0] ^= 1
			if recompute {
				digest := sha256.Sum256(expected.Data.PredecessorWire)
				expected.Data.WireDigest = hex.EncodeToString(digest[:])
			}
			if _, err := s.CompareAndSwap(ctx, expected, Rejected, expected.Data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("changed predecessor accepted: %v", err)
			}
		})
	}
	stored, err := s.Get(ctx, j.ProjectID, j.AskID)
	if err != nil || string(stored.Data.PredecessorWire) != string(j.Data.PredecessorWire) || stored.Revision != j.Revision {
		t.Fatalf("rejected mutation changed stored job: %v", err)
	}
}

func TestCASAcrossStoresAndRevocation(t *testing.T) {
	s, dir := openTest(t)
	j := insert(t, s)
	other, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
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
			_, _, e := s.ClaimProvider(ctx, j, time.Now())
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
	j = advance(t, s, j, ProviderStarted, j.Data)
	var e error
	j = advance(t, s, j, Unknown, j.Data)
	if _, e = s.CompareAndSwap(ctx, j, Queued, j.Data); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
func TestRejectionOnlyBeforeProviderStarted(t *testing.T) {
	for _, phase := range []Phase{Queued, ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted, Unknown, Rejected} {
		t.Run(string(phase), func(t *testing.T) {
			s, _ := openTest(t)
			j := insert(t, s)
			if phase == Unknown || phase == Rejected {
				var e error
				j, e = s.CompareAndSwap(ctx, j, phase, j.Data)
				if e != nil {
					t.Fatal(e)
				}
			} else {
				for _, next := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared, Admitted} {
					if j.Phase == phase {
						break
					}
					j = advance(t, s, j, next, j.Data)
				}
			}
			_, e := s.CompareAndSwap(ctx, j, Rejected, j.Data)
			if phase == Queued && e != nil {
				t.Fatal(e)
			}
			if phase != Queued && !errors.Is(e, ErrInvalid) {
				t.Fatalf("rejected after %s: %v", phase, e)
			}
		})
	}
}
func TestRevokedPreparedReplyReceiptReconciliation(t *testing.T) {
	for _, phase := range []Phase{Queued, ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared} {
		t.Run(string(phase), func(t *testing.T) {
			s, dir := openTest(t)
			j := insert(t, s)
			for _, next := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared} {
				if j.Phase == phase {
					break
				}
				d := j.Data
				if next == ReplyPrepared {
					d.ReplyID = "reply"
					d.ReplyDigest = strings.Repeat("b", 64)
				}
				j = advance(t, s, j, next, d)
			}
			j, e := s.Revoke(ctx, j)
			if e != nil {
				t.Fatal(e)
			}
			for _, next := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared} {
				if _, e = s.CompareAndSwap(ctx, j, next, j.Data); !errors.Is(e, ErrInvalid) {
					t.Fatalf("revoked transition to %s: %v", next, e)
				}
			}
			if _, e = s.CompareAndSwap(ctx, j, Admitted, j.Data); !errors.Is(e, ErrInvalid) {
				t.Fatalf("missing receipt accepted: %v", e)
			}
			d := j.Data
			d.Receipt = []byte(`{"validated":true}`)
			if phase != ReplyPrepared {
				if _, e = s.CompareAndSwap(ctx, j, Admitted, d); !errors.Is(e, ErrInvalid) {
					t.Fatalf("receipt admitted from %s: %v", phase, e)
				}
				return
			}
			for _, kind := range []string{"missing reply ID", "changed reply ID", "changed reply digest", "invalid receipt", "null receipt"} {
				invalid := d
				switch kind {
				case "missing reply ID":
					invalid.ReplyID = ""
				case "changed reply ID":
					invalid.ReplyID = "different"
				case "changed reply digest":
					invalid.ReplyDigest = strings.Repeat("c", 64)
				case "invalid receipt":
					invalid.Receipt = []byte("invalid JSON")
				case "null receipt":
					invalid.Receipt = []byte(" null ")
				}
				if _, e = s.CompareAndSwap(ctx, j, Admitted, invalid); !errors.Is(e, ErrInvalid) {
					t.Fatalf("%s reconciliation accepted: %v", kind, e)
				}
			}
			j, e = s.CompareAndSwap(ctx, j, Admitted, d)
			if e != nil || !j.Revoked || string(j.Data.Receipt) != string(d.Receipt) {
				t.Fatalf("reconciliation: %+v %v", j, e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s, e = Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			got, e := s.Get(ctx, j.ProjectID, j.AskID)
			if e != nil || got.Phase != Admitted || !got.Revoked || string(got.Data.Receipt) != string(d.Receipt) {
				t.Fatalf("persisted reconciliation: %+v %v", got, e)
			}
		})
	}
}
func TestRevokedReconciliationRequiresStoredReplyID(t *testing.T) {
	s, _ := openTest(t)
	j := insert(t, s)
	for _, next := range []Phase{ProviderStarted, OutputReady, ReplyPreparing, ReplyPrepared} {
		j = advance(t, s, j, next, j.Data)
	}
	j, e := s.Revoke(ctx, j)
	if e != nil {
		t.Fatal(e)
	}
	j.Data.ReplyID = "caller-only-reply"
	d := j.Data
	d.Receipt = []byte(`{"validated":true}`)
	if _, e = s.CompareAndSwap(ctx, j, Admitted, d); !errors.Is(e, ErrInvalid) {
		t.Fatalf("reconciled without persisted reply identity: %v", e)
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
			if reopened, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); e == nil {
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
			if reopened, e := Open(dir, binding(), Limits{CallsPerDay: 100, MaxConcurrent: 100}); e == nil {
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
