package a2a

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

func retainedAdmission() Association {
	ref, _ := fabric.NewEndpointRef(make([]byte, 32))
	return Association{Key: AssociationKey{Principal: fabric.Principal{Ref: "local:alice", Issuer: "verified.owner", Kind: "actor.human"}, Ref: ref, Revision: "r1", Binding: "selected-binding", InvocationID: "first", Audience: "test.audience"}, InputSHA: strings.Repeat("a", 64), Operation: "send", Mode: "stream"}
}
func bootstrapLedger(t *testing.T, c StoreConfig) (*SQLiteStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	s, e := Bootstrap(context.Background(), dir, testStoreScope(), c, testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func TestRetainedLedgerRequiresExplicitIdentityAndInitialization(t *testing.T) {
	ctx := context.Background()
	s, dir := bootstrapLedger(t, DefaultStoreConfig())
	s.Close()
	if _, e := Bootstrap(ctx, dir, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		t.Fatal("rebootstrap accepted")
	}
	cases := []struct {
		name      string
		scope     StoreScope
		config    StoreConfig
		protector DataProtector
	}{
		{"scope", StoreScope{Domain: testStoreScope().Domain, ID: "other-node", Audience: "test.audience"}, DefaultStoreConfig(), testProtector(t)},
		{"audience", StoreScope{Domain: testStoreScope().Domain, ID: "node-a2a", Audience: "other.audience"}, DefaultStoreConfig(), testProtector(t)},
		{"config", testStoreScope(), StoreConfig{1, 2, 64 << 20, 128 << 20, 16384, 20480, 64}, testProtector(t)},
	}
	wrong, _ := durable.NewAESGCM(KeyReference{ID: "operator-test", Version: "1"}, make([]byte, 32))
	cases = append(cases, struct {
		name      string
		scope     StoreScope
		config    StoreConfig
		protector DataProtector
	}{"same-reference-wrong-secret", testStoreScope(), DefaultStoreConfig(), wrong})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, e := Open(ctx, dir, tc.scope, tc.config, tc.protector); e == nil {
				got.Close()
				t.Fatal("retained identity mismatch accepted")
			}
		})
	}
	if e := os.Remove(filepath.Join(dir, "a2a.sqlite")); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(ctx, dir, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		t.Fatal("missing DB recreated")
	}
	if _, e := os.Stat(filepath.Join(dir, "a2a.sqlite")); !os.IsNotExist(e) {
		t.Fatal("Open wrote missing database", e)
	}
	if _, e := Open(ctx, filepath.Join(t.TempDir(), "missing"), testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		t.Fatal("missing directory recreated")
	}
}
func TestRetainedReplayFenceIndependentOfChangedTarget(t *testing.T) {
	ctx := context.Background()
	s, _ := bootstrapLedger(t, DefaultStoreConfig())
	a := retainedAdmission()
	if e := s.Admit(ctx, a); e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*Association){"revision": func(a *Association) { a.Key.Revision = "r2" }, "binding": func(a *Association) { a.Key.Binding = "different" }, "target": func(a *Association) { a.Key.Ref, _ = fabric.NewEndpointRef([]byte(strings.Repeat("x", 32))) }, "hash": func(a *Association) { a.InputSHA = strings.Repeat("b", 64) }, "mode": func(a *Association) { a.Mode = "unary" }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := a
			mutate(&changed)
			if e := s.Admit(ctx, changed); !errors.Is(e, ErrConflict) {
				t.Fatal("changed retry acquired new effect", e)
			}
			if changed.Key != a.Key {
				if _, e := s.Lookup(ctx, changed.Key); e == nil {
					t.Fatal("old task read through changed scope")
				}
			}
		})
	}
	if e := s.Admit(ctx, a); e != ErrAttempted {
		t.Fatal(e)
	}
	if e := s.Associate(ctx, a.Key, "task", "context"); e != nil {
		t.Fatal(e)
	}
	before := s.state
	for i := 0; i < 5; i++ {
		if e := s.Associate(ctx, a.Key, "task", "context"); e != nil {
			t.Fatal(e)
		}
	}
	if s.state != before {
		t.Fatal("idempotent association appended history")
	}
	if s.Associate(ctx, a.Key, "other", "context") == nil {
		t.Fatal("changed association accepted")
	}
	for _, mutate := range []func(*Association){func(a *Association) { a.Key.Principal.Kind = "actor.service" }, func(a *Association) { a.Key.Principal.Issuer = "other-owner" }} {
		changed := a
		mutate(&changed)
		if _, e := s.Lookup(ctx, changed.Key); e == nil {
			t.Fatal("cross-owner/kind association revealed")
		}
	}
}
func TestRetainedLedgerCapacityRejectsWithoutWrites(t *testing.T) {
	c := DefaultStoreConfig()
	c.MaxAdmissions = 1
	c.MaxEntries = 2
	s, _ := bootstrapLedger(t, c)
	ctx := context.Background()
	a := retainedAdmission()
	if s.Admit(ctx, a) != nil || s.Associate(ctx, a.Key, "task", "context") != nil {
		t.Fatal("first admission failed")
	}
	before := s.state
	a.Key.InvocationID = "new"
	if e := s.Admit(ctx, a); e != ErrCapacity {
		t.Fatal(e)
	}
	if s.state != before {
		t.Fatal("capacity rejection mutated checkpoint")
	}
	c = DefaultStoreConfig()
	c.MaxBytes = int64(c.MaxCipherBytes)
	s, _ = bootstrapLedger(t, c)
	a = retainedAdmission()
	var rejected bool
	for i := 0; i < 100; i++ {
		a.Key.InvocationID = strings.Repeat("x", i+1)
		before = s.state
		e := s.Admit(ctx, a)
		if e == ErrCapacity {
			if before != s.state {
				t.Fatal("byte rejection mutated checkpoint")
			}
			rejected = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if !rejected {
		t.Fatal("byte capacity not enforced")
	}
}
func TestRetainedLedgerDetectsMaterializationAndAuthenticatedJournalTamper(t *testing.T) {
	mutations := map[string]string{
		"unexpected-schema": "CREATE TABLE unexpected(value INTEGER)",
		"empty-checkpoint":  "DELETE FROM checkpoint",
		"checkpoint-cipher": "UPDATE checkpoint SET cipher=zeroblob(64)",
		"journal-cipher":    "UPDATE journal SET cipher=zeroblob(64) WHERE seq=1",
		"oversized-journal": "UPDATE journal SET cipher=zeroblob(1048576) WHERE seq=1",
		"index-drop":        "DELETE FROM latest",
		"index-head":        "UPDATE latest SET last_seq=admit_seq",
		"journal-drop":      "DELETE FROM journal WHERE seq=2",
		"journal-metadata":  "UPDATE journal SET identity='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE seq=1",
	}
	for name, statement := range mutations {
		t.Run(name, func(t *testing.T) {
			s, dir := bootstrapLedger(t, DefaultStoreConfig())
			ctx := context.Background()
			a := retainedAdmission()
			if s.Admit(ctx, a) != nil || s.Associate(ctx, a.Key, "task", "context") != nil {
				t.Fatal("prepare")
			}
			s.Close()
			db, e := sql.Open("sqlite", filepath.Join(dir, "a2a.sqlite"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(statement); e != nil {
				t.Fatal(e)
			}
			db.Close()
			if got, e := Open(ctx, dir, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
				got.Close()
				t.Fatal("forged/incomplete state accepted")
			}
		})
	}
	// Empty stores also authenticate the retained operator secret.
	s, dir := bootstrapLedger(t, DefaultStoreConfig())
	s.Close()
	db, _ := sql.Open("sqlite", filepath.Join(dir, "a2a.sqlite"))
	db.Exec("DROP TABLE journal")
	db.Close()
	if got, e := Open(context.Background(), dir, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		got.Close()
		t.Fatal("missing empty-store schema accepted")
	}
}
func TestRetainedLedgerLockPrivatePathAndBoundedRestore(t *testing.T) {
	ctx := context.Background()
	c := DefaultStoreConfig()
	c.ScanPage = 2
	s, dir := bootstrapLedger(t, c)
	if got, e := Open(ctx, dir, testStoreScope(), c, testProtector(t)); e == nil {
		got.Close()
		t.Fatal("second writer opened")
	}
	a := retainedAdmission()
	for i := 0; i < 9; i++ {
		a.Key.InvocationID = strings.Repeat("x", i+1)
		if s.Admit(ctx, a) != nil || s.Associate(ctx, a.Key, "task", "context") != nil {
			t.Fatal("append")
		}
	}
	expected := s.state
	s.Close()
	s, e := Open(ctx, dir, testStoreScope(), c, testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.state != expected {
		t.Fatal("paged replay changed snapshot")
	}
	// A foreign writer is a permanent fail-closed event even if its row is otherwise valid.
	db, e := sql.Open("sqlite", filepath.Join(dir, "a2a.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec("CREATE TABLE foreign_write(value INTEGER)")
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Lookup(ctx, a.Key); e == nil {
		t.Fatal("foreign mutation ignored")
	}
	bad := c
	bad.ScanPage = 129
	if _, e = Bootstrap(ctx, filepath.Join(t.TempDir(), "oversized-page"), testStoreScope(), bad, testProtector(t)); e == nil {
		t.Fatal("unbounded scan page accepted")
	}
}

func TestExhaustedReplayLedgerNeverSendsHTTP(t *testing.T) {
	c := DefaultStoreConfig()
	c.MaxAdmissions = 1
	c.MaxEntries = 2
	f := setupConfig(t, sdk.TaskStateCompleted, true, c)
	stream, e := f.invoke("first", `{"operation":"send","mode":"stream","parts":[{"text":"hello"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	consume(t, stream)
	before := f.calls.Load()
	if before != 1 {
		t.Fatal("fixture did not send exactly once", before)
	}
	if _, e = f.invoke("second", `{"operation":"send","mode":"stream","parts":[{"text":"hello"}]}`); e == nil {
		t.Fatal("capacity admitted effect")
	}
	if f.calls.Load() != before {
		t.Fatal("capacity failure reached transport")
	}
}
func TestPrivateLedgerRejectsSymlinkAndUnsafeDirectory(t *testing.T) {
	ctx := context.Background()
	s, dir := bootstrapLedger(t, DefaultStoreConfig())
	s.Close()
	linked := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(dir, linked); e != nil {
		t.Skip("symlinks unavailable")
	}
	if got, e := Open(ctx, linked, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		got.Close()
		t.Fatal("linked directory accepted")
	}
	path := filepath.Join(dir, "a2a.sqlite")
	renamed := path + ".original"
	if os.Rename(path, renamed) != nil || os.Symlink(renamed, path) != nil {
		t.Fatal("prepare symlink")
	}
	if got, e := Open(ctx, dir, testStoreScope(), DefaultStoreConfig(), testProtector(t)); e == nil {
		got.Close()
		t.Fatal("linked database accepted")
	}
}
