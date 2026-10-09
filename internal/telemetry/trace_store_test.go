package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// testSpanRecord builds one valid metadata-only record for invocation inv
// at index i (start = now - (n-i)*time.Second, so the records are
// chronologically ordered).
func testSpanRecord(inv string, i, n int) SpanRecord {
	now := time.Now().UTC().UnixNano()
	start := now - int64(n-i)*int64(time.Second)
	return SpanRecord{
		InvocationID: inv,
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       hexID(i),
		Name:         "pagnet.invoke",
		Stage:        "pagnet.dispatch",
		Phase:        "response",
		Disposition:  "completed",
		StatusCode:   1,
		Attributes:   `{"pagnet.invocation.id":"` + inv + `","pagnet.operation.stage":"pagnet.dispatch","pagnet.interceptor.phase":"response","pagnet.operation.disposition":"completed"}`,
		Start:        start,
		End:          start + int64(500*time.Millisecond),
	}
}

// hexID renders a stable unique 16-hex span id for index i.
func hexID(i int) string {
	return fmt.Sprintf("%016x", i)
}

func storeCount(t *testing.T, s *TraceStore, inv string) int {
	t.Helper()
	spans, err := s.SpansForInvocation(context.Background(), inv, MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	return len(spans)
}

// TestTraceStoreRowCapPrunesOldest: the row cap is enforced on every
// record — the oldest records beyond the cap are pruned, the newest are
// kept, and the ordering is chronological.
func TestTraceStoreRowCapPrunesOldest(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenTraceStore(dir, StoreConfig{Retention: DefaultTraceRetention, MaxTraces: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 7; i++ {
		if err := s.Record(context.Background(), testSpanRecord("inv-cap", i, 7)); err != nil {
			t.Fatal(err)
		}
	}
	spans, err := s.SpansForInvocation(context.Background(), "inv-cap", MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 5 {
		t.Fatalf("row cap: %d rows, want 5 (the cap)", len(spans))
	}
	// The two oldest (i=0, i=1) are pruned; the newest five remain, in
	// chronological order.
	if spans[0].SpanID != hexID(2) || spans[4].SpanID != hexID(6) {
		t.Fatalf("wrong survivors/order: first=%s last=%s, want i=2..6", spans[0].SpanID, spans[4].SpanID)
	}
	// Re-recording a surviving span is idempotent (the cap holds).
	if err := s.Record(context.Background(), testSpanRecord("inv-cap", 3, 7)); err != nil {
		t.Fatal(err)
	}
	if n := storeCount(t, s, "inv-cap"); n != 5 {
		t.Fatalf("idempotent re-record changed the count: %d, want 5", n)
	}
}

// TestTraceStoreRetentionPrunesExpired: retain_until = end + retention;
// expired rows are removed by Prune, live rows survive.
func TestTraceStoreRetentionPrunesExpired(t *testing.T) {
	dir := t.TempDir()
	retention := time.Hour
	s, err := OpenTraceStore(dir, StoreConfig{Retention: retention, MaxTraces: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().UnixNano()
	live := testSpanRecord("inv-ret", 0, 1)
	if err := s.Record(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	// Expired: it ended 2h ago under a 1h retention.
	expired := testSpanRecord("inv-ret", 1, 1)
	expired.End = now - 2*int64(time.Hour)
	expired.Start = expired.End - int64(time.Second)
	if err := s.Record(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if n := storeCount(t, s, "inv-ret"); n != 2 {
		t.Fatalf("before prune: %d rows, want 2", n)
	}
	removed, err := s.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("prune removed %d rows, want 1 (the expired)", removed)
	}
	spans, err := s.SpansForInvocation(context.Background(), "inv-ret", MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 || spans[0].SpanID != live.SpanID {
		t.Fatalf("after prune: %d rows, want only the live span", len(spans))
	}
	// The live row's retention is end + the configured retention.
	if want := live.End + int64(retention); spans[0].RetainUntil != want {
		t.Fatalf("retain_until = %d, want %d (end + retention)", spans[0].RetainUntil, want)
	}
}

// TestTraceStorePruneAtOpen: an expired backlog is swept by the open-time
// prune, before any new record lands.
func TestTraceStorePruneAtOpen(t *testing.T) {
	dir := t.TempDir()
	retention := time.Hour
	s, err := OpenTraceStore(dir, StoreConfig{Retention: retention, MaxTraces: 100})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().UnixNano()
	expired := testSpanRecord("inv-open", 0, 1)
	expired.End = now - 2*int64(time.Hour)
	expired.Start = expired.End - int64(time.Second)
	if err := s.Record(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: the open-time prune must have swept the expired row.
	s2, err := OpenTraceStore(dir, StoreConfig{Retention: retention, MaxTraces: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if n := storeCount(t, s2, "inv-open"); n != 0 {
		t.Fatalf("after reopen: %d rows, want 0 (expired swept at open)", n)
	}
}

// TestTraceStoreRejectsInvalidRecords: the persistence boundary re-validates
// the metadata-only invariants — a record that fails is dropped with an
// error, never stored.
func TestTraceStoreRejectsInvalidRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenTraceStore(dir, StoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := testSpanRecord("inv-bad", 0, 1)

	longAttr := `{"pagnet.invocation.id":"` + string(make([]byte, MaxSpanAttributeBytes)) + `"`
	cases := map[string]func(*SpanRecord){
		"non-pagnet attribute key": func(r *SpanRecord) {
			r.Attributes = `{"invocation":"leak"}`
		},
		"attribute beyond bound": func(r *SpanRecord) { r.Attributes = longAttr },
		"invalid trace id":       func(r *SpanRecord) { r.TraceID = "zzf92f3577b34da6a3ce929d0e0e4736" },
		"invalid span id":        func(r *SpanRecord) { r.SpanID = "zz" },
		"missing invocation": func(r *SpanRecord) {
			r.InvocationID = ""
			r.Attributes = `{}`
		},
		"oversized invocation id": func(r *SpanRecord) { r.InvocationID = string(make([]byte, MaxSpanInvocationBytes+1)) },
		"empty name":              func(r *SpanRecord) { r.Name = "" },
		"oversized name":          func(r *SpanRecord) { r.Name = "pagnet." + string(make([]byte, MaxSpanNameBytes)) },
		"bad phase":               func(r *SpanRecord) { r.Phase = "rogue" },
		"bad disposition":         func(r *SpanRecord) { r.Disposition = "rogue" },
		"end before start":        func(r *SpanRecord) { r.End = r.Start - 1 },
		"duration beyond bound":   func(r *SpanRecord) { r.End = r.Start + int64(MaxSpanDuration+time.Hour) },
		"malformed attributes":    func(r *SpanRecord) { r.Attributes = `{not-json` },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rec := base
			mutate(&rec)
			if err := s.Record(context.Background(), rec); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	if n := storeCount(t, s, "inv-bad"); n != 0 {
		t.Fatalf("invalid records landed in the store: %d rows", n)
	}
}

// TestTraceStoreReadonlyMissing: a reader against an absent store gets the
// honest no-traces sentinel, not a failure.
func TestTraceStoreReadonlyMissing(t *testing.T) {
	if _, err := OpenTraceStoreReadonly(t.TempDir()); !errors.Is(err, ErrStoreMissing) {
		t.Fatalf("err = %v, want ErrStoreMissing", err)
	}
}

// TestTraceStoreReopenAndLimits: the schema is stable across opens, data
// persists, and the listing limit is honored.
func TestTraceStoreReopenAndLimits(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenTraceStore(dir, StoreConfig{Retention: DefaultTraceRetention, MaxTraces: 100})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Record(context.Background(), testSpanRecord("inv-reopen", i, 3)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenTraceStoreReadonly(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	all, err := s2.SpansForInvocation(context.Background(), "inv-reopen", MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("after reopen: %d rows, want 3", len(all))
	}
	// Chronological order across the reopen.
	if all[0].SpanID != hexID(0) || all[2].SpanID != hexID(2) {
		t.Fatalf("ordering lost across reopen: %s..%s", all[0].SpanID, all[2].SpanID)
	}
	two, err := s2.SpansForInvocation(context.Background(), "inv-reopen", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(two) != 2 {
		t.Fatalf("limit honored: %d rows, want 2", len(two))
	}
	// An absurd limit is clamped, not an error.
	many, err := s2.SpansForInvocation(context.Background(), "inv-reopen", 10*MaxTraceQueryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(many) != 3 {
		t.Fatalf("clamped limit: %d rows, want 3", len(many))
	}
}

// TestTraceStoreConfigBounds: retention and row-cap bounds are enforced at
// open (fail closed; zero selects the documented defaults).
func TestTraceStoreConfigBounds(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		cfg     StoreConfig
		wantErr bool
	}{
		{"zero config defaults", StoreConfig{}, false},
		{"retention below bound", StoreConfig{Retention: time.Minute}, true},
		{"retention above bound", StoreConfig{Retention: 100 * 24 * time.Hour}, true},
		{"max traces negative", StoreConfig{MaxTraces: -1}, true},
		{"max traces above bound", StoreConfig{MaxTraces: 10_000_001}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenTraceStore(dir, tc.cfg)
			if tc.wantErr {
				if err == nil {
					s.Close()
					t.Fatal("invalid config accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid config rejected: %v", err)
			}
			s.Close()
		})
	}
}

// TestTraceStoreParallelRecords: concurrent records serialize cleanly under
// the race detector (single-connection SQLite + the store mutex).
func TestTraceStoreParallelRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenTraceStore(dir, StoreConfig{Retention: DefaultTraceRetention, MaxTraces: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 80)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				rec := testSpanRecord("inv-parallel", g*10+i, 80)
				rec.SpanID = hexID(g*100 + i)
				if err := s.Record(context.Background(), rec); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := storeCount(t, s, "inv-parallel"); n != 80 {
		t.Fatalf("parallel records: %d rows, want 80", n)
	}
}
