package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"strconv"
	"testing"
)

func checkpointLoader(c *Checkpoint, limit int) CheckpointLoader {
	return func(ctx context.Context, section, after string, _ int) (CheckpointPage, error) {
		return c.Page(ctx, section, after, limit)
	}
}
func TestCheckpointPinnedPagedRestoreAndTail(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	for i := uint64(0); i < 170; i++ {
		d := doc(i, "common rare")
		if err := b.Upsert(ctx, d); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			d.Revision = "r2"
			d.ShortDescription = "common"
			if err := b.Upsert(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		if i%7 == 0 {
			if err := b.Delete(ctx, d.Ref, d.Revision); err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot, err := b.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := fabric.DiscoverRequest{Query: "common rare", Limit: 100}
	expected, err := b.Search(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := b.Prepare(ctx, Batch{Upserts: []fabric.SearchDocument{doc(200, "rare")}, UpstreamCursor: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Publish(ctx, tail, nil); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{1, 7, 32, MaxBatchDocuments} {
		fresh := newBackend(t)
		if err = fresh.RestoreCheckpoint(ctx, snapshot.Header(), checkpointLoader(snapshot, limit)); err != nil {
			t.Fatalf("limit%d: %v", limit, err)
		}
		got, err := fresh.Search(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		equalHits(t, got.Candidates, expected.Candidates)
		if got.IndexRevision != expected.IndexRevision {
			t.Fatal("checkpoint revision changed")
		}
		if err = fresh.Restore(ctx, tail.Record()); err != nil {
			t.Fatal("tail", err)
		}
		old := doc(0, "common rare")
		if err = fresh.Upsert(ctx, old); err != nil {
			t.Fatal(err)
		}
		current, _ := get(fresh.current.Load().refs, old.Ref.String())
		if current.value != nil {
			t.Fatal("old revision resurrected retired descriptor after checkpoint")
		}
	}
}
func TestCheckpointFailureNeverPublishesPartialState(t *testing.T) {
	ctx := context.Background()
	source := newBackend(t)
	for i := uint64(0); i < 100; i++ {
		if err := source.Upsert(ctx, doc(i, "common")); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := source.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*CheckpointPage){
		"corrupt raw checksum": func(p *CheckpointPage) {
			if len(p.References) > 0 {
				p.References[0].Document.ShortDescription = "tampered"
			}
		},
		"valid page digest but incomplete stream": func(p *CheckpointPage) { p.Next = ""; p.SHA256, _ = checksumPage(*p) },
		"wrong generation":                        func(p *CheckpointPage) { p.Generation++; p.SHA256, _ = checksumPage(*p) },
		"duplicate storage ID": func(p *CheckpointPage) {
			if len(p.References) > 1 {
				p.References[1].StorageID = p.References[0].StorageID
				p.SHA256, _ = checksumPage(*p)
			}
		},
		"out of order": func(p *CheckpointPage) {
			if len(p.References) > 1 {
				p.References[0], p.References[1] = p.References[1], p.References[0]
				p.SHA256, _ = checksumPage(*p)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fresh := newBackend(t)
			loader := func(ctx context.Context, section, after string, _ int) (CheckpointPage, error) {
				p, err := snapshot.Page(ctx, section, after, 7)
				mutate(&p)
				return p, err
			}
			if err = fresh.RestoreCheckpoint(ctx, snapshot.Header(), loader); err == nil {
				t.Fatal("corrupt snapshot admitted")
			}
			stats, _ := fresh.Stats(ctx)
			if stats.Documents != 0 || fresh.current.Load().number != 0 {
				t.Fatal("partial snapshot visible")
			}
		})
	}
	failed := errors.New("storage read failed")
	fresh := newBackend(t)
	reads := 0
	if err = fresh.RestoreCheckpoint(ctx, snapshot.Header(), func(ctx context.Context, section, after string, _ int) (CheckpointPage, error) {
		reads++
		if reads == 3 {
			return CheckpointPage{}, failed
		}
		return snapshot.Page(ctx, section, after, 7)
	}); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	stats, _ := fresh.Stats(ctx)
	if stats.Documents != 0 {
		t.Fatal("failed load published")
	}
}
func TestCheckpointCancellationConcurrentPublicationAndRollback(t *testing.T) {
	ctx := context.Background()
	source := newBackend(t)
	if err := source.Upsert(ctx, doc(1, "old")); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := source.Checkpoint(ctx)
	if err := source.Delete(ctx, testRef(1), "r1"); err != nil {
		t.Fatal(err)
	}
	if err := source.RestoreCheckpoint(ctx, snapshot.Header(), checkpointLoader(snapshot, 7)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("rollback admitted", err)
	}
	fresh := newBackend(t)
	once := false
	loader := func(ctx context.Context, section, after string, _ int) (CheckpointPage, error) {
		if !once {
			once = true
			if err := fresh.Upsert(ctx, doc(3, "concurrent")); err != nil {
				return CheckpointPage{}, err
			}
		}
		return snapshot.Page(ctx, section, after, 7)
	}
	if err := fresh.RestoreCheckpoint(ctx, snapshot.Header(), loader); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("mixed restore publication", err)
	}
	result, err := fresh.Search(ctx, fabric.DiscoverRequest{Query: "concurrent", Limit: 1})
	if err != nil || len(result.Candidates) != 1 {
		t.Fatal("concurrent state lost", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = source.Checkpoint(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = newBackend(t).RestoreCheckpoint(cancelled, snapshot.Header(), checkpointLoader(snapshot, 7)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestEmptyCheckpointAndZeroLexicalCorpus(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	snapshot, err := b.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newBackend(t)
	if err = fresh.RestoreCheckpoint(ctx, snapshot.Header(), checkpointLoader(snapshot, 1)); err != nil {
		t.Fatal(err)
	}
	d := doc(1, "")
	d.Tags = nil
	if err = fresh.Upsert(ctx, d); err != nil {
		t.Fatal(err)
	}
	result, err := fresh.Search(ctx, fabric.DiscoverRequest{Query: "unknown", Limit: 1})
	if err != nil || len(result.Candidates) != 0 {
		t.Fatal(err)
	}
	snapshot, err = fresh.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = newBackend(t).RestoreCheckpoint(ctx, snapshot.Header(), checkpointLoader(snapshot, 1)); err != nil {
		t.Fatal(err)
	}
}
func TestCheckpointPaginationIsBoundedAndStable(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	for i := uint64(0); i < 90; i++ {
		d := doc(100-i, fmt.Sprintf("token%d", i))
		if err := b.Upsert(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, _ := b.Checkpoint(ctx)
	original, _ := snapshot.Page(ctx, CheckpointReferences, "", 7)
	if err := b.Upsert(ctx, doc(999, "new")); err != nil {
		t.Fatal(err)
	}
	again, _ := snapshot.Page(ctx, CheckpointReferences, "", 7)
	one, _ := json.Marshal(original)
	two, _ := json.Marshal(again)
	if string(one) != string(two) {
		t.Fatal("export mixed concurrent generations")
	}
	for _, section := range []string{CheckpointReferences, CheckpointRevisions} {
		after := ""
		count := 0
		for {
			page, err := snapshot.Page(ctx, section, after, 7)
			if err != nil {
				t.Fatal(err)
			}
			rows := len(page.References) + len(page.Revisions)
			if rows > 7 {
				t.Fatal("unbounded page")
			}
			count += rows
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		if count != 90 {
			t.Fatalf("section%s count%d", section, count)
		}
	}
}

func orderedBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(Config{ReplayOrder: &ReplayOrder{Format: "registry.outbox-sequence.v1", Sequence: func(cursor string) (uint64, error) {
		n, err := strconv.ParseUint(cursor, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != cursor {
			return 0, errors.New("noncanonical source cursor")
		}
		return n, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestOrderedCheckpointReplayFloorAndTail(t *testing.T) {
	ctx := context.Background()
	b := orderedBackend(t)
	publish := func(batch Batch) CommitRecord {
		t.Helper()
		p, err := b.Prepare(ctx, batch)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Publish(ctx, p, nil); err != nil {
			t.Fatal(err)
		}
		return p.Record()
	}
	live := doc(1, "common")
	retired := doc(2, "common")
	first := publish(Batch{Upserts: []fabric.SearchDocument{live, retired}, UpstreamCursor: "1"})
	live.Revision = "r2"
	live.ShortDescription = "common newer"
	publish(Batch{Upserts: []fabric.SearchDocument{live}, UpstreamCursor: "2"})
	last := publish(Batch{Deletes: []Deletion{{Ref: retired.Ref, ExpectedRevision: retired.Revision}}, UpstreamCursor: "3"})
	full, err := b.Checkpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := b.CheckpointAtReplayFloor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if full.Header().RevisionRows != 3 || compact.Header().RevisionRows != 2 || compact.Header().ReplayFloor != 3 {
		t.Fatal("unexpected compaction headers", full.Header(), compact.Header())
	}
	if err = b.ActivateCheckpoint(ctx, compact); err != nil {
		t.Fatal(err)
	}
	fresh := orderedBackend(t)
	if err = fresh.RestoreCheckpoint(ctx, compact.Header(), checkpointLoader(compact, 1)); err != nil {
		t.Fatal(err)
	}
	for _, batch := range []Batch{
		{Upserts: []fabric.SearchDocument{doc(1, "common")}, UpstreamCursor: "1"},
		{Upserts: []fabric.SearchDocument{live}, UpstreamCursor: "3"},
		{Upserts: []fabric.SearchDocument{retired}, UpstreamCursor: "2"},
	} {
		if _, err = fresh.Prepare(ctx, batch); !errors.Is(err, ErrReplayBeforeFloor) {
			t.Fatal("old source cursor admitted", err)
		}
	}
	if err = fresh.Restore(ctx, first); err == nil {
		t.Fatal("old commit admitted")
	}
	if err = fresh.Restore(ctx, last); err != nil {
		t.Fatal("exact final commit should remain idempotent", err)
	}
	// A fresh attested source record referencing the already remembered tombstone
	// revision must not resurrect it. Authoritative source validation is external.
	tail := publish(Batch{Upserts: []fabric.SearchDocument{retired, doc(3, "common tail")}, UpstreamCursor: "4"})
	if err = fresh.Restore(ctx, tail); err != nil {
		t.Fatal(err)
	}
	e, _ := get(fresh.current.Load().refs, retired.Ref.String())
	if e.value != nil {
		t.Fatal("remembered tombstone resurrected")
	}
	got, _ := fresh.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 10})
	if len(got.Candidates) != 2 {
		t.Fatal(got)
	}
	if err = b.ActivateCheckpoint(ctx, compact); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale checkpoint rolled back tail", err)
	}
	if _, err = newBackend(t).CheckpointAtReplayFloor(ctx); err == nil {
		t.Fatal("generic source was compacted")
	}
	incompatible := newBackend(t)
	if err = incompatible.RestoreCheckpoint(ctx, compact.Header(), checkpointLoader(compact, 1)); err == nil {
		t.Fatal("ordered source restored without contract")
	}
}
