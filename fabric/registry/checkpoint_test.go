package registry

import (
	"context"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"testing"
)

func publishPending(t *testing.T, s *Store, b *search.Backend) {
	t.Helper()
	ctx := context.Background()
	batch, e := s.PendingIndex(ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := b.Prepare(ctx, batch)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Publish(ctx, prepared, s.CommitIndex); e != nil {
		t.Fatal(e)
	}
}
func TestCheckpointCompactRestartPagedTailAndPermanentHistory(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	first, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	b, e := search.New(search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	d.Name = "Renamed"
	second, e := s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: first})
	if e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	cp, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM index_commits").Scan(&n); e != nil || n != 0 {
		t.Fatal("old search generation bodies retained", e)
	}
	records, e := s.Records(ctx, s.Namespace(), 0, 100)
	if e != nil || len(records) != 2 {
		t.Fatal("signed source history purged", e)
	}
	d.Description = "New tail evidence"
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: second}); e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	s.Close()
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal("checkpoint/tail startup", e)
	}
	defer s.Close()
	restored, e := s.LoadIndex(ctx, search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	result, e := restored.Search(ctx, fabric.DiscoverRequest{Query: "evidence", Limit: 10})
	if e != nil || len(result.Candidates) != 1 || result.Candidates[0].Document.Name != "Renamed" {
		t.Fatal("tail not applied to checkpoint", e)
	}
	tail, e := s.IndexRecords(ctx, cp.Header().Generation, 32)
	if e != nil || len(tail) != 1 {
		t.Fatal("unbounded old history restored", e)
	}
}
func TestFailedCheckpointLeavesOldSnapshotAndTailIntact(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := search.New(search.Config{})
	publishPending(t, s, b)
	old, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, old); e != nil {
		t.Fatal(e)
	}
	d.Name = "New"
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev}); e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	next, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER reject_checkpoint BEFORE INSERT ON checkpoint_pages BEGIN SELECT RAISE(ABORT,'checkpoint failure fixture'); END;`); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, next); e == nil {
		t.Fatal("expected checkpoint rollback")
	}
	header, e := s.checkpointHeader(ctx)
	if e != nil || header.SHA256 != old.Header().SHA256 {
		t.Fatal("old checkpoint changed", e)
	}
	tail, e := s.IndexRecords(ctx, old.Header().Generation, 32)
	if e != nil || len(tail) != 1 {
		t.Fatal("failed checkpoint purged tail", e)
	}
	restored, e := s.LoadIndex(ctx, search.Config{})
	if e != nil {
		t.Fatal("old snapshot plus retained tail cannot recover", e)
	}
	result, e := restored.Search(ctx, fabric.DiscoverRequest{Query: "new", Limit: 10})
	if e != nil || len(result.Candidates) != 1 {
		t.Fatal(e)
	}
}
func TestCorruptCheckpointNoVisibleBackend(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	b, _ := search.New(search.Config{})
	publishPending(t, s, b)
	cp, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE checkpoint_pages SET page='{}' WHERE section=?", search.CheckpointReferences); e != nil {
		t.Fatal(e)
	}
	if exposed, e := s.LoadIndex(ctx, search.Config{}); e == nil || exposed != nil {
		t.Fatal("partial or malformed snapshot exposed")
	}
}
func TestCheckpointGenerationMismatchCannotDeleteRecoveryTail(t *testing.T) {
	s, c, _ := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	rev, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := search.New(search.Config{})
	publishPending(t, s, b)
	old, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	d.Name = "Advanced"
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: rev}); e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	if e = s.SaveCheckpoint(ctx, old); e == nil {
		t.Fatal("stale snapshot deleted current tail")
	}
	tail, e := s.IndexRecords(ctx, 0, 32)
	if e != nil || len(tail) != 2 {
		t.Fatal("history lost", e)
	}
}
func TestCheckpointPagedMoreThanOnePageAndEmptyDomain(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	b, _ := search.New(search.Config{})
	empty, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, empty); e != nil {
		t.Fatal("empty-domain checkpoint", e)
	}
	for i := range 40 {
		d := endpoint(t, s)
		d.Name = "Common"
		if _, e = s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
			t.Fatal(e)
		}
		if i%16 == 15 {
			publishPending(t, s, b)
		}
	}
	publishPending(t, s, b)
	cp, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	var pages int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM checkpoint_pages WHERE section=?", search.CheckpointReferences).Scan(&pages); e != nil || pages != 2 {
		t.Fatal("not real paged checkpoint", e)
	}
	s.Close()
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.LoadIndex(ctx, search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	stats, e := got.Stats(ctx)
	if e != nil || stats.Documents != 40 {
		t.Fatal("paged restore count", e)
	}
}
func TestCheckpointCarrierCorruptionFailsOpen(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	d := endpoint(t, s)
	if _, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d}); e != nil {
		t.Fatal(e)
	}
	b, _ := search.New(search.Config{})
	publishPending(t, s, b)
	cp, e := b.Checkpoint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	header := cp.Header()
	header.ReferenceRows++
	raw, _ := json.Marshal(header)
	if _, e = s.db.Exec("UPDATE checkpoint_head SET header=?", raw); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if opened, e := Open(ctx, dir); e == nil {
		opened.Close()
		t.Fatal("corrupted checkpoint accepted on reopen")
	}
}

func TestOrderedReplayFloorCompactsOnlyIndexHistoryAndRejectsForgedNewCursor(t *testing.T) {
	s, c, dir := fixture(t)
	ctx := context.Background()
	b, e := search.New(s.IndexConfig())
	if e != nil {
		t.Fatal(e)
	}
	d := endpoint(t, s)
	firstRevision, e := s.Register(ctx, c, fabric.RegistryUpdate{Descriptor: d})
	if e != nil {
		t.Fatal(e)
	}
	publishPending(t, s, b)
	old := d
	old.Revision = firstRevision
	revision := firstRevision
	for i := range 5 {
		d.Name = string(rune('a' + i))
		revision, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: revision})
		if e != nil {
			t.Fatal(e)
		}
		publishPending(t, s, b)
	}
	cp, e := b.CheckpointAtReplayFloor(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if cp.Header().RevisionRows != 1 || cp.Header().ReplayFloor != cp.Header().SourceSequence {
		t.Fatal("floor didn't compact superseded hashes")
	}
	if e = s.SaveCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	if e = b.ActivateCheckpoint(ctx, cp); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Prepare(ctx, search.Batch{Upserts: []fabric.SearchDocument{{Ref: d.Ref, Revision: old.Revision, Name: old.Name, Kind: d.Kind}}, UpstreamCursor: "1"}); e == nil {
		t.Fatal("cursor before floor accepted")
	}
	d.Description = "Genuine newer source"
	if _, e = s.Update(ctx, c, fabric.RegistryUpdate{Descriptor: d, ExpectedRevision: revision}); e != nil {
		t.Fatal(e)
	}
	batch, e := s.PendingIndex(ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	forged := batch
	forged.Upserts = []fabric.SearchDocument{{Ref: d.Ref, Revision: old.Revision, Name: old.Name, Kind: d.Kind}}
	prepared, e := b.Prepare(ctx, forged)
	if e != nil {
		t.Fatal("ordered source must enforce authoritative source in commit callback", e)
	}
	if e = b.Publish(ctx, prepared, s.CommitIndex); e == nil {
		t.Fatal("new cursor forged stale descriptor authority")
	}
	publishPending(t, s, b)
	s.Close()
	s, e = Open(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	restored, e := s.LoadIndex(ctx, s.IndexConfig())
	if e != nil {
		t.Fatal(e)
	}
	got, e := restored.Search(ctx, fabric.DiscoverRequest{Query: "genuine", Limit: 10})
	if e != nil || len(got.Candidates) != 1 {
		t.Fatal("compacted checkpoint + new tail failed", e)
	}
	records, e := s.Records(ctx, s.Namespace(), 0, 100)
	if e != nil || len(records) != 7 {
		t.Fatal("signed source identity history compacted", e)
	}
}
