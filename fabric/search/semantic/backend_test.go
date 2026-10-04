package semantic

import (
	"context"
	"errors"
	"math"
	"sort"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

// memoryANN is only a deterministic fault fixture. Real ANN has separate opt-in
// tests and scale proof against a pinned actual Qdrant service.
type memoryANN struct {
	points                  map[string]VectorPoint
	until                   map[string]uint64
	stages, queries, resets int
	notReady                bool
	override                func([]VectorHit) []VectorHit
}

func (m *memoryANN) Identity() string { return "verification-only-ann" }
func (m *memoryANN) ResetStage(_ context.Context, g uint64) error {
	m.resets++
	for key, p := range m.points {
		if p.From == g {
			delete(m.points, key)
			delete(m.until, key)
		}
	}
	for key, end := range m.until {
		if end == g {
			m.until[key] = math.MaxUint64
		}
	}
	return nil
}
func (m *memoryANN) Stage(_ context.Context, g uint64, ps []VectorPoint, rs []string) error {
	m.stages++
	if m.points == nil {
		m.points = map[string]VectorPoint{}
		m.until = map[string]uint64{}
	}
	for _, key := range rs {
		m.until[key] = g
	}
	for _, p := range ps {
		m.points[p.Key] = p
		m.until[p.Key] = math.MaxUint64
	}
	return nil
}
func (m *memoryANN) Ready(context.Context) error {
	if m.notReady {
		return ErrIndexNotReady
	}
	return nil
}
func (m *memoryANN) Count(_ context.Context, g uint64, model string) (uint64, error) {
	n := uint64(0)
	for key, p := range m.points {
		if p.Model == model && p.From <= g && m.until[key] > g {
			n++
		}
	}
	return n, nil
}
func (m *memoryANN) Query(_ context.Context, q VectorQuery) (VectorResult, error) {
	m.queries++
	out := []VectorHit{}
	for key, p := range m.points {
		if p.Model != q.Model || p.From > q.Generation || m.until[key] <= q.Generation {
			continue
		}
		dot, a, b := 0.0, 0.0, 0.0
		for i, v := range p.Vector {
			dot += float64(v) * float64(q.Vector[i])
			a += float64(v) * float64(v)
			b += float64(q.Vector[i]) * float64(q.Vector[i])
		}
		out = append(out, VectorHit{Ref: p.Ref, Revision: p.Revision, Score: dot / math.Sqrt(a*b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	if m.override != nil {
		out = m.override(out)
	}
	return VectorResult{Hits: out, Usage: Usage{Reported: true}}, nil
}
func (m *memoryANN) Snapshot(context.Context) (ANNSnapshot, error) {
	return ANNSnapshot{Name: "fixture", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IndexIdentity: m.Identity()}, nil
}
func (m *memoryANN) VerifySnapshot(context.Context, ANNSnapshot) error { return nil }

type embedFunc struct {
	identity EmbeddingIdentity
	run      func(context.Context, []string) ([][]float32, error)
}

func (e embedFunc) Identity() EmbeddingIdentity { return e.identity }
func (e embedFunc) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	return e.run(ctx, texts)
}
func configured(t *testing.T) (*Backend, *memoryANN) {
	t.Helper()
	ann := &memoryANN{}
	c := Config{ANN: ann, Embeddings: featureEmbedding{4}}
	gates(&c)
	b, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	return b, ann
}
func TestPublicationFailureAndRetryDoNotRepeatEmbeddingOrStage(t *testing.T) {
	ctx := context.Background()
	ann := &memoryANN{notReady: true}
	embeds := 0
	c := Config{ANN: ann, Embeddings: embedFunc{EmbeddingIdentity{"fixture", "model", "v1", 2}, func(_ context.Context, ts []string) ([][]float32, error) {
		embeds++
		vs := make([][]float32, len(ts))
		for i := range vs {
			vs[i] = []float32{1, 2}
		}
		return vs, nil
	}}}
	gates(&c)
	records := []search.CommitRecord{}
	c.Commit = func(_ context.Context, r search.CommitRecord) error { records = append(records, r); return nil }
	b, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	batch := search.Batch{Upserts: []fabric.SearchDocument{document(1, "mail")}, UpstreamCursor: "1"}
	if e = b.Apply(ctx, batch); !errors.Is(e, ErrIndexNotReady) {
		t.Fatal(e)
	}
	stats, _ := b.Stats(ctx)
	if stats.Documents != 0 || len(records) != 0 {
		t.Fatal("unready index published")
	}
	ann.notReady = false
	if e = b.Apply(ctx, batch); e != nil {
		t.Fatal(e)
	}
	if embeds != 1 || ann.stages != 1 || ann.resets != 1 {
		t.Fatal("retry repeated external side effect", embeds, ann.stages, ann.resets)
	}
	// A failed commit's abandoned generation must not become visible when a
	// different source record is selected for the same unpublished generation.
	failed := errors.New("durable rejected")
	b.config.Commit = func(context.Context, search.CommitRecord) error { return failed }
	if e = b.Apply(ctx, search.Batch{Upserts: []fabric.SearchDocument{document(2, "abandoned")}, UpstreamCursor: "2"}); !errors.Is(e, failed) {
		t.Fatal(e)
	}
	b.config.Commit = c.Commit
	if e = b.Apply(ctx, search.Batch{Upserts: []fabric.SearchDocument{document(3, "mail")}, UpstreamCursor: "2"}); e != nil {
		t.Fatal(e)
	}
	result, e := b.Search(ctx, fabric.DiscoverRequest{Query: "mail", Limit: 10})
	if e != nil || len(result.Candidates) != 2 {
		t.Fatal(result, e)
	}
	for _, c := range result.Candidates {
		if c.Document.Ref == document(2, "").Ref {
			t.Fatal("abandoned stage resurrected")
		}
	}
}
func TestDisclosureDeniedBeforeAnySelectedProviderReceivesData(t *testing.T) {
	b, ann := configured(t)
	denied := errors.New("operator denied disclosure")
	b.config.DisclosureGate = func(context.Context, Disclosure) error { return denied }
	if e := b.Upsert(context.Background(), document(1, "secret")); !errors.Is(e, denied) || ann.stages != 0 {
		t.Fatal(e)
	}
	if _, e := b.Search(context.Background(), fabric.DiscoverRequest{Query: "secret", Limit: 10}); !errors.Is(e, denied) || ann.queries != 0 {
		t.Fatal(e)
	}
	b.config.DisclosureGate = func(context.Context, Disclosure) error { return nil }
	b.config.IndexGate = func(context.Context, []fabric.SearchDocument) error { return denied }
	if e := b.Upsert(context.Background(), document(1, "secret")); !errors.Is(e, denied) || ann.stages != 0 {
		t.Fatal(e)
	}
}
func TestMalformedEmbeddingAndANNResultFailClosed(t *testing.T) {
	for name, vectors := range map[string][][]float32{"wrong count": {}, "wrong dimensions": {{1}}, "zero norm": {{0, 0}}, "NaN": {{float32(math.NaN()), 1}}, "Inf": {{float32(math.Inf(1)), 1}}} {
		t.Run(name, func(t *testing.T) {
			ann := &memoryANN{}
			c := Config{ANN: ann, Embeddings: embedFunc{EmbeddingIdentity{"fixture", "model", "v1", 2}, func(context.Context, []string) ([][]float32, error) { return vectors, nil }}}
			gates(&c)
			b, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			if e = b.Upsert(context.Background(), document(1, "mail")); !errors.Is(e, ErrInvalidVector) || ann.stages != 0 {
				t.Fatal(e)
			}
		})
	}
	b, ann := configured(t)
	if e := b.Upsert(context.Background(), document(1, "mail")); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func([]VectorHit) []VectorHit{
		"unknown ref": func(h []VectorHit) []VectorHit { h[0].Ref = document(3, "").Ref; return h }, "changed revision": func(h []VectorHit) []VectorHit { h[0].Revision = "r2"; return h }, "duplicate": func(h []VectorHit) []VectorHit { return append(h, h[0]) }, "NaN": func(h []VectorHit) []VectorHit { h[0].Score = math.NaN(); return h },
	} {
		t.Run(name, func(t *testing.T) {
			ann.override = mutate
			if _, e := b.Search(context.Background(), fabric.DiscoverRequest{Query: "mail", Limit: 10}); e == nil {
				t.Fatal("invalid ANN result escaped")
			}
		})
	}
	ann.override = nil
	if _, e := b.Search(context.Background(), fabric.DiscoverRequest{Query: "mail", Limit: 10, Filters: fabric.SearchFilters{Providers: []string{"forbidden"}}}); e == nil {
		t.Fatal("provider returned outside indexed filters")
	}
}
func TestSemanticPagingDoesNotRerunEmbeddingOrANN(t *testing.T) {
	b, ann := configured(t)
	for i := uint64(1); i <= 3; i++ {
		if e := b.Upsert(context.Background(), document(i, "mail")); e != nil {
			t.Fatal(e)
		}
	}
	r := fabric.DiscoverRequest{Query: "mail", Limit: 1}
	first, e := b.Search(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	r.Cursor = first.NextCursor
	queries := ann.queries
	if _, e = b.Search(context.Background(), r); e != nil || ann.queries != queries {
		t.Fatal("paid/index query rerun", e)
	}
	if e = b.Upsert(context.Background(), document(4, "mail")); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Search(context.Background(), r); !errors.Is(e, snapshotStale()) {
		t.Fatal("stale source generation page", e)
	}
}

type changingANN struct {
	*memoryANN
	id string
}

func (m *changingANN) Identity() string { return m.id }
func TestChangedSelectedANNFailsBeforeDisclosure(t *testing.T) {
	ann := &changingANN{memoryANN: &memoryANN{}, id: "selected-v1"}
	c := Config{Embeddings: featureEmbedding{dims: 2}, ANN: ann}
	gates(&c)
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	b.config.DisclosureGate = func(context.Context, Disclosure) error { calls++; return nil }
	ann.id = "another-provider"
	if err = b.Upsert(context.Background(), document(1, "test")); err == nil {
		t.Fatal("changed provider mutation accepted")
	}
	if _, err = b.Search(context.Background(), fabric.DiscoverRequest{Query: "test", Limit: 1}); err == nil {
		t.Fatal("changed provider query accepted")
	}
	if _, err = b.Checkpoint(context.Background()); err == nil {
		t.Fatal("changed provider checkpoint accepted")
	}
	if calls != 0 || ann.stages != 0 || ann.queries != 0 {
		t.Fatal("changed provider received disclosure/work")
	}
}
