package search

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
)

func testRef(i uint64) fabric.EndpointRef {
	pub := make([]byte, 32)
	pub[0] = 1
	domain, _ := fabric.DomainNamespace(pub)
	id := make([]byte, 32)
	binary.BigEndian.PutUint64(id, i)
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	ref, err := fabric.ParseEndpointRef("pagnet://" + domain + "/e/" + enc.EncodeToString(id))
	if err != nil {
		panic(err)
	}
	return ref
}
func doc(i uint64, text string) fabric.SearchDocument {
	return fabric.SearchDocument{Ref: testRef(i), Revision: "r1", Name: "", ShortDescription: text, Kind: "actor.agent", Provider: "local", Tags: []string{"visible"}}
}
func newBackend(t testing.TB) *Backend {
	t.Helper()
	b, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Independent full-scan matcher/scorer over source documents: it never reads
// hierarchy summaries, compact index records, heaps or query-bound code.
func oracle(docs []fabric.SearchDocument, r fabric.DiscoverRequest, p Parameters, operator Operator) []fabric.Candidate {
	counts := make([]map[string]uint32, len(docs))
	lengths := make([]uint32, len(docs))
	dfs := map[string]uint64{}
	total := uint64(0)
	for i, d := range docs {
		counts[i] = map[string]uint32{}
		fields := append([]string{d.Name, d.ShortDescription}, d.Tags...)
		fields = append(fields, d.Examples...)
		for _, f := range fields {
			for _, token := range tokenize(f) {
				counts[i][token]++
				lengths[i]++
				total++
			}
		}
		for term := range counts[i] {
			dfs[term]++
		}
	}
	weights := map[string]uint32{}
	for _, token := range tokenize(r.Query) {
		weights[token]++
	}
	terms := make([]string, 0, len(weights))
	for name := range weights {
		terms = append(terms, name)
	}
	sort.Strings(terms)
	if len(terms) == 0 || len(docs) == 0 {
		return nil
	}
	avg := float64(total) / float64(len(docs))
	out := []fabric.Candidate{}
	for i, d := range docs {
		has := func(values []string, s string) bool {
			for _, v := range values {
				if v == s {
					return true
				}
			}
			return false
		}
		if len(r.Filters.Kinds) > 0 && !has(r.Filters.Kinds, d.Kind) || len(r.Filters.Providers) > 0 && !has(r.Filters.Providers, d.Provider) || len(r.Scope.Domains) > 0 && !has(r.Scope.Domains, d.Ref.Domain()) {
			continue
		}
		if len(r.Filters.Tags) > 0 {
			found := false
			for _, tag := range d.Tags {
				found = found || has(r.Filters.Tags, tag)
			}
			if !found {
				continue
			}
		}
		any, all := false, true
		score := 0.0
		for _, name := range terms {
			tf := counts[i][name]
			any = any || tf > 0
			all = all && tf > 0
			if tf > 0 {
				df := dfs[name]
				idf := math.Log1p((float64(uint64(len(docs))-df) + .5) / (float64(df) + .5))
				c := (float64(weights[name]) * idf) * (p.K1 + 1)
				norm := (1 - p.B) + p.B*(float64(lengths[i])/avg)
				score += c / (1 + (p.K1*norm)/float64(tf))
			}
		}
		if any && (operator != AND || all) {
			out = append(out, fabric.Candidate{Document: d, Score: score})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score || out[i].Score == out[j].Score && out[i].Document.Ref.String() < out[j].Document.Ref.String()
	})
	return out
}
func applyDocuments(ctx context.Context, b *Backend, docs []fabric.SearchDocument) error {
	for offset := 0; offset < len(docs); offset += MaxBatchDocuments {
		end := offset + MaxBatchDocuments
		if end > len(docs) {
			end = len(docs)
		}
		if err := b.Apply(ctx, Batch{Upserts: docs[offset:end]}); err != nil {
			return err
		}
	}
	return nil
}
func equalHits(t testing.TB, got, want []fabric.Candidate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("hit length %d != %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Document.Ref != want[i].Document.Ref || math.Float64bits(got[i].Score) != math.Float64bits(want[i].Score) {
			t.Fatalf("rank %d: %s %.17g != %s %.17g", i, got[i].Document.Ref.String(), got[i].Score, want[i].Document.Ref.String(), want[i].Score)
		}
	}
}
func TestExactOracleAndPagination(t *testing.T) {
	ctx := context.Background()
	rng := rand.New(rand.NewSource(42))
	docs := make([]fabric.SearchDocument, 300)
	for i := range docs {
		tokens := []string{}
		for n := 0; n < rng.Intn(12)+1; n++ {
			tokens = append(tokens, []string{"common", "rare", "alpha", "beta", "café", "日本"}[rng.Intn(6)])
		}
		docs[i] = doc(uint64(i), strings.Join(tokens, " "))
		if i%3 == 0 {
			docs[i].Kind = "service.typed"
			docs[i].Provider = "remote"
		}
		if i%7 == 0 {
			docs[i].Tags = []string{"other"}
		}
	}
	b := newBackend(t)
	reversed := append([]fabric.SearchDocument(nil), docs...)
	sort.Slice(reversed, func(i, j int) bool { return i > j })
	if err := b.Apply(ctx, Batch{Upserts: reversed}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operator{OR, AND} {
		for _, query := range []string{"common", "common rare", "rare rare café", "日本 beta", "missing", ""} {
			for _, filters := range []fabric.SearchFilters{{}, {Kinds: []string{"service.typed"}}, {Tags: []string{"other"}, Providers: []string{"remote"}}} {
				r := fabric.DiscoverRequest{Query: query, Limit: 7, Filters: filters}
				want := oracle(docs, r, b.parameters, op)
				all := []fabric.Candidate{}
				for {
					result, _, err := b.SearchWithOptions(ctx, r, Options{Operator: op})
					if err != nil {
						t.Fatal(err)
					}
					all = append(all, result.Candidates...)
					if result.NextCursor == "" {
						break
					}
					r.Cursor = result.NextCursor
				}
				equalHits(t, all, want)
			}
		}
	}
	r := fabric.DiscoverRequest{Query: "common", Limit: 3}
	page, err := b.Search(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	d := docs[0]
	d.Revision = "r2"
	d.ShortDescription = "updated"
	if err = b.Upsert(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.Cursor = page.NextCursor
	if _, err = b.Search(ctx, r); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale page: %v", err)
	}
}
func TestRandomMutationOracle(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	rng := rand.New(rand.NewSource(9))
	live := map[uint64]fabric.SearchDocument{}
	version := map[uint64]int{}
	for step := 0; step < 250; step++ {
		id := uint64(rng.Intn(70))
		if current, ok := live[id]; ok && rng.Intn(4) == 0 {
			if err := b.Delete(ctx, current.Ref, current.Revision); err != nil {
				t.Fatal(err)
			}
			delete(live, id)
		} else {
			version[id]++
			d := doc(id, strings.Repeat("common ", rng.Intn(4))+strings.Repeat("rare ", rng.Intn(8))+"filler")
			d.Revision = fabric.Revision(fmt.Sprintf("r%d", version[id]))
			if err := b.Upsert(ctx, d); err != nil {
				t.Fatal(err)
			}
			live[id] = d
		}
		docs := []fabric.SearchDocument{}
		for _, d := range live {
			docs = append(docs, d)
		}
		r := fabric.DiscoverRequest{Query: "common rare", Limit: 100}
		result, _, err := b.SearchWithOptions(ctx, r, Options{})
		if err != nil {
			t.Fatal(err)
		}
		equalHits(t, result.Candidates, oracle(docs, r, b.parameters, OR))
	}
}
func TestBoundsDominateExactFloatScores(t *testing.T) {
	rng := rand.New(rand.NewSource(73))
	ctx := context.Background()
	for iteration := 0; iteration < 25; iteration++ {
		parameters := Parameters{K1: rng.Float64() * 20, B: rng.Float64()}
		if iteration == 0 {
			parameters = Parameters{K1: 0, B: 1}
		}
		b, err := New(Config{Parameters: &parameters})
		if err != nil {
			t.Fatal(err)
		}
		docs := []fabric.SearchDocument{}
		for i := 0; i < 90; i++ {
			docs = append(docs, doc(uint64(i), strings.Repeat("a ", rng.Intn(20))+strings.Repeat("b ", rng.Intn(30))+"z"))
		}
		if err = applyDocuments(ctx, b, docs); err != nil {
			t.Fatal(err)
		}
		g := b.current.Load()
		terms, err := buildQuery("a a b", g.stats, &Work{})
		if err != nil {
			t.Fatal(err)
		}
		avg := float64(g.stats.totalLength) / float64(g.stats.count)
		var walk func(*node) []*indexed
		walk = func(n *node) []*indexed {
			if n == nil {
				return nil
			}
			records := []*indexed{}
			if n.leaf != nil {
				for _, d := range n.leaf {
					if d != nil {
						records = append(records, d)
					}
				}
			} else {
				records = append(walk(n.left), walk(n.right)...)
			}
			bound, _ := nodeBound(n, terms, parameters, avg, OR, &Work{})
			for _, d := range records {
				score := scoreDocument(d, terms, parameters, avg)
				if bound < score || n.minRef > d.doc.Ref.String() {
					t.Fatalf("unsafe bound %.17g < %.17g", bound, score)
				}
			}
			return records
		}
		walk(g.root)
	}
}
func TestUniformTiePruningReversedReferences(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	docs := make([]fabric.SearchDocument, 10000)
	for i := range docs {
		docs[i] = doc(uint64(len(docs)-i-1), "common")
	}
	if err := applyDocuments(ctx, b, docs); err != nil {
		t.Fatal(err)
	}
	r := fabric.DiscoverRequest{Query: "common", Limit: 20}
	got, work, err := b.SearchWithOptions(ctx, r, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := oracle(docs, r, b.parameters, OR)
	equalHits(t, got.Candidates, want[:20])
	if work.ScoredDocuments > 128 || work.Nodes > 100 || work.TiePrunes == 0 {
		t.Fatalf("uniform tie didn't skip hierarchy: %s", work)
	}
	t.Log(work.String())
}
func TestVisibilityStatsFiltersAndFinalRevocation(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	docs := []fabric.SearchDocument{doc(1, "common"), doc(2, "common common common"), doc(3, "rare")}
	if err := applyDocuments(ctx, b, docs); err != nil {
		t.Fatal(err)
	}
	v, err := b.NewVisibility(ctx, []fabric.EndpointRef{docs[0].Ref, docs[2].Ref}, "policy1")
	if err != nil {
		t.Fatal(err)
	}
	r := fabric.DiscoverRequest{Query: "common rare", Limit: 10}
	got, work, err := b.SearchWithOptions(ctx, r, Options{Visibility: v})
	if err != nil {
		t.Fatal(err)
	}
	equalHits(t, got.Candidates, oracle([]fabric.SearchDocument{docs[0], docs[2]}, r, b.parameters, OR))
	if work.ScoredDocuments != 2 {
		t.Fatalf("hidden docs scored: %s", work)
	}
	revoked := errors.New("authority revoked")
	got, _, err = b.SearchWithOptions(ctx, r, Options{Visibility: v, FinalValidate: func(context.Context, fabric.Revision) error { return revoked }})
	if !errors.Is(err, revoked) || len(got.Candidates) != 0 {
		t.Fatal("revoked results exposed")
	}
	if err = b.Upsert(ctx, doc(4, "new")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = b.SearchWithOptions(ctx, r, Options{Visibility: v}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatal("stale visibility admitted")
	}
}
func TestAtomicPublicationFailureReplayAndAliasing(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	batch := Batch{Upserts: []fabric.SearchDocument{doc(1, "first")}, UpstreamCursor: "sync:1"}
	p, err := b.Prepare(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	batch.Upserts[0].ShortDescription = "outside mutation"
	failed := errors.New("transaction failed")
	if err = b.Publish(ctx, p, func(context.Context, CommitRecord) error { return failed }); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	stats, _ := b.Stats(ctx)
	if stats.Documents != 0 || b.CurrentCursor() != "" {
		t.Fatal("failed commit became visible")
	}
	record := p.Record()
	mutated := p.Record()
	mutated.Batch.Upserts[0].ShortDescription = "changed"
	if err = b.Publish(ctx, p, func(ctx context.Context, r CommitRecord) error {
		r.Batch.Upserts[0].ShortDescription = "mutated callback"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fresh := newBackend(t)
	if err = fresh.Restore(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err = fresh.Restore(ctx, record); err != nil {
		t.Fatal("ambiguous replay", err)
	}
	mutated.SHA256 = record.SHA256
	if err = fresh.Restore(ctx, mutated); err == nil {
		t.Fatal("corrupt replay admitted")
	}
	if fresh.CurrentCursor() != "sync:1" {
		t.Fatal("cursor lost")
	}
	r := fabric.DiscoverRequest{Query: "first", Limit: 10}
	hit, err := fresh.Search(ctx, r)
	if err != nil || len(hit.Candidates) != 1 {
		t.Fatal("restored indexed content lost", err)
	}
	hit.Candidates[0].Document.Tags[0] = "outside"
	again, _ := fresh.Search(ctx, r)
	if again.Candidates[0].Document.Tags[0] != "visible" {
		t.Fatal("mutable result aliases index")
	}
}
func TestCancellationSyntaxParametersAndConcurrency(t *testing.T) {
	for _, p := range []Parameters{{math.NaN(), .75}, {math.Inf(1), .5}, {1, -1}, {1, 2}, {-1, .5}, {1001, .5}} {
		if _, err := New(Config{Parameters: &p}); err == nil {
			t.Fatal("invalid parameters admitted")
		}
	}
	b := newBackend(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Search(ctx, fabric.DiscoverRequest{Query: "x", Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, q := range []string{`"phrase"`, `field:value`} {
		if _, err := b.Search(context.Background(), fabric.DiscoverRequest{Query: q, Limit: 1}); !errors.Is(err, ErrUnsupportedQuery) {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Go(func() {
			for i := 0; i < 80; i++ {
				_, err := b.Search(context.Background(), fabric.DiscoverRequest{Query: "common", Limit: 5})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	for i := 0; i < 80; i++ {
		if err := b.Upsert(context.Background(), doc(uint64(i), "common")); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func FuzzRestoreRejectsCorruption(f *testing.F) {
	f.Add([]byte(`{"format":1,"sha256":"wrong"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		var record CommitRecord
		if json.Unmarshal(data, &record) != nil {
			return
		}
		b := newBackend(t)
		if err := b.Restore(context.Background(), record); err == nil {
			t.Fatal("unsigned/corrupt record admitted")
		}
	})
}

func TestPreparedCASCommitCancellationAndReplay(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	first, _ := b.Prepare(ctx, Batch{Upserts: []fabric.SearchDocument{doc(1, "common")}, UpstreamCursor: "1"})
	second, _ := b.Prepare(ctx, Batch{Upserts: []fabric.SearchDocument{doc(2, "common")}, UpstreamCursor: "2"})
	cancelled, cancel := context.WithCancel(ctx)
	if err := b.Publish(cancelled, first, func(context.Context, CommitRecord) error { cancel(); return nil }); err != nil {
		t.Fatal("durable success must publish despite late cancellation", err)
	}
	called := false
	if err := b.Publish(ctx, second, func(context.Context, CommitRecord) error { called = true; return nil }); !errors.Is(err, ErrStaleGeneration) || called {
		t.Fatal("stale prepared record reached commit")
	}
	if b.CurrentCursor() != "1" {
		t.Fatal("committed cursor missing")
	}
	older := doc(1, "common")
	newer := older
	newer.Revision = "r2"
	newer.ShortDescription = "new"
	if err := b.Upsert(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, newer.Ref, newer.Revision); err != nil {
		t.Fatal(err)
	}
	if err := b.Upsert(ctx, older); err != nil {
		t.Fatal("already committed old revision replay", err)
	}
	stats, _ := b.Stats(ctx)
	if stats.Documents != 0 {
		t.Fatal("old revision resurrected retired descriptor")
	}
	newer.Revision = "r3"
	if err := b.Upsert(ctx, newer); err != nil {
		t.Fatal(err)
	}
	newer.ShortDescription = "conflicting body"
	if err := b.Upsert(ctx, newer); !errors.Is(err, ErrRevisionConflict) {
		t.Fatal("same revision changed content admitted", err)
	}
}
func TestEmptyTombstonesExpansionAndNoObsoleteSummary(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	for i := uint64(0); i < 32; i++ {
		d := doc(i, "old")
		if err := b.Upsert(ctx, d); err != nil {
			t.Fatal(err)
		}
		if err := b.Delete(ctx, d.Ref, d.Revision); err != nil {
			t.Fatal(err)
		}
	}
	if b.current.Load().root != nil || b.current.Load().stats.df != nil {
		t.Fatal("obsolete summaries/stat terms retained")
	}
	if err := b.Upsert(ctx, doc(32, "new")); err != nil {
		t.Fatal(err)
	}
	result, err := b.Search(ctx, fabric.DiscoverRequest{Query: "new", Limit: 1})
	if err != nil || len(result.Candidates) != 1 {
		t.Fatal("empty physical range could not grow", err)
	}
}
func TestPublicationBoundsAndInputCancellation(t *testing.T) {
	b := newBackend(t)
	docs := make([]fabric.SearchDocument, MaxBatchDocuments+1)
	if _, err := b.Prepare(context.Background(), Batch{Upserts: docs}); err == nil {
		t.Fatal("unbounded publication admitted")
	}
	d := doc(1, strings.Repeat("x", MaxDocumentBytes))
	if err := b.Upsert(context.Background(), d); err == nil {
		t.Fatal("oversized compact document admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Prepare(ctx, Batch{Upserts: []fabric.SearchDocument{doc(1, "common")}}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stats, _ := b.Stats(context.Background())
	if stats.Documents != 0 {
		t.Fatal("cancelled prepare changed state")
	}
}
func TestIndexedFilterIntersectionsLooseBoundsRemainExact(t *testing.T) {
	ctx := context.Background()
	b := newBackend(t)
	docs := []fabric.SearchDocument{}
	for i := uint64(0); i < 128; i++ {
		d := doc(i, "common")
		if i%2 == 0 {
			d.Kind = "service.typed"
			d.Provider = "left"
		} else {
			d.Kind = "actor.agent"
			d.Provider = "right"
		}
		docs = append(docs, d)
	}
	if err := applyDocuments(ctx, b, docs); err != nil {
		t.Fatal(err)
	}
	request := fabric.DiscoverRequest{Query: "common", Limit: 20, Filters: fabric.SearchFilters{Kinds: []string{"service.typed"}, Providers: []string{"right"}}}
	result, work, err := b.SearchWithOptions(ctx, request, Options{})
	if err != nil || len(result.Candidates) != 0 {
		t.Fatal("cross-filter unauthorized result", err)
	}
	if work.LeafSlots != 128 || work.ScoredDocuments != 0 {
		t.Fatalf("loose intersecting metadata bounds work must stay explicit: %s", work)
	}
	t.Log("intentionally adverse empty intersection", work.String())
}
func TestIndependentFloatNeighbourParameterOracle(t *testing.T) {
	ctx := context.Background()
	docs := []fabric.SearchDocument{doc(1, "a a a b filler filler filler filler"), doc(2, "a b b b"), doc(3, "a b")}
	for _, p := range []Parameters{{math.SmallestNonzeroFloat64, 0}, {math.Nextafter(1.2, math.Inf(1)), math.Nextafter(1, 0)}, {0, 0}, {1000, 1}} {
		b, err := New(Config{Parameters: &p})
		if err != nil {
			t.Fatal(err)
		}
		if err = applyDocuments(ctx, b, docs); err != nil {
			t.Fatal(err)
		}
		r := fabric.DiscoverRequest{Query: "b a b", Limit: 100}
		result, _, err := b.SearchWithOptions(ctx, r, Options{})
		if err != nil {
			t.Fatal(err)
		}
		equalHits(t, result.Candidates, oracle(docs, r, p, OR))
	}
}
