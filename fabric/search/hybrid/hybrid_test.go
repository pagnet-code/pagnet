package hybrid

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

type retrieveFunc func(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error)

func (f retrieveFunc) Search(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	return f(ctx, r)
}

type rankFunc func(context.Context, fabric.DiscoverRequest, []fabric.Candidate) ([]fabric.Candidate, error)

func (f rankFunc) Rerank(ctx context.Context, r fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
	return f(ctx, r, cs)
}
func document(i uint64, text string) fabric.SearchDocument {
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
	return fabric.SearchDocument{Ref: ref, Revision: "r1", ShortDescription: text, Kind: "actor.agent"}
}
func gateAll(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) (GateResult, error) {
	return GateResult{"caller:alice", "policy1", cs}, nil
}
func lexical(t *testing.T, docs ...fabric.SearchDocument) Provider {
	t.Helper()
	b, e := search.New(search.Config{})
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range docs {
		if e = b.Upsert(context.Background(), d); e != nil {
			t.Fatal(e)
		}
	}
	return Provider{ID: "lexical", Version: "v1", Retriever: b, CurrentRevision: b.IndexRevision}
}
func staticProvider(id string, cs []fabric.Candidate, rev *fabric.Revision, calls *int) Provider {
	return Provider{ID: id, Version: "v1", Retriever: retrieveFunc(func(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
		if calls != nil {
			*calls++
		}
		out := clone(cs)
		if len(out) > r.Limit {
			out = out[:r.Limit]
		}
		return fabric.DiscoverResult{Candidates: out, IndexRevision: *rev}, nil
	}), CurrentRevision: func(context.Context) (fabric.Revision, error) { return *rev, nil }}
}
func requireBackend(t *testing.T, c Config) *Backend {
	t.Helper()
	b, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestLexicalOnlyDelegatesExactPagingWithoutModels(t *testing.T) {
	ctx := context.Background()
	p := lexical(t, document(1, "common"), document(2, "common"), document(3, "common"))
	b := requireBackend(t, Config{Lexical: p, Gate: gateAll})
	r := fabric.DiscoverRequest{Query: "common", Limit: 1}
	for page := 0; page < 3; page++ {
		expected, e := p.Retriever.Search(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		got, e := b.Search(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprint(expected) != fmt.Sprint(got) {
			t.Fatal("lexical-only output changed", expected, got)
		}
		r.Cursor = got.NextCursor
	}
}
func TestHybridPagingDoesNotRepeatProvidersAndRevalidates(t *testing.T) {
	ctx := context.Background()
	rev := fabric.Revision("semantic1")
	calls, ranks := 0, 0
	cs := []fabric.Candidate{{Document: document(4, "semantic"), Score: 3}, {Document: document(3, "semantic"), Score: 2}, {Document: document(2, "common"), Score: 1}}
	semantic := staticProvider("semantic", cs, &rev, &calls)
	policy := fabric.Revision("policy1")
	scope := "alice"
	denied := false
	config := Config{Lexical: lexical(t, document(1, "common"), document(2, "common")), Semantic: &semantic, FusionLimit: 4, Gate: func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) (GateResult, error) {
		if denied && len(cs) > 0 {
			cs = cs[:len(cs)-1]
		}
		return GateResult{scope, policy, cs}, nil
	}, Reranker: &RerankProvider{ID: "rank", Version: "1", Reranker: rankFunc(func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
		ranks++
		return cs, nil
	})}}
	b := requireBackend(t, config)
	r := fabric.DiscoverRequest{Query: "common", Limit: 1}
	first, e := b.Search(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if first.NextCursor == "" {
		t.Fatal(first)
	}
	r.Cursor = first.NextCursor
	seen := map[string]bool{first.Candidates[0].Document.Ref.String(): true}
	for r.Cursor != "" {
		got, e := b.Search(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range got.Candidates {
			key := c.Document.Ref.String()
			if seen[key] {
				t.Fatal("duplicate page", key)
			}
			seen[key] = true
		}
		r.Cursor = got.NextCursor
	}
	if len(seen) != 4 || calls != 1 || ranks != 1 {
		t.Fatal("paging repeated model/retrieval", len(seen), calls, ranks)
	}
	r.Cursor = first.NextCursor
	for _, mutate := range []func(){func() { policy = "policy2" }, func() { scope = "bob" }, func() { rev = "semantic2" }, func() { denied = true }} {
		policy = "policy1"
		scope = "alice"
		rev = "semantic1"
		denied = false
		mutate()
		if _, e = b.Search(ctx, r); !errors.Is(e, ErrStaleSnapshot) {
			t.Fatal("stale authority/index accepted", e)
		}
	}
	policy = "policy1"
	scope = "alice"
	rev = "semantic1"
	denied = false
	changed := r
	changed.Query = "another"
	if _, e = b.Search(ctx, changed); !errors.Is(e, ErrStaleSnapshot) {
		t.Fatal("cross-query cursor", e)
	}
	changed = r
	changed.Cursor += "x"
	if _, e = b.Search(ctx, changed); !errors.Is(e, ErrStaleSnapshot) {
		t.Fatal("tampered cursor", e)
	}

}
func TestGatesPrecedeExternalDisclosureAndRejectInventedTargets(t *testing.T) {
	ctx := context.Background()
	rev := fabric.Revision("s1")
	semanticCalls, rankCalls := 0, 0
	visible := document(1, "common")
	hidden := document(2, "private")
	semantic := staticProvider("semantic", []fabric.Candidate{{Document: visible, Score: 2}, {Document: hidden, Score: 1}}, &rev, &semanticCalls)
	semantic.External = true
	queryApproved := false
	rankApproved := false
	gate := func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) (GateResult, error) {
		out := []fabric.Candidate{}
		for _, c := range cs {
			if c.Document.Ref != hidden.Ref {
				out = append(out, c)
			}
		}
		return GateResult{"alice", "policy1", out}, nil
	}
	config := Config{Lexical: lexical(t, visible), Semantic: &semantic, Gate: gate, DisclosureGate: func(_ context.Context, d Disclosure, _ fabric.DiscoverRequest, cs []fabric.Candidate) error {
		if d.Stage == "query" {
			if len(cs) != 0 {
				t.Fatal("query disclosure leaked candidates")
			}
			queryApproved = true
		} else {
			rankApproved = true
			for _, c := range cs {
				if c.Document.Ref == hidden.Ref {
					t.Fatal("unauthorized candidate disclosed")
				}
			}
		}
		return nil
	}, Reranker: &RerankProvider{ID: "rank", Version: "1", External: true, Reranker: rankFunc(func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
		rankCalls++
		if !queryApproved || !rankApproved {
			t.Fatal("provider before gates")
		}
		if len(cs) != 1 {
			t.Fatal(cs)
		}
		cs[0].Document.ShortDescription = "provider tried to rewrite"
		cs[0].Score = 99
		return cs, nil
	})}}
	b := requireBackend(t, config)
	result, e := b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 5})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Document.ShortDescription != "common" {
		t.Fatal("provider metadata escaped", result)
	}
	denied := errors.New("operator denied query disclosure")
	config.DisclosureGate = func(context.Context, Disclosure, fabric.DiscoverRequest, []fabric.Candidate) error { return denied }
	b = requireBackend(t, config)
	before := semanticCalls
	if _, e = b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 5}); !errors.Is(e, denied) || semanticCalls != before {
		t.Fatal("denied query reached provider", e)
	}
	for name, mutate := range map[string]func([]fabric.Candidate) []fabric.Candidate{
		"invented target":  func(cs []fabric.Candidate) []fabric.Candidate { cs[0].Document = hidden; return cs },
		"changed revision": func(cs []fabric.Candidate) []fabric.Candidate { cs[0].Document.Revision = "r2"; return cs },
		"duplicate target": func(cs []fabric.Candidate) []fabric.Candidate { return append(cs, cs[0]) },
		"NaN score":        func(cs []fabric.Candidate) []fabric.Candidate { cs[0].Score = math.NaN(); return cs },
		"Inf score":        func(cs []fabric.Candidate) []fabric.Candidate { cs[0].Score = math.Inf(1); return cs },
	} {
		t.Run(name, func(t *testing.T) {
			config.DisclosureGate = func(context.Context, Disclosure, fabric.DiscoverRequest, []fabric.Candidate) error { return nil }
			config.Reranker = &RerankProvider{ID: "rank", Version: "1", Reranker: rankFunc(func(_ context.Context, _ fabric.DiscoverRequest, cs []fabric.Candidate) ([]fabric.Candidate, error) {
				return mutate(cs), nil
			})}
			b := requireBackend(t, config)
			if _, e = b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 5}); !errors.Is(e, ErrProviderResult) {
				t.Fatal(e)
			}
		})
	}
}
func TestBoundsCancellationEvictionAndConfiguration(t *testing.T) {
	ctx := context.Background()
	rev := fabric.Revision("s1")
	cs := []fabric.Candidate{{Document: document(2, "common"), Score: 1}}
	semantic := staticProvider("semantic", cs, &rev, nil)
	config := Config{Lexical: lexical(t, document(1, "common")), Semantic: &semantic, Gate: gateAll, MaxSnapshots: 1}
	b := requireBackend(t, config)
	r := fabric.DiscoverRequest{Query: "common", Limit: 1}
	first, e := b.Search(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	second, e := b.Search(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	if second.NextCursor == first.NextCursor {
		t.Fatal("snapshot identity reused")
	}
	r.Cursor = first.NextCursor
	if _, e = b.Search(ctx, r); !errors.Is(e, ErrStaleSnapshot) {
		t.Fatal("evicted snapshot retained", e)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = b.Search(cancelCtx, fabric.DiscoverRequest{Query: "common", Limit: 1}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	config.MaxSnapshotBytes = 1
	b = requireBackend(t, config)
	if _, e = b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 1}); e == nil {
		t.Fatal("byte budget ignored")
	}
	config.MaxSnapshotBytes = 0
	config.Semantic.CurrentRevision = nil
	if _, e = New(config); e == nil {
		t.Fatal("missing current revision accepted")
	}
	config.Semantic.CurrentRevision = func(context.Context) (fabric.Revision, error) { return rev, nil }
	config.Semantic.External = true
	if _, e = New(config); e == nil {
		t.Fatal("external disclosure gate optional")
	}
	config.Semantic.External = false
	for name, mutate := range map[string]func(*Config){"NaN weight": func(c *Config) { c.SemanticWeight = math.NaN() }, "unbounded horizon": func(c *Config) { c.FusionLimit = 201 }, "unbounded cache": func(c *Config) { c.MaxSnapshots = 5000 }, "short key": func(c *Config) { c.CursorKey = []byte("short") }} {
		t.Run(name, func(t *testing.T) {
			c := config
			mutate(&c)
			if _, e = New(c); e == nil {
				t.Fatal("bad config accepted")
			}
		})
	}
}
func TestDeterministicFusionAndCrossIndexRevisionConflict(t *testing.T) {
	a := fabric.Candidate{Document: document(1, "one"), Score: 90}
	b := fabric.Candidate{Document: document(2, "two"), Score: 2}
	ranked, e := fuse([][]fabric.Candidate{{a, b}, {b, a}}, []float64{1, 1}, 60, 10)
	if e != nil {
		t.Fatal(e)
	}
	if ranked[0].Document.Ref.String() > ranked[1].Document.Ref.String() || ranked[0].Score != ranked[1].Score {
		t.Fatal("RRF tie not canonical", ranked)
	}
	changed := a
	changed.Document.Revision = "r2"
	if _, e = fuse([][]fabric.Candidate{{a}, {changed}}, []float64{1, 1}, 60, 10); !errors.Is(e, ErrProviderResult) {
		t.Fatal(e)
	}
	oversized := a
	oversized.Document.ShortDescription = strings.Repeat("x", search.MaxDocumentBytes)
	if _, e = candidateMap([]fabric.Candidate{oversized}, 1); !errors.Is(e, ErrProviderResult) {
		t.Fatal(e)
	}
}

func TestConcurrentSnapshotReadersAndBoundedWriters(t *testing.T) {
	ctx := context.Background()
	rev := fabric.Revision("semantic1")
	semantic := staticProvider("semantic", []fabric.Candidate{{Document: document(3, "semantic"), Score: 1}}, &rev, nil)
	b := requireBackend(t, Config{Lexical: lexical(t, document(1, "common"), document(2, "common")), Semantic: &semantic, Gate: gateAll, MaxSnapshots: 4})
	r := fabric.DiscoverRequest{Query: "common", Limit: 1}
	first, err := b.Search(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Cursor = first.NextCursor
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Search(ctx, r)
			if err != nil && !errors.Is(err, ErrStaleSnapshot) {
				errs <- err
			}
		}()
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: 1})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	count, bytes := b.pager.Stats()
	if count > 4 || bytes > b.config.MaxSnapshotBytes {
		t.Fatal("cache escaped limits")
	}
}
