// Package conformance is the swappability gate for fabric.SearchBackend.
//
// A backend is conformant when a factory that constructs a FRESH instance
// passes every case in RunConformance. The suite exercises only the
// mandatory fabric.SearchBackend surface (Upsert/Delete/Search/Stats) plus
// the optional OperatorSearcher capability: the contract's default operator
// is OR, and a backend that offers the AND operator must expose it through
// OperatorSearcher for the AND-vs-OR set-relation case to verify it.
package conformance

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

// OperatorSearcher is the optional explicit-operator capability. The
// reference lexical backend satisfies it structurally; the conformance gate
// verifies the AND-vs-OR set relation whenever the candidate implements it.
type OperatorSearcher interface {
	SearchWithOptions(context.Context, fabric.DiscoverRequest, search.Options) (fabric.DiscoverResult, search.Work, error)
}

// RunConformance verifies the fabric.SearchBackend contract against every
// fresh backend the factory produces. Each case runs in its own subtest on a
// fresh instance, so a failure identifies both the case and the exact
// contract violation.
func RunConformance(t *testing.T, factory func() fabric.SearchBackend) {
	t.Helper()
	fresh := func() fabric.SearchBackend {
		t.Helper()
		return factory()
	}
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, b fabric.SearchBackend)
	}{
		{"UpsertReadConsistency", caseUpsertReadConsistency},
		{"DeleteRemovesDocument", caseDeleteRemovesDocument},
		{"BM25RankingProperties", caseBM25RankingProperties},
		{"PaginationNoDuplicatesNoGaps", casePagination},
		{"FiltersNarrowResults", caseFilters},
		{"AndVsOrSetRelation", caseAndVsOr},
		{"EmptyCorpus", caseEmptyCorpus},
		{"StatsConsistency", caseStats},
		{"InvalidInputsRejected", caseInvalidInputs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, fresh())
		})
	}
}

// refFor derives a canonical endpoint reference from a stable integer, so
// the suite never depends on the backend's identity allocation.
func refFor(t *testing.T, n uint64) fabric.EndpointRef {
	t.Helper()
	pub := make([]byte, 32)
	pub[0] = 7 // conformance-domain genesis key
	domain, err := fabric.DomainNamespace(pub)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	binary.BigEndian.PutUint64(id, n)
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	ref, err := fabric.ParseEndpointRef("pagnet://" + domain + "/e/" + enc.EncodeToString(id))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func document(t *testing.T, n uint64, revision fabric.Revision, text string) fabric.SearchDocument {
	t.Helper()
	return fabric.SearchDocument{
		Ref:              refFor(t, n),
		Revision:         revision,
		ShortDescription: text,
		Kind:             "actor.agent",
		Provider:         "conformance",
		Tags:             []string{"visible"},
	}
}

func upsert(t *testing.T, b fabric.SearchBackend, d fabric.SearchDocument) {
	t.Helper()
	if err := b.Upsert(context.Background(), d); err != nil {
		t.Fatalf("Upsert %s: %v", d.Ref.String(), err)
	}
}

func searchBackend(t *testing.T, b fabric.SearchBackend, r fabric.DiscoverRequest) fabric.DiscoverResult {
	t.Helper()
	result, err := b.Search(context.Background(), r)
	if err != nil {
		t.Fatalf("Search %q: %v", r.Query, err)
	}
	return result
}

func refsOf(t *testing.T, result fabric.DiscoverResult) []fabric.EndpointRef {
	t.Helper()
	refs := make([]fabric.EndpointRef, 0, len(result.Candidates))
	for _, c := range result.Candidates {
		if _, err := fabric.ParseEndpointRef(c.Document.Ref.String()); err != nil {
			t.Fatalf("candidate carries an invalid reference: %v", err)
		}
		refs = append(refs, c.Document.Ref)
	}
	return refs
}

// caseUpsertReadConsistency: an upserted document is searchable with its
// exact ref and revision; a new revision supersedes the old content.
func caseUpsertReadConsistency(t *testing.T, b fabric.SearchBackend) {
	ctx := context.Background()
	d := document(t, 1, "v1", "zebra quartz")
	upsert(t, b, d)
	result := searchBackend(t, b, fabric.DiscoverRequest{Query: "zebra quartz", Limit: 10})
	if len(result.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d", len(result.Candidates))
	}
	if result.Candidates[0].Document.Ref != d.Ref || result.Candidates[0].Document.Revision != "v1" {
		t.Fatalf("candidate identity mismatch: %s @%s", result.Candidates[0].Document.Ref, result.Candidates[0].Document.Revision)
	}
	if result.IndexRevision == "" {
		t.Fatal("result did not carry an index revision")
	}
	// A new revision supersedes: the old-only term is gone, the new term is live.
	next := d
	next.Revision = "v2"
	next.ShortDescription = "amethyst garnet"
	upsert(t, b, next)
	if result := searchBackend(t, b, fabric.DiscoverRequest{Query: "zebra", Limit: 10}); len(result.Candidates) != 0 {
		t.Fatalf("superseded content still searchable: %d candidates", len(result.Candidates))
	}
	result = searchBackend(t, b, fabric.DiscoverRequest{Query: "amethyst", Limit: 10})
	if len(result.Candidates) != 1 || result.Candidates[0].Document.Revision != "v2" {
		t.Fatalf("new revision not searchable: %+v", result.Candidates)
	}
	stats, err := b.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Documents != 1 {
		t.Fatalf("superseding a revision must keep exactly 1 document, stats=%d", stats.Documents)
	}
}

// caseDeleteRemovesDocument: a deleted document never appears again, and a
// delete with a stale expected revision is rejected.
func caseDeleteRemovesDocument(t *testing.T, b fabric.SearchBackend) {
	ctx := context.Background()
	keep := document(t, 2, "v1", "common keep")
	gone := document(t, 3, "v1", "common vanish")
	upsert(t, b, keep)
	upsert(t, b, gone)
	if err := b.Delete(ctx, gone.Ref, "stale-revision"); err == nil {
		t.Fatal("delete with a stale expected revision was admitted")
	}
	if err := b.Delete(ctx, gone.Ref, "v1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	result := searchBackend(t, b, fabric.DiscoverRequest{Query: "common", Limit: 10})
	refs := refsOf(t, result)
	if len(refs) != 1 || refs[0] != keep.Ref {
		t.Fatalf("deleted document still returned: %+v", result.Candidates)
	}
	if result := searchBackend(t, b, fabric.DiscoverRequest{Query: "vanish", Limit: 10}); len(result.Candidates) != 0 {
		t.Fatalf("deleted term still searchable: %d candidates", len(result.Candidates))
	}
	// A repeated delete with the same expected revision is an idempotent
	// no-op (the tombstone stays in the revision ledger), and it must not
	// change the corpus.
	if err := b.Delete(ctx, gone.Ref, "v1"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	stats, err := b.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Documents != 1 {
		t.Fatalf("idempotent delete changed the corpus: stats=%d", stats.Documents)
	}
	if err := b.Delete(ctx, keep.Ref, "v1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// caseBM25RankingProperties: a document matching MORE query terms ranks
// above one matching fewer; a higher term frequency ranks above a lower one
// at comparable length; a RARE matched term dominates a common one.
func caseBM25RankingProperties(t *testing.T, b fabric.SearchBackend) {
	// More matched terms wins over fewer.
	docs := []fabric.SearchDocument{
		document(t, 10, "v1", "alpha beta"),
		document(t, 11, "v1", "alpha"),
		document(t, 12, "v1", "beta"),
	}
	for _, d := range docs {
		upsert(t, b, d)
	}
	result := searchBackend(t, b, fabric.DiscoverRequest{Query: "alpha beta", Limit: 10})
	if len(result.Candidates) != 3 || result.Candidates[0].Document.Ref != docs[0].Ref {
		t.Fatalf("multi-term document not ranked first: %+v", result.Candidates)
	}
	// Higher term frequency wins at comparable length.
	upsert(t, b, document(t, 20, "v1", "gamma gamma gamma"))
	upsert(t, b, document(t, 21, "v1", "gamma"))
	result = searchBackend(t, b, fabric.DiscoverRequest{Query: "gamma", Limit: 10})
	if len(result.Candidates) != 2 || result.Candidates[0].Document.Ref != refFor(t, 20) {
		t.Fatalf("higher-frequency document not ranked first: %+v", result.Candidates)
	}
	// A rare term dominates a common one: with 20 filler documents carrying
	// "common", the document that also carries the rare term wins the
	// "common rareterm" query despite a common-only document's frequency.
	for i := uint64(30); i < 50; i++ {
		upsert(t, b, document(t, i, "v1", "common filler"))
	}
	upsert(t, b, document(t, 50, "v1", "common rareterm"))
	upsert(t, b, document(t, 51, "v1", "common common common common common"))
	result = searchBackend(t, b, fabric.DiscoverRequest{Query: "common rareterm", Limit: 10})
	if len(result.Candidates) == 0 || result.Candidates[0].Document.Ref != refFor(t, 50) {
		t.Fatalf("rare-term document not ranked first: %+v", result.Candidates)
	}
}

// casePagination: a result set larger than the page size paginates with an
// advancing cursor, no duplicates, no gaps, and the full set reconstructable.
func casePagination(t *testing.T, b fabric.SearchBackend) {
	const n = 25
	for i := uint64(60); i < 60+n; i++ {
		upsert(t, b, document(t, i, "v1", "common"))
	}
	seen := map[fabric.EndpointRef]int{}
	cursor := ""
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("cursor never terminated")
		}
		result := searchBackend(t, b, fabric.DiscoverRequest{Query: "common", Limit: 7, Cursor: cursor})
		if len(result.Candidates) > 7 {
			t.Fatalf("page %d exceeded the limit: %d candidates", page, len(result.Candidates))
		}
		for _, ref := range refsOf(t, result) {
			if _, dup := seen[ref]; dup {
				t.Fatalf("duplicate candidate across pages: %s", ref)
			}
			seen[ref] = len(seen)
		}
		if result.NextCursor == "" {
			break
		}
		if result.NextCursor == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = result.NextCursor
	}
	if len(seen) != n {
		t.Fatalf("pagination lost documents: got %d of %d", len(seen), n)
	}
}

// caseFilters: k:/g:/p: filters narrow results to matching documents only.
func caseFilters(t *testing.T, b fabric.SearchBackend) {
	mk := func(n uint64, kind, provider string, tags []string) fabric.SearchDocument {
		d := document(t, n, "v1", "common")
		d.Kind = kind
		d.Provider = provider
		d.Tags = tags
		return d
	}
	upsert(t, b, mk(70, "actor.agent", "alpha", []string{"ops"}))
	upsert(t, b, mk(71, "service.typed", "alpha", []string{"ops"}))
	upsert(t, b, mk(72, "service.typed", "beta", []string{"billing"}))
	upsert(t, b, mk(73, "actor.agent", "beta", []string{"billing", "ops"}))
	check := func(name string, filters fabric.SearchFilters, want ...uint64) {
		t.Helper()
		result := searchBackend(t, b, fabric.DiscoverRequest{Query: "common", Limit: 10, Filters: filters})
		got := map[fabric.EndpointRef]bool{}
		for _, ref := range refsOf(t, result) {
			got[ref] = true
		}
		if len(got) != len(want) {
			t.Fatalf("%s: expected %d candidates, got %d: %+v", name, len(want), len(got), result.Candidates)
		}
		for _, n := range want {
			if !got[refFor(t, n)] {
				t.Fatalf("%s: document %d missing from %+v", name, n, result.Candidates)
			}
		}
	}
	check("kind filter", fabric.SearchFilters{Kinds: []string{"actor.agent"}}, 70, 73)
	check("kind filter (services)", fabric.SearchFilters{Kinds: []string{"service.typed"}}, 71, 72)
	check("tag filter", fabric.SearchFilters{Tags: []string{"billing"}}, 72, 73)
	check("tag filter (ops)", fabric.SearchFilters{Tags: []string{"ops"}}, 70, 71, 73)
	check("provider filter", fabric.SearchFilters{Providers: []string{"beta"}}, 72, 73)
	check("kind+provider filter", fabric.SearchFilters{Kinds: []string{"service.typed"}, Providers: []string{"beta"}}, 72)
	check("kind+tag intersection", fabric.SearchFilters{Kinds: []string{"actor.agent"}, Tags: []string{"billing"}}, 73)
}

// caseAndVsOr: an AND query returns only documents matching ALL terms, an OR
// query returns documents matching ANY term, and the AND set is a subset of
// the OR set. Requires the optional OperatorSearcher capability.
func caseAndVsOr(t *testing.T, b fabric.SearchBackend) {
	upsert(t, b, document(t, 80, "v1", "red blue"))
	upsert(t, b, document(t, 81, "v1", "red"))
	upsert(t, b, document(t, 82, "v1", "blue"))
	// AND needs the optional capability; the contract default is OR.
	or := searchBackend(t, b, fabric.DiscoverRequest{Query: "red blue", Limit: 10})
	orSet := map[fabric.EndpointRef]bool{}
	for _, ref := range refsOf(t, or) {
		orSet[ref] = true
	}
	if len(orSet) != 3 {
		t.Fatalf("OR query must return documents matching any term: %+v", or.Candidates)
	}
	ops, ok := b.(OperatorSearcher)
	if !ok {
		t.Skip("backend does not expose the optional AND operator capability")
	}
	and, _, err := ops.SearchWithOptions(context.Background(), fabric.DiscoverRequest{Query: "red blue", Limit: 10}, search.Options{Operator: search.AND})
	if err != nil {
		t.Fatalf("AND search: %v", err)
	}
	andRefs := refsOf(t, and)
	if len(andRefs) != 1 || andRefs[0] != refFor(t, 80) {
		t.Fatalf("AND query must return only documents matching all terms: %+v", and.Candidates)
	}
	for _, ref := range andRefs {
		if !orSet[ref] {
			t.Fatalf("AND result %s is not in the OR set", ref)
		}
	}
}

// caseEmptyCorpus: searching an empty corpus returns an empty result, no error.
func caseEmptyCorpus(t *testing.T, b fabric.SearchBackend) {
	for _, query := range []string{"anything", ""} {
		result := searchBackend(t, b, fabric.DiscoverRequest{Query: query, Limit: 5})
		if len(result.Candidates) != 0 {
			t.Fatalf("empty corpus returned candidates for %q", query)
		}
	}
	stats, err := b.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Documents != 0 {
		t.Fatalf("empty corpus stats: %d", stats.Documents)
	}
	// The corpus stays empty after a rejected upsert.
	if err := b.Upsert(context.Background(), fabric.SearchDocument{Ref: fabric.EndpointRef{}, Revision: "v1", ShortDescription: "x"}); err == nil {
		t.Fatal("invalid document was admitted")
	}
	if result := searchBackend(t, b, fabric.DiscoverRequest{Query: "x", Limit: 5}); len(result.Candidates) != 0 {
		t.Fatalf("rejected document searchable: %+v", result.Candidates)
	}
}

// caseStats: Stats reports a document count consistent with upserts/deletes.
func caseStats(t *testing.T, b fabric.SearchBackend) {
	ctx := context.Background()
	expect := func(want uint64) {
		t.Helper()
		stats, err := b.Stats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Documents != want {
			t.Fatalf("stats=%d, want %d", stats.Documents, want)
		}
	}
	expect(0)
	for i := uint64(90); i < 95; i++ {
		upsert(t, b, document(t, i, "v1", "common"))
	}
	expect(5)
	// Superseding a revision is not a new document.
	d := document(t, 90, "v2", "common")
	upsert(t, b, d)
	expect(5)
	if err := b.Delete(ctx, d.Ref, "v2"); err != nil {
		t.Fatal(err)
	}
	expect(4)
	if err := b.Delete(ctx, refFor(t, 91), "v1"); err != nil {
		t.Fatal(err)
	}
	expect(3)
}

// caseInvalidInputsRejected: unsupported query syntax and out-of-bounds
// requests are rejected, never silently answered.
func caseInvalidInputs(t *testing.T, b fabric.SearchBackend) {
	ctx := context.Background()
	upsert(t, b, document(t, 99, "v1", "common"))
	for _, query := range []string{`field:value`, `"phrase"`, "bad\x00query"} {
		if _, err := b.Search(ctx, fabric.DiscoverRequest{Query: query, Limit: 5}); !errors.Is(err, search.ErrUnsupportedQuery) {
			t.Fatalf("query %q: want ErrUnsupportedQuery, got %v", query, err)
		}
	}
	for _, limit := range []int{0, 101, -1} {
		if _, err := b.Search(ctx, fabric.DiscoverRequest{Query: "common", Limit: limit}); err == nil {
			t.Fatalf("limit %d was admitted", limit)
		}
	}
	if err := b.Upsert(ctx, fabric.SearchDocument{Ref: refFor(t, 98), Revision: "v1", ShortDescription: "common", Kind: "not a kind!!"}); err == nil {
		t.Fatal("document with an invalid kind was admitted")
	}
	if err := b.Delete(ctx, refFor(t, 98), "v1"); !isNotFound(err) {
		t.Fatalf("deleting an unknown document: %v", err)
	}
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var fabricError *fabric.Error
	if errors.As(err, &fabricError) {
		return fabricError.Code == fabric.CodeNotFound
	}
	return false
}
