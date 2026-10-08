package search

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// TestSearchAdversarialWorstCase is the worst-case regression: it constructs
// the corpora and queries that degrade the retrieval the most — every
// document matches every query term, so no branch can be pruned by
// eligibility, the maximum query term count (MaxQueryTerms) multiplies the
// per-document scoring cost, per-document term frequencies vary so tie
// pruning cannot skip uniform runs, and the documents carry the maximum
// length with high term frequency — and asserts the search still completes
// within a bounded budget.
//
// The test asserts two independent classes of bounds:
//  1. Structural work bounds that hold on any hardware: the hierarchy
//     traversal visits each node at most once, and per-document work stays
//     linear in the corpus (ScoredDocuments <= n, Postings <= n*terms).
//     These are the "no catastrophic degradation" proof: any super-linear
//     regression fails here before the wall-clock budget is even reached.
//  2. A locked wall-clock budget per scenario, measured under -race on the
//     CI runner class and re-locked only by a new measurement
//     (SEARCH_ADVERSARIAL_PROBE=1 reports without asserting). First clean
//     measurement (owl-deploy host, 28-core x86, GOMAXPROCS=4, -race): the
//     worst case is the 64-term match-all query at p99 ~= 351ms (32,768 docs
//     scored, 2,097,152 posting lookups); the budget is 2,000,000us, a ~5.7x
//     margin over that measurement.
const (
	adversarialCorpus    = 32768 // 2^15: 1024 full leaves, hierarchy depth 10
	adversarialTerms     = 64    // MaxQueryTerms: the maximum query term count
	adversarialLongDocs  = 4096
	adversarialLongWords = 800     // tokens per long document
	adversarialSamples   = 5       // wall-clock samples per scenario
	adversarialBudgetUS  = 2000000 // locked worst-case p99 wall-clock budget
)

var adversarialTermNames = func() []string {
	terms := make([]string, adversarialTerms)
	for i := range terms {
		terms[i] = "term" + strconv.Itoa(i)
	}
	return terms
}()

// adversarialCorpusDocs builds the worst-case corpus: every document carries
// every query term with a term frequency that varies by document (defeating
// tie pruning) and a padding run whose length varies (defeating uniform
// length normalization).
func adversarialCorpusDocs() []string {
	texts := make([]string, adversarialCorpus)
	for i := range texts {
		parts := make([]string, 0, adversarialTerms+8)
		for j := range adversarialTerms {
			tf := 1 + (i+j)%3
			for k := 0; k < tf; k++ {
				parts = append(parts, adversarialTermNames[j])
			}
		}
		for k := 0; k < i%7; k++ {
			parts = append(parts, "pad")
		}
		texts[i] = strings.Join(parts, " ")
	}
	return texts
}

func adversarialFullQuery() string { return strings.Join(adversarialTermNames, " ") }

// adversarialLongDocs builds the maximum-length-document corpus: every
// document carries the query terms at high, per-document-varying frequency
// plus a long variable tail, so every document matches and every score pays
// the full per-term cost on a maximum-length document.
func adversarialLongTexts() []string {
	longTerms := []string{"long0", "long1", "long2", "long3", "long4", "long5", "long6"}
	texts := make([]string, adversarialLongDocs)
	for i := range texts {
		parts := make([]string, 0, adversarialLongWords)
		for k := 0; k < 50+i%7; k++ {
			parts = append(parts, "common")
		}
		for j, name := range longTerms {
			for k := 0; k < 4+(i+j)%3; k++ {
				parts = append(parts, name)
			}
		}
		for k := len(parts); k < adversarialLongWords; k++ {
			parts = append(parts, "pad"+strconv.Itoa((i+k)%13))
		}
		texts[i] = strings.Join(parts, " ")
	}
	return texts
}

func adversarialLongQuery() string {
	return "common long0 long1 long2 long3 long4 long5 long6"
}

type adversarialScenario struct {
	name        string
	query       string
	operator    Operator
	docCount    int
	termCount   int
	description string
}

func TestSearchAdversarialWorstCase(t *testing.T) {
	probe := os.Getenv("SEARCH_ADVERSARIAL_PROBE") == "1"
	ctx := context.Background()
	b := newBackend(t)
	if err := applyDocuments(ctx, b, textsToDocs(adversarialCorpusDocs())); err != nil {
		t.Fatal(err)
	}
	fullQuery := adversarialFullQuery()
	scenarios := []adversarialScenario{
		{
			name:        "match-all-64-terms-or",
			query:       fullQuery,
			operator:    OR,
			docCount:    adversarialCorpus,
			termCount:   adversarialTerms,
			description: "every document matches every one of the 64 query terms (OR): no eligibility pruning, max term count, per-doc tf varies",
		},
		{
			name:        "match-all-single-term-or",
			query:       "term0",
			operator:    OR,
			docCount:    adversarialCorpus,
			termCount:   1,
			description: "every document matches the single query term with varying tf: no tie pruning, full leaf scan",
		},
		{
			name:        "match-all-64-terms-and",
			query:       fullQuery,
			operator:    AND,
			docCount:    adversarialCorpus,
			termCount:   adversarialTerms,
			description: "every document matches all 64 terms under AND: full scan plus per-doc all-term verification",
		},
	}
	longTexts := adversarialLongTexts()
	bl := newBackend(t)
	if err := applyDocuments(ctx, bl, textsToDocs(longTexts)); err != nil {
		t.Fatal(err)
	}
	scenarios = append(scenarios, adversarialScenario{
		name:        "max-length-docs",
		query:       adversarialLongQuery(),
		operator:    OR,
		docCount:    adversarialLongDocs,
		termCount:   8,
		description: "every document is ~800 tokens long with high term frequency and matches all query terms: full per-document scoring cost at maximum length",
	})
	worst := struct {
		name    string
		latency time.Duration
	}{}
	for _, sc := range scenarios {
		backend := b
		if sc.name == "max-length-docs" {
			backend = bl
		}
		r := fabric.DiscoverRequest{Query: sc.query, Limit: 20}
		for i := 0; i < 2; i++ {
			if _, _, err := backend.SearchWithOptions(ctx, r, Options{Operator: sc.operator}); err != nil {
				t.Fatal(err)
			}
		}
		latencies := make([]time.Duration, 0, adversarialSamples)
		var work Work
		for i := 0; i < adversarialSamples; i++ {
			start := time.Now()
			_, w, err := backend.SearchWithOptions(ctx, r, Options{Operator: sc.operator})
			if err != nil {
				t.Fatal(err)
			}
			latencies = append(latencies, time.Since(start))
			work = w
		}
		p99 := maxDuration(latencies)
		t.Logf("adversarial: %s n=%d terms=%d %s: p99=%s scored=%d nodes=%d leafSlots=%d postings=%d",
			sc.name, sc.docCount, sc.termCount, sc.description, p99, work.ScoredDocuments, work.Nodes, work.LeafSlots, work.Postings)
		// Structural bounds: the traversal is a single best-first walk of the
		// hierarchy (each node is pushed at most once, so visits are bounded
		// by the node count of a complete binary tree over the leaf spans)
		// and the per-document work is linear in the corpus.
		leaves := nextPow2((uint64(sc.docCount) + leafSize - 1) / leafSize)
		if work.Nodes > 2*leaves {
			t.Fatalf("%s: hierarchy visited %d times, bound is %d (a node cannot be pushed twice)", sc.name, work.Nodes, 2*leaves)
		}
		if work.ScoredDocuments > uint64(sc.docCount) {
			t.Fatalf("%s: scored %d documents from a corpus of %d", sc.name, work.ScoredDocuments, sc.docCount)
		}
		if work.LeafSlots > leafSize*leaves {
			t.Fatalf("%s: scanned %d leaf slots, bound is %d", sc.name, work.LeafSlots, leafSize*leaves)
		}
		if work.Postings > uint64(sc.docCount)*uint64(sc.termCount) {
			t.Fatalf("%s: %d posting lookups, bound is %d (n*terms)", sc.name, work.Postings, uint64(sc.docCount)*uint64(sc.termCount))
		}
		if p99 > worst.latency {
			worst = struct {
				name    string
				latency time.Duration
			}{sc.name, p99}
		}
		if !probe && p99 > time.Duration(adversarialBudgetUS)*time.Microsecond {
			t.Fatalf("%s: worst-case p99 %s exceeds the locked budget of %dµs; remeasure with SEARCH_ADVERSARIAL_PROBE=1 before re-locking", sc.name, p99, adversarialBudgetUS)
		}
	}
	t.Logf("adversarial: worst case %s at p99=%s (budget %dµs)", worst.name, worst.latency, adversarialBudgetUS)
}

// textsToDocs wraps deterministic texts into the corpus's document shape,
// with the same kind/provider/tag profile as the rest of the test corpus.
func textsToDocs(texts []string) []fabric.SearchDocument {
	docs := make([]fabric.SearchDocument, len(texts))
	for i := range docs {
		docs[i] = doc(uint64(i+1), texts[i])
	}
	return docs
}

func maxDuration(d []time.Duration) time.Duration {
	m := d[0]
	for _, x := range d[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func nextPow2(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	p := uint64(1)
	for p < n {
		p *= 2
	}
	return p
}
