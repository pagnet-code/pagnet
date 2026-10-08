package search

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

// TestSearchPerformanceTargets is the locked 10k/100k/1M p99 search gate.
//
// The budgets are explicit measured values, not arbitrary constants. First
// clean measurement on the CI runner class (self-hosted owl-deploy host,
// 28-core x86, GOMAXPROCS=4) under -race instrumentation — the slowest
// supported execution mode, so the same numeric budget also bounds the
// non-race CI step and ordinary runs. Worst measured p99 per size (all from
// the "common" query with the provider=selective filter, the slowest shape):
//
//	corpus      measured p99 (-race)   locked budget
//	10,000      1,369µs                3,000µs
//	100,000     7,200µs                15,000µs
//	1,000,000   7,423µs                15,000µs
//
// Re-locking a budget requires a new measurement on that hardware class;
// SEARCH_PERF_SIZES trims the size list for local probes and
// SEARCH_PERF_PROBE=1 reports measurements without asserting, which is how a
// new measurement is produced.
//
// The corpus is deterministic (fixed modulo-based term placement) and the
// queries span the selectivity extremes: a term in every document, a rare
// term, their AND intersection, and a provider-filtered common term.
const (
	perfP99Target10kUS  = 3000  // p99 search latency budget at 10,000 documents
	perfP99Target100kUS = 15000 // p99 search latency budget at 100,000 documents
	perfP99Target1MUS   = 15000 // p99 search latency budget at 1,000,000 documents
	perfSamples         = 100   // latency samples per query shape
	perfWarmup          = 20    // discarded warm-up queries per shape
)

func perfQueryShapes() []struct {
	name, query string
	filters     []string
	operator    Operator
} {
	return []struct {
		name, query string
		filters     []string
		operator    Operator
	}{
		{"common-term", "common", nil, OR},
		{"common-rare-or", "common rare", nil, OR},
		{"common-rare-and", "common rare", nil, AND},
		{"common-filtered", "common", []string{"selective"}, OR},
	}
}

// perfDocuments is the deterministic publication unit: every document carries
// the common term; half carry "even", a third carry "third", one per 997
// carries "rare", one per 101 comes from the "selective" provider, and the
// padding run length varies with the index so document lengths (and therefore
// BM25 norms) are not uniform.
func perfDocuments(n int) []fabric.SearchDocument {
	docs := make([]fabric.SearchDocument, n)
	for i := range docs {
		terms := []string{"common"}
		if i%2 == 0 {
			terms = append(terms, "even")
		}
		if i%3 == 0 {
			terms = append(terms, "third")
		}
		if i%997 == 0 {
			terms = append(terms, "rare")
		}
		for j := 0; j < 1+i%5; j++ {
			terms = append(terms, "pad"+strconv.Itoa(j%3))
		}
		docs[i] = doc(uint64(n-i-1), strings.Join(terms, " "))
		if i%101 == 0 {
			docs[i].Provider = "selective"
		}
	}
	return docs
}

// perfTargetUS returns the locked p99 budget for a corpus size.
func perfTargetUS(n int) int {
	switch {
	case n <= 10000:
		return perfP99Target10kUS
	case n <= 100000:
		return perfP99Target100kUS
	default:
		return perfP99Target1MUS
	}
}

func TestSearchPerformanceTargets(t *testing.T) {
	sizes := []int{10000, 100000, 1000000}
	if value := os.Getenv("SEARCH_PERF_SIZES"); value != "" {
		sizes = nil
		for _, part := range strings.Split(value, ",") {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || uint64(n) > MaxDocuments {
				t.Fatalf("invalid SEARCH_PERF_SIZES entry %q", part)
			}
			sizes = append(sizes, n)
		}
	}
	probe := os.Getenv("SEARCH_PERF_PROBE") == "1"
	ctx := context.Background()
	for _, n := range sizes {
		runtime.GC()
		docs := perfDocuments(n)
		b := newBackend(t)
		buildStart := time.Now()
		if err := applyDocuments(ctx, b, docs); err != nil {
			t.Fatal(err)
		}
		build := time.Since(buildStart)
		runtime.GC()
		t.Logf("perf: corpus=%d build=%s", n, build)
		for _, shape := range perfQueryShapes() {
			r := fabric.DiscoverRequest{Query: shape.query, Limit: 20}
			if len(shape.filters) > 0 {
				r.Filters.Providers = shape.filters
			}
			options := Options{Operator: shape.operator}
			for i := 0; i < perfWarmup; i++ {
				if _, _, err := b.SearchWithOptions(ctx, r, options); err != nil {
					t.Fatal(err)
				}
			}
			latencies := make([]time.Duration, 0, perfSamples)
			var work Work
			for i := 0; i < perfSamples; i++ {
				start := time.Now()
				_, w, err := b.SearchWithOptions(ctx, r, options)
				if err != nil {
					t.Fatal(err)
				}
				latencies = append(latencies, time.Since(start))
				work = w
			}
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			p99 := latencies[len(latencies)*99/100]
			mean := time.Duration(0)
			for _, d := range latencies {
				mean += d
			}
			mean /= time.Duration(len(latencies))
			target := perfTargetUS(n)
			row, _ := json.Marshal(struct {
				Corpus      int
				Query       string
				Operator    Operator
				MeanUS      int64
				P99US       int64
				TargetUS    int
				ThroughputK float64
				ScoredDocs  uint64
				Nodes       uint64
			}{n, shape.query, shape.operator, int64(mean) / 1000, int64(p99) / 1000, target, float64(1) / mean.Seconds() / 1000, work.ScoredDocuments, work.Nodes})
			t.Logf("perf: %s", row)
			if probe {
				continue
			}
			if p99 > time.Duration(target)*time.Microsecond {
				t.Fatalf("corpus=%d query=%q op=%s: p99 %s exceeds the locked budget of %dµs (mean %s); remeasure on the runner class with SEARCH_PERF_PROBE=1 before re-locking",
					n, shape.query, shape.operator, p99, target, mean)
			}
		}
	}
}

// BenchmarkSearchPerf10k/100k/1M report throughput for the common-term
// query at each corpus size. They build their own deterministic corpus and
// are the -bench surface for the same shapes the p99 gate asserts.
func BenchmarkSearchPerf10k(b *testing.B)  { benchmarkPerfCorpus(b, 10000) }
func BenchmarkSearchPerf100k(b *testing.B) { benchmarkPerfCorpus(b, 100000) }
func BenchmarkSearchPerf1M(b *testing.B)   { benchmarkPerfCorpus(b, 1000000) }

func benchmarkPerfCorpus(b *testing.B, n int) {
	ctx := context.Background()
	backend := newBackend(b)
	if err := applyDocuments(ctx, backend, perfDocuments(n)); err != nil {
		b.Fatal(err)
	}
	r := fabric.DiscoverRequest{Query: "common", Limit: 20}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := backend.SearchWithOptions(ctx, r, Options{}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
