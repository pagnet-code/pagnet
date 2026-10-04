package search

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in measured harness keeps million-document resource use out of ordinary
// tests. It never uses latency as a substitute for visited-work evidence.
// SEARCH_SCALE=1 SEARCH_SCALE_SIZES=10000,100000,1000000 go test -run TestScaleHarness -v ./fabric/search
func TestScaleHarness(t *testing.T) {
	if os.Getenv("SEARCH_SCALE") == "" {
		t.Skip("set SEARCH_SCALE=1 for 10k/100k/1M measured oracle harness")
	}
	sizes := []int{10000, 100000, 1000000}
	if value := os.Getenv("SEARCH_SCALE_SIZES"); value != "" {
		sizes = nil
		for _, part := range strings.Split(value, ",") {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || uint64(n) > MaxDocuments {
				t.Fatal("invalid scale size")
			}
			sizes = append(sizes, n)
		}
	}
	ctx := context.Background()
	for _, n := range sizes {
		for _, layout := range []string{"uniform", "skew"} {
			runtime.GC()
			func() {
				docs := make([]fabric.SearchDocument, n)
				for i := range docs {
					text := "common filler"
					if layout == "skew" {
						text = "common " + strings.Repeat("filler ", 20)
						if i >= n-32 {
							text = strings.Repeat("common ", 10) + "filler"
						}
						if i%997 == 0 {
							text += " rare"
						}
					}
					docs[i] = doc(uint64(n-i-1), text)
					if i%101 == 0 {
						docs[i].Provider = "selective"
					}
				}
				b := newBackend(t)
				start := time.Now()
				publication := PublicationWork{}
				for offset := 0; offset < len(docs); offset += MaxBatchDocuments {
					end := offset + MaxBatchDocuments
					if end > len(docs) {
						end = len(docs)
					}
					prepared, err := b.Prepare(ctx, Batch{Upserts: docs[offset:end]})
					if err != nil {
						t.Fatal(err)
					}
					if err = b.Publish(ctx, prepared, nil); err != nil {
						t.Fatal(err)
					}
					w := prepared.Work
					publication.Documents += w.Documents
					publication.Terms += w.Terms
					publication.HierarchyNodes += w.HierarchyNodes
					publication.SummaryUpdates += w.SummaryUpdates
					publication.EncodedBytes += w.EncodedBytes
				}
				build := time.Since(start)
				runtime.GC()
				cases := []struct {
					name, query string
					filters     fabric.SearchFilters
				}{{"common", "common", fabric.SearchFilters{}}, {"common-selective", "common", fabric.SearchFilters{Providers: []string{"selective"}}}, {"common-rare-and", "common rare", fabric.SearchFilters{}}}
				for _, item := range cases {
					r := fabric.DiscoverRequest{Query: item.query, Limit: 20, Filters: item.filters}
					op := OR
					if item.name == "common-rare-and" {
						op = AND
					}
					want := oracle(docs, r, b.parameters, op)
					if len(want) > 20 {
						want = want[:20]
					}
					var latency time.Duration
					var work Work
					for repeat := 0; repeat < 3; repeat++ {
						start = time.Now()
						result, w, err := b.SearchWithOptions(ctx, r, Options{Operator: op})
						if err != nil {
							t.Fatal(err)
						}
						latency += time.Since(start)
						work = w
						equalHits(t, result.Candidates, want)
					}
					if layout == "uniform" && item.name == "common" {
						if work.ScoredDocuments > 64 || work.Nodes > uint64(4*(strconv.IntSize+20)) || work.TiePrunes == 0 {
							t.Fatalf("uniform nonpruning at%d: %s", n, work)
						}
					}
					row := struct {
						Corpus               string
						N                    int
						Query                string
						BuildMS, QueryMeanMS float64
						Publication          PublicationWork
						Work                 Work
					}{layout, n, item.name, float64(build.Microseconds()) / 1000, float64(latency.Microseconds()) / 3000, publication, work}
					raw, _ := json.Marshal(row)
					fmt.Println(string(raw))
				}
			}()
		}
	}
}
