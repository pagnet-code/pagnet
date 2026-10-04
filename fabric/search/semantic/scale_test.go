package semantic

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func hitID(ref string) int {
	s := ref[strings.LastIndex(ref, "/")+1:]
	raw, e := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding).DecodeString(s)
	if e != nil {
		panic(e)
	}
	return int(binary.BigEndian.Uint64(raw)) - 1
}

// TestANNScaleHarness builds real HNSW in an explicitly selected development
// Qdrant endpoint. The source vector generator/exhaustive scorer tests ANN
// retrieval quality only, never claims semantic language relevance.
func TestANNScaleHarness(t *testing.T) {
	if os.Getenv("ANN_SCALE") == "" {
		t.Skip("explicit ANN_SCALE and QDRANT_TEST_URL required")
	}
	sizes := []int{10000, 100000, 1000000}
	if raw := os.Getenv("ANN_SCALE_SIZES"); raw != "" {
		sizes = nil
		for _, s := range strings.Split(raw, ",") {
			n, e := strconv.Atoi(s)
			if e != nil || n < 100 || n > 1000000 {
				t.Fatal("invalid bounded verification size")
			}
			sizes = append(sizes, n)
		}
	}
	q := qdrant(t, 32)
	// Explicit bulk-maintenance budget; hot queries retain their own 15s deadline.
	q.http.client.Timeout = 2 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	vectors := [][]float32{}
	rng := rand.New(rand.NewSource(73))
	start := time.Now()
	for _, n := range sizes {
		for len(vectors) < n {
			end := len(vectors) + 128
			if end > n {
				end = n
			}
			points := make([]VectorPoint, 0, end-len(vectors))
			for len(vectors) < end {
				i := len(vectors)
				v := make([]float32, 32)
				for d := range v {
					v[d] = rng.Float32()*2 - 1
				}
				vectors = append(vectors, v)
				doc := document(uint64(i+1), "scale compact role")
				provider := "common"
				if i%997 == 0 {
					provider = "selective"
				}
				kind := "actor.agent"
				if i%2 == 0 {
					kind = "service.application"
				}
				points = append(points, VectorPoint{Key: pointKey(EmbeddingIdentity{Provider: "scale", Model: "uniform32", Version: "v1", Dimensions: 32}, doc.Ref, doc.Revision), Ref: doc.Ref, Revision: doc.Revision, Vector: v, Domain: doc.Ref.Domain(), Kind: kind, Provider: provider, Tags: []string{"scale"}, From: 1, Model: "scale-uniform32-v1"})
			}
			if e := q.Stage(ctx, 1, points, nil); e != nil {
				t.Fatal(e)
			}
		}
		readyWithin(t, q, 8*time.Minute)
		build := time.Since(start)
		cases := []struct {
			name     string
			query    VectorQuery
			eligible func(int) bool
		}{
			{"broad", VectorQuery{Vector: vectors[17], Generation: 1, Model: "scale-uniform32-v1", Limit: 10, Ef: 512}, func(int) bool { return true }},
			{"selective", VectorQuery{Vector: vectors[17], Generation: 1, Model: "scale-uniform32-v1", Providers: []string{"selective"}, Limit: 10, Ef: 512}, func(i int) bool { return i%997 == 0 }},
			{"intersection", VectorQuery{Vector: vectors[17], Generation: 1, Model: "scale-uniform32-v1", Providers: []string{"selective"}, Kinds: []string{"service.application"}, Tags: []string{"scale"}, Limit: 10, Ef: 512}, func(i int) bool { return i%997 == 0 && i%2 == 0 }},
		}
		for _, c := range cases {
			// Independent exhaustive cosine top10, outside timed remote calls. O(N)
			// oracle work is explicit verification, not a backend candidate fallback.
			type neighbor struct {
				id    int
				score float64
			}
			oracle := []neighbor{}
			qnorm := 0.0
			for _, v := range c.query.Vector {
				qnorm += float64(v) * float64(v)
			}
			eligible := 0
			for i, v := range vectors {
				if !c.eligible(i) {
					continue
				}
				eligible++
				dot, norm := 0.0, 0.0
				for d, x := range v {
					dot += float64(x) * float64(c.query.Vector[d])
					norm += float64(x) * float64(x)
				}
				candidate := neighbor{i, dot / math.Sqrt(norm*qnorm)}
				at := sort.Search(len(oracle), func(j int) bool {
					return oracle[j].score < candidate.score || oracle[j].score == candidate.score && oracle[j].id > candidate.id
				})
				oracle = append(oracle, neighbor{})
				copy(oracle[at+1:], oracle[at:])
				oracle[at] = candidate
				if len(oracle) > 10 {
					oracle = oracle[:10]
				}
			}
			correct := map[int]bool{}
			for _, o := range oracle {
				correct[o.id] = true
			}
			latencies := make([]float64, 30)
			recall := 0.0
			cpu := uint64(0)
			reported := true
			for i := range latencies {
				before := time.Now()
				result, e := q.Query(ctx, c.query)
				latencies[i] = float64(time.Since(before).Nanoseconds()) / 1e6
				if e != nil {
					t.Fatal(e)
				}
				matches := 0
				for _, h := range result.Hits {
					id := hitID(h.Ref.String())
					if id < 0 || id >= n || !c.eligible(id) {
						t.Fatal("incorrect indexed filter result")
					}
					if correct[id] {
						matches++
					}
				}
				if len(oracle) > 0 {
					recall += float64(matches) / float64(len(oracle))
				}
				reported = reported && result.Usage.Reported
				cpu += result.Usage.CPU
			}
			sort.Float64s(latencies)
			recall /= float64(len(latencies))
			if !reported {
				t.Fatal("enable hardware_reporting on explicit verification ANN endpoint")
			}
			if recall < .7 {
				t.Fatalf("measured ANN recall regression n%d query%s recall%.3f", n, c.name, recall)
			}
			t.Logf("ANN n=%d shape=uniform32 query=%s eligible=%d ef512 recall@10=%.3f samples30 p50ms=%.3f p95ms=%.3f p99ms=%.3f mean_cpu=%.1f indexed_build_ms=%.0f", n, c.name, eligible, recall, latencies[15], latencies[28], latencies[29], float64(cpu)/30, float64(build.Milliseconds()))
		}
	}
}
