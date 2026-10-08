package search

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

// TestRelevanceCorpus loads the committed relevance fixture
// (testdata/relevance_corpus.json, >= 50 expert-graded cases) and asserts the
// backend's ranking matches the grades: for every case the top-1 candidate is
// the most-relevant document (the unique grade-2 document), every grade-2
// document is retrieved within the case's limit, filters genuinely narrow the
// returned set, and per-case NDCG@limit / precision@limit stay above the
// locked thresholds. The fixture is CI data: committed, not generated.
const (
	corpusMinCases         = 50
	corpusMinScaleCases    = 3 // cases with >= 40 documents
	corpusMinSingleTerm    = 5
	corpusMinAND           = 5
	corpusMinFiltered      = 5
	corpusCaseMinDocs      = 4
	corpusPerCaseNDCG      = 0.80 // per-case floor
	corpusPerCasePrecision = 0.50 // per-case floor: share of returned candidates that are grade >= 1
	corpusMeanNDCG         = 0.85 // aggregate floor
	corpusMeanPrecision    = 0.60 // aggregate floor
)

type corpusDocument struct {
	Name             string   `json:"name"`
	ShortDescription string   `json:"shortDescription"`
	Kind             string   `json:"kind"`
	Provider         string   `json:"provider"`
	Tags             []string `json:"tags"`
	Examples         []string `json:"examples"`
	Grade            int      `json:"grade"`
}

type corpusCase struct {
	ID        string               `json:"id"`
	Query     string               `json:"query"`
	Operator  string               `json:"operator"`
	Limit     int                  `json:"limit"`
	Filters   fabric.SearchFilters `json:"filters"`
	Documents []corpusDocument     `json:"documents"`
}

type corpusFixture struct {
	Description string       `json:"description"`
	Cases       []corpusCase `json:"cases"`
}

func loadRelevanceCorpus(t *testing.T) corpusFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/relevance_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx corpusFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) < corpusMinCases {
		t.Fatalf("relevance corpus has %d cases, the gate requires %d", len(fx.Cases), corpusMinCases)
	}
	ids := map[string]bool{}
	scale, singleTerm, and, filtered := 0, 0, 0, 0
	for i, c := range fx.Cases {
		if c.ID == "" || ids[c.ID] {
			t.Fatalf("case %d: missing or duplicate id %q", i, c.ID)
		}
		ids[c.ID] = true
		if len(c.Query) == 0 || len(c.Query) > 4096 || unsupported(c.Query) {
			t.Fatalf("case %s: invalid query %q", c.ID, c.Query)
		}
		if c.Operator != "" && c.Operator != string(OR) && c.Operator != string(AND) {
			t.Fatalf("case %s: invalid operator %q", c.ID, c.Operator)
		}
		if c.Limit != 0 && (c.Limit < 1 || c.Limit > 100) {
			t.Fatalf("case %s: invalid limit %d", c.ID, c.Limit)
		}
		if len(c.Documents) < corpusCaseMinDocs {
			t.Fatalf("case %s: %d documents, the corpus requires %d", c.ID, len(c.Documents), corpusCaseMinDocs)
		}
		g2 := 0
		for _, d := range c.Documents {
			if d.Grade < 0 || d.Grade > 2 {
				t.Fatalf("case %s: grade %d out of range", c.ID, d.Grade)
			}
			if d.Grade == 2 {
				g2++
			}
			if !fabric.ValidNamespacedName(d.Kind) {
				t.Fatalf("case %s: invalid kind %q", c.ID, d.Kind)
			}
		}
		if g2 != 1 {
			t.Fatalf("case %s: %d grade-2 documents, the corpus requires exactly one most-relevant document", c.ID, g2)
		}
		if len(strings.Fields(c.Query)) == 1 {
			singleTerm++
		}
		if c.Operator == string(AND) {
			and++
		}
		if len(c.Filters.Kinds) > 0 || len(c.Filters.Tags) > 0 || len(c.Filters.Providers) > 0 {
			filtered++
		}
		if len(c.Documents) >= 40 {
			scale++
		}
	}
	if scale < corpusMinScaleCases || singleTerm < corpusMinSingleTerm || and < corpusMinAND || filtered < corpusMinFiltered {
		t.Fatalf("relevance corpus diversity insufficient: scale=%d singleTerm=%d and=%d filtered=%d", scale, singleTerm, and, filtered)
	}
	return fx
}

func corpusNDCG(grades []int, limit int) float64 {
	if limit > len(grades) {
		limit = len(grades)
	}
	dcg := 0.0
	for i := 0; i < limit; i++ {
		dcg += (math.Pow(2, float64(grades[i])) - 1) / math.Log2(float64(i+2))
	}
	ideal := append([]int(nil), grades...)
	sort.Sort(sort.Reverse(sort.IntSlice(ideal)))
	idcg := 0.0
	for i := 0; i < limit && i < len(ideal); i++ {
		idcg += (math.Pow(2, float64(ideal[i])) - 1) / math.Log2(float64(i+2))
	}
	if idcg == 0 {
		return 0
	}
	return dcg / idcg
}

func TestRelevanceCorpus(t *testing.T) {
	fx := loadRelevanceCorpus(t)
	ctx := context.Background()
	var totalNDCG, totalPrecision float64
	for ci, c := range fx.Cases {
		c, ci := c, ci
		t.Run(c.ID, func(t *testing.T) {
			b := newBackend(t)
			grades := map[fabric.EndpointRef]int{}
			g2Ref := fabric.EndpointRef{}
			for di, d := range c.Documents {
				ref := testRef(uint64(ci+1)*100000 + uint64(di+1))
				doc := fabric.SearchDocument{
					Ref:              ref,
					Revision:         "v1",
					Name:             d.Name,
					ShortDescription: d.ShortDescription,
					Kind:             d.Kind,
					Provider:         d.Provider,
					Tags:             d.Tags,
					Examples:         d.Examples,
				}
				if err := b.Upsert(ctx, doc); err != nil {
					t.Fatalf("upsert %d: %v", di, err)
				}
				grades[ref] = d.Grade
				if d.Grade == 2 {
					g2Ref = ref
				}
			}
			limit := c.Limit
			if limit == 0 {
				limit = 3
			}
			operator := OR
			if c.Operator == string(AND) {
				operator = AND
			}
			r := fabric.DiscoverRequest{Query: c.Query, Limit: limit, Filters: c.Filters}
			result, _, err := b.SearchWithOptions(ctx, r, Options{Operator: operator})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Candidates) == 0 {
				t.Fatalf("query %q returned no candidates", c.Query)
			}
			satisfies := func(d fabric.SearchDocument) bool {
				for _, k := range c.Filters.Kinds {
					if d.Kind != k {
						return false
					}
				}
				for _, p := range c.Filters.Providers {
					if d.Provider != p {
						return false
					}
				}
				if len(c.Filters.Tags) > 0 {
					found := false
					for _, tag := range d.Tags {
						for _, want := range c.Filters.Tags {
							if tag == want {
								found = true
							}
						}
					}
					if !found {
						return false
					}
				}
				return true
			}
			// Every candidate must be a fixture document of this case, and the
			// case's filters must have genuinely narrowed the result set.
			ordered := []int{}
			for _, cand := range result.Candidates {
				g, ok := grades[cand.Document.Ref]
				if !ok {
					t.Fatalf("candidate %s is not a document of case %s", cand.Document.Ref, c.ID)
				}
				if !satisfies(cand.Document) {
					t.Fatalf("candidate %s violates the case filters (kind=%s provider=%s tags=%v)", cand.Document.Ref, cand.Document.Kind, cand.Document.Provider, cand.Document.Tags)
				}
				ordered = append(ordered, g)
			}
			// Top-1 is the most-relevant document, and every grade-2 document
			// is retrieved within the case's limit.
			if result.Candidates[0].Document.Ref != g2Ref {
				t.Fatalf("top-1 is %q (grade %d), not the most-relevant document %q",
					result.Candidates[0].Document.ShortDescription, grades[result.Candidates[0].Document.Ref], g2Ref)
			}
			for ref, g := range grades {
				if g != 2 {
					continue
				}
				found := false
				for _, cand := range result.Candidates {
					if cand.Document.Ref == ref {
						found = true
					}
				}
				if !found {
					t.Fatalf("most-relevant document %q was not retrieved within limit %d", ref, limit)
				}
			}
			precision := 0.0
			for _, g := range ordered {
				if g >= 1 {
					precision++
				}
			}
			precision /= float64(len(ordered))
			ndcg := corpusNDCG(ordered, limit)
			t.Logf("case %s: top3=%v ndcg@%d=%.3f precision=%.3f", c.ID, ordered, limit, ndcg, precision)
			if ndcg < corpusPerCaseNDCG {
				t.Fatalf("ndcg@%d %.3f below the per-case floor %.2f (top3=%v)", limit, ndcg, corpusPerCaseNDCG, ordered)
			}
			if precision < corpusPerCasePrecision {
				t.Fatalf("precision %.3f below the per-case floor %.2f (top3=%v)", precision, corpusPerCasePrecision, ordered)
			}
			totalNDCG += ndcg
			totalPrecision += precision
		})
	}
	meanNDCG := totalNDCG / float64(len(fx.Cases))
	meanPrecision := totalPrecision / float64(len(fx.Cases))
	t.Logf("relevance corpus: %d cases, mean NDCG@limit=%.3f (floor %.2f), mean precision=%.3f (floor %.2f)",
		len(fx.Cases), meanNDCG, corpusMeanNDCG, meanPrecision, corpusMeanPrecision)
	if meanNDCG < corpusMeanNDCG {
		t.Fatalf("mean NDCG %.3f below aggregate floor %.2f", meanNDCG, corpusMeanNDCG)
	}
	if meanPrecision < corpusMeanPrecision {
		t.Fatalf("mean precision %.3f below aggregate floor %.2f", meanPrecision, corpusMeanPrecision)
	}
}
