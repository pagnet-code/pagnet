package hybrid

import (
	"context"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

// This small transparent semantic fixture uses a fixed, operator-selected
// concept vocabulary and cosine scorer. It downloads no model and is not a
// production embedding provider or a claim about arbitrary semantic quality.
// Relevance grades are separately authored against the endpoint's role.
func TestRelevanceRecallMRRAndNDCG(t *testing.T) {
	docs := []fabric.SearchDocument{
		document(1, "email inbox summary"), document(2, "email delivery sent"),
		document(3, "invoice expenses accounting"), document(4, "invoice vendor payment"),
		document(5, "thermostat building energy"), document(6, "building temperature sensor"),
		document(7, "microscope laboratory imaging"), document(8, "laboratory sample instrument"),
		document(9, "warehouse inventory stock"), document(10, "warehouse shipment transport"),
		document(11, "translate customer tickets"), document(12, "translate document language"),
		document(13, "software repository development"), document(14, "calendar scheduling appointments"),
		document(15, "music playback speakers"), document(16, "website marketing traffic"),
	}
	cases := []struct {
		query  string
		grades map[string]int
	}{
		{"mail digest", map[string]int{docs[0].Ref.String(): 2, docs[1].Ref.String(): 1}},
		{"invoice accounting", map[string]int{docs[2].Ref.String(): 2, docs[3].Ref.String(): 1}},
		{"heating efficiency", map[string]int{docs[4].Ref.String(): 2, docs[5].Ref.String(): 1}},
		{"laboratory imaging", map[string]int{docs[6].Ref.String(): 2, docs[7].Ref.String(): 1}},
		{"depot goods", map[string]int{docs[8].Ref.String(): 2, docs[9].Ref.String(): 1}},
		{"multilingual support", map[string]int{docs[10].Ref.String(): 2, docs[11].Ref.String(): 1}},
	}
	concepts := map[string]string{}
	for dimension, words := range map[string]string{
		"mail": "email inbox mail delivery sent", "summary": "summary digest",
		"finance":     "invoice expenses accounting vendor payment billing",
		"building":    "thermostat building energy temperature sensor heating efficiency",
		"lab":         "microscope laboratory imaging sample instrument microscopy",
		"warehouse":   "warehouse inventory stock shipment transport depot goods",
		"translation": "translate customer tickets document language multilingual support",
	} {
		for _, word := range strings.Fields(words) {
			concepts[word] = dimension
		}
	}
	vector := func(text string) map[string]float64 {
		v := map[string]float64{}
		for _, word := range strings.Fields(text) {
			if key := concepts[word]; key != "" {
				v[key]++
			}
		}
		return v
	}
	cosine := func(a, b map[string]float64) float64 {
		dot, na, nb := 0.0, 0.0, 0.0
		for k, v := range a {
			dot += v * b[k]
			na += v * v
		}
		for _, v := range b {
			nb += v * v
		}
		if na == 0 || nb == 0 {
			return 0
		}
		return dot / math.Sqrt(na*nb)
	}
	lexical := lexical(t, docs...)
	semantic := Provider{ID: "fixture-concept-cosine", Version: "v1", Retriever: retrieveFunc(func(_ context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
		q := vector(r.Query)
		cs := []fabric.Candidate{}
		for _, d := range docs {
			s := cosine(q, vector(d.ShortDescription))
			if s > 0 {
				cs = append(cs, fabric.Candidate{Document: d, Score: s})
			}
		}
		sortCandidates(cs)
		if len(cs) > r.Limit {
			cs = cs[:r.Limit]
		}
		return fabric.DiscoverResult{Candidates: cs, IndexRevision: "concepts-v1"}, nil
	}), CurrentRevision: func(context.Context) (fabric.Revision, error) { return "concepts-v1", nil }}
	hybrid := requireBackend(t, Config{Lexical: lexical, Semantic: &semantic, Gate: gateAll})
	type metrics struct{ recall, mrr, ndcg float64 }
	measure := func(cs []fabric.Candidate, grades map[string]int) metrics {
		found := 0
		rr, dcg := 0.0, 0.0
		for i, c := range cs {
			if i >= 2 {
				break
			}
			g := grades[c.Document.Ref.String()]
			if g > 0 {
				found++
				if rr == 0 {
					rr = 1 / float64(i+1)
				}
			}
			dcg += (math.Pow(2, float64(g)) - 1) / math.Log2(float64(i+2))
		}
		ideal := []int{}
		for _, g := range grades {
			ideal = append(ideal, g)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ideal)))
		idcg := 0.0
		for i, g := range ideal {
			if i >= 2 {
				break
			}
			idcg += (math.Pow(2, float64(g)) - 1) / math.Log2(float64(i+2))
		}
		return metrics{float64(found) / float64(len(grades)), rr, dcg / idcg}
	}
	totals := []metrics{{}, {}}
	ctx := context.Background()
	for _, c := range cases {
		r := fabric.DiscoverRequest{Query: c.query, Limit: 2}
		l, e := lexical.Retriever.Search(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		h, e := hybrid.Search(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		for i, cs := range [][]fabric.Candidate{l.Candidates, h.Candidates} {
			m := measure(cs, c.grades)
			totals[i].recall += m.recall
			totals[i].mrr += m.mrr
			totals[i].ndcg += m.ndcg
		}
		t.Logf("query=%q lexical=%+v hybrid=%+v", c.query, measure(l.Candidates, c.grades), measure(h.Candidates, c.grades))
	}
	for i := range totals {
		totals[i].recall /= float64(len(cases))
		totals[i].mrr /= float64(len(cases))
		totals[i].ndcg /= float64(len(cases))
	}
	t.Logf("16-doc/6-query fixed concept corpus Recall@2/MRR/NDCG@2 lexical=%+v hybrid=%+v", totals[0], totals[1])
	if totals[1].recall < .99 || totals[1].mrr < .99 || totals[1].ndcg < .85 || totals[1].recall <= totals[0].recall || totals[1].ndcg <= totals[0].ndcg {
		t.Fatal("relevance baseline regression", totals)
	}
}
