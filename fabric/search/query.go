package search

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"math"
	"sort"
)

type queryTerm struct {
	name     string
	constant float64
}
type ranked struct {
	record *indexed
	score  float64
}

func better(a, b ranked) bool {
	return a.score > b.score || (a.score == b.score && a.record.doc.Ref.String() < b.record.doc.Ref.String())
}

type winners []ranked

func (h winners) Len() int           { return len(h) }
func (h winners) Less(i, j int) bool { return better(h[j], h[i]) }
func (h winners) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *winners) Push(v any)        { *h = append(*h, v.(ranked)) }
func (h *winners) Pop() any          { n := len(*h); v := (*h)[n-1]; *h = (*h)[:n-1]; return v }

type branch struct {
	node     *node
	eligible *idSet
	lo, span uint64
	bound    float64
}
type frontier []branch

func (h frontier) Len() int { return len(h) }
func (h frontier) Less(i, j int) bool {
	return h[i].bound > h[j].bound || (h[i].bound == h[j].bound && h[i].node.minRef < h[j].node.minRef)
}
func (h frontier) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *frontier) Push(v any)   { *h = append(*h, v.(branch)) }
func (h *frontier) Pop() any     { n := len(*h); v := (*h)[n-1]; *h = (*h)[:n-1]; return v }

type pageCursor struct {
	Generation uint64          `json:"generation"`
	Query      string          `json:"query"`
	Visibility fabric.Revision `json:"visibility"`
	Score      uint64          `json:"score"`
	Ref        string          `json:"ref"`
}

func contribution(constant, k1, b, avg float64, length, tf uint32) float64 {
	if tf == 0 {
		return 0
	}
	norm := (1 - b) + b*(float64(length)/avg)
	return constant / (1 + (k1*norm)/float64(tf))
}
func buildQuery(text string, c corpus, w *Work) ([]queryTerm, error) {
	if unsupported(text) {
		return nil, ErrUnsupportedQuery
	}
	weights := map[string]uint32{}
	for _, token := range tokenize(text) {
		weights[token]++
	}
	if len(weights) > MaxQueryTerms {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Too many lexical query terms")
	}
	names := make([]string, 0, len(weights))
	for name := range weights {
		names = append(names, name)
	}
	sort.Strings(names)
	terms := make([]queryTerm, 0, len(names))
	for _, name := range names {
		w.StatisticsLookups++
		df, _ := queryGet(c.df, name, w)
		if df > c.count {
			return nil, fabric.NewError(fabric.CodeProtocolError, "Invalid visible corpus statistics")
		}
		idf := math.Log1p((float64(c.count-df) + .5) / (float64(df) + .5))
		terms = append(terms, queryTerm{name, float64(weights[name]) * idf})
	}
	return terms, nil
}
func scoreDocument(d *indexed, terms []queryTerm, p Parameters, avg float64) float64 {
	score := 0.0
	for _, t := range terms {
		score += contribution(t.constant*(p.K1+1), p.K1, p.B, avg, d.length, frequency(d.terms, t.name))
	}
	return score
}
func nodeBound(n *node, terms []queryTerm, p Parameters, avg float64, operator Operator, w *Work) (float64, bool) {
	score := 0.0
	any := false
	for _, t := range terms {
		w.SummaryLookups++
		v, _ := queryGet(n.summaries, "t:"+t.name, w)
		if v.count == 0 {
			if operator == AND {
				return 0, false
			}
			continue
		}
		any = true
		score += contribution(t.constant*(p.K1+1), p.K1, p.B, avg, v.minLength, v.maxTF)
	}
	return score, any
}
func competitive(bound float64, minRef string, h winners, k int, w *Work) bool {
	if len(h) < k {
		return true
	}
	worst := h[0]
	if bound < worst.score {
		w.ScorePrunes++
		return false
	}
	if bound == worst.score && minRef >= worst.record.doc.Ref.String() {
		w.TiePrunes++
		return false
	}
	return true
}
func nodeFilter(n *node, groups [][]string, w *Work) bool {
	for _, group := range groups {
		found := false
		for _, key := range group {
			w.SummaryLookups++
			v, _ := queryGet(n.summaries, key, w)
			if v.count > 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func documentFilter(d *indexed, groups [][]string, w *Work) bool {
	for _, group := range groups {
		found := false
		for _, key := range group {
			w.MembershipProbes++
			if recordImpact(d, key).count > 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (b *Backend) Search(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	result, _, err := b.SearchWithOptions(ctx, r, Options{})
	return result, err
}
func (b *Backend) SearchWithOptions(ctx context.Context, r fabric.DiscoverRequest, options Options) (fabric.DiscoverResult, Work, error) {
	w := Work{}
	empty := fabric.DiscoverResult{Candidates: []fabric.Candidate{}}
	if err := ctx.Err(); err != nil {
		return empty, w, err
	}
	if err := r.Validate(); err != nil {
		return empty, w, err
	}
	operator := options.Operator
	if operator == "" {
		operator = OR
	}
	if operator != OR && operator != AND {
		return empty, w, ErrUnsupportedQuery
	}
	g := b.current.Load()
	stats := g.stats
	scoped := options.Visibility != nil
	var eligible *idSet
	authority := fabric.Revision("")
	if scoped {
		if options.Visibility.generation != g {
			return empty, w, ErrStaleGeneration
		}
		stats = options.Visibility.stats
		eligible = options.Visibility.set
		authority = options.Visibility.authorityRevision
	}
	terms, err := buildQuery(r.Query, stats, &w)
	if err != nil {
		return empty, w, err
	}
	empty.IndexRevision = revision(g)
	canonicalRequest := r
	canonicalRequest.Cursor = ""
	visibilityKey := ""
	if scoped {
		visibilityKey = options.Visibility.fingerprint
	}
	encoded, _ := json.Marshal(struct {
		Request    fabric.DiscoverRequest
		Operator   Operator
		Tokenizer  string
		Parameters Parameters
		Visibility string
	}{canonicalRequest, operator, TokenizerVersion, b.parameters, visibilityKey})
	hash := sha256.Sum256(encoded)
	queryHash := hex.EncodeToString(hash[:])
	var after *pageCursor
	if r.Cursor != "" {
		data, err := base64.RawURLEncoding.DecodeString(r.Cursor)
		if err != nil {
			return empty, w, fabric.NewError(fabric.CodeInvalidInput, "Invalid search page cursor")
		}
		var c pageCursor
		if json.Unmarshal(data, &c) != nil || c.Generation != g.number || c.Query != queryHash || c.Visibility != authority {
			return empty, w, ErrStaleGeneration
		}
		if _, err := fabric.ParseEndpointRef(c.Ref); err != nil || math.IsNaN(math.Float64frombits(c.Score)) || math.IsInf(math.Float64frombits(c.Score), 0) {
			return empty, w, fabric.NewError(fabric.CodeInvalidInput, "Invalid search cursor boundary")
		}
		after = &c
	}
	finish := func(result fabric.DiscoverResult) (fabric.DiscoverResult, Work, error) {
		if err := ctx.Err(); err != nil {
			return empty, w, err
		}
		if options.FinalValidate != nil {
			if err := options.FinalValidate(ctx, authority); err != nil {
				return empty, w, err
			}
		}
		if scoped && b.current.Load() != g {
			return empty, w, ErrStaleGeneration
		}
		b.visited.Add(w.Postings)
		b.candidates.Add(w.ScoredDocuments)
		return result, w, nil
	}
	if g.root == nil || stats.count == 0 || len(terms) == 0 {
		return finish(empty)
	}
	if stats.totalLength == 0 {
		return finish(empty)
	}
	avg := float64(stats.totalLength) / float64(stats.count)
	groups := filterGroups(r)
	k := r.Limit + 1
	h := winners{}
	front := frontier{}
	push := func(n *node, set *idSet, lo, span uint64) {
		if n == nil {
			return
		}
		w.Nodes++
		if scoped && (set == nil || set.count == 0) {
			w.EligibilityPrunes++
			return
		}
		if !nodeFilter(n, groups, &w) {
			w.EligibilityPrunes++
			return
		}
		bound, match := nodeBound(n, terms, b.parameters, avg, operator, &w)
		if !match {
			return
		}
		if !competitive(bound, n.minRef, h, k, &w) {
			return
		}
		heap.Push(&front, branch{n, set, lo, span, bound})
		w.HeapOperations++
	}
	w.Roots++
	push(g.root, eligible, 0, g.span)
	for len(front) > 0 {
		if err := ctx.Err(); err != nil {
			return empty, w, err
		}
		entry := heap.Pop(&front).(branch)
		w.HeapOperations++
		if !competitive(entry.bound, entry.node.minRef, h, k, &w) {
			continue
		}
		if entry.span > leafSize {
			half := entry.span / 2
			var left, right *idSet
			if entry.eligible != nil {
				left = entry.eligible.left
				right = entry.eligible.right
			}
			w.Edges += 2
			push(entry.node.left, left, entry.lo, half)
			push(entry.node.right, right, entry.lo+half, half)
			continue
		}
		for offset, d := range entry.node.leaf {
			w.LeafSlots++
			if d == nil {
				continue
			}
			if scoped {
				w.MembershipProbes++
				if entry.eligible.bits&(uint32(1)<<offset) == 0 {
					continue
				}
			}
			if !documentFilter(d, groups, &w) {
				continue
			}
			matched := false
			all := true
			score := 0.0
			for _, t := range terms {
				w.Postings++
				tf := queryFrequency(d.terms, t.name, &w)
				score += contribution(t.constant*(b.parameters.K1+1), b.parameters.K1, b.parameters.B, avg, d.length, tf)
				matched = matched || tf > 0
				all = all && tf > 0
			}
			if !matched || (operator == AND && !all) {
				continue
			}
			w.ScoredDocuments++
			ref := d.doc.Ref.String()
			if after != nil && (score > math.Float64frombits(after.Score) || (score == math.Float64frombits(after.Score) && ref <= after.Ref)) {
				continue
			}
			candidate := ranked{d, score}
			if len(h) < k {
				heap.Push(&h, candidate)
				w.HeapOperations++
			} else if better(candidate, h[0]) {
				heap.Pop(&h)
				heap.Push(&h, candidate)
				w.HeapOperations += 2
			}
		}
	}
	sort.Slice(h, func(i, j int) bool { return better(h[i], h[j]) })
	result := empty
	if len(h) > r.Limit {
		last := h[r.Limit-1]
		c := pageCursor{g.number, queryHash, authority, math.Float64bits(last.score), last.record.doc.Ref.String()}
		raw, _ := json.Marshal(c)
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		h = h[:r.Limit]
	}
	for _, hit := range h {
		result.Candidates = append(result.Candidates, fabric.Candidate{Document: cloneDocument(hit.record.doc), Score: hit.score})
		w.DocumentLoads++
	}
	return finish(result)
}
func (w Work) String() string {
	return fmt.Sprintf("nodes=%d edges=%d summaries=%d slots=%d postings=%d scored=%d tiePrunes=%d scorePrunes=%d eligibilityPrunes=%d", w.Nodes, w.Edges, w.SummaryLookups, w.LeafSlots, w.Postings, w.ScoredDocuments, w.TiePrunes, w.ScorePrunes, w.EligibilityPrunes)
}

func queryGet[V any](n *dictionary[V], key string, w *Work) (zero V, ok bool) {
	for n != nil {
		w.DictionaryNodes++
		if key < n.key {
			n = n.left
		} else if key > n.key {
			n = n.right
		} else {
			return n.value, true
		}
	}
	return
}
func queryFrequency(terms []term, name string, w *Work) uint32 {
	lo, hi := 0, len(terms)
	for lo < hi {
		mid := lo + (hi-lo)/2
		w.TermProbes++
		if terms[mid].name < name {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(terms) && terms[lo].name == name {
		return terms[lo].tf
	}
	return 0
}
