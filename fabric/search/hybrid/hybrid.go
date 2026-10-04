// Package hybrid composes explicitly selected compact discovery retrievers.
// It owns no authorization policy, schemas, invocation adapter or model loader.
package hybrid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/internal/snapshot"
)

var ErrStaleSnapshot = snapshot.ErrStale
var ErrProviderResult = errors.New("discovery provider returned invalid or inconsistent bounded candidates")

type Retriever interface {
	Search(context.Context, fabric.DiscoverRequest) (fabric.DiscoverResult, error)
}
type Provider struct {
	ID, Version string
	Retriever   Retriever
	// CurrentRevision must be a cheap read of the same indexed universe Search uses.
	// It must not rerun retrieval/model calls or infer revision from the request.
	CurrentRevision func(context.Context) (fabric.Revision, error)
	External        bool
}
type RerankProvider struct {
	ID, Version string
	Reranker    fabric.DiscoveryReranker
	External    bool
}
type GateResult struct {
	// Both values come from authenticated policy composition, not request labels.
	ScopeKey       string
	PolicyRevision fabric.Revision
	Candidates     []fabric.Candidate
}
type CandidateGate func(context.Context, fabric.DiscoverRequest, []fabric.Candidate) (GateResult, error)
type Disclosure struct {
	Stage, ProviderID, ProviderVersion string
	PolicyRevision                     fabric.Revision
	ScopeKey                           string
}
type DisclosureGate func(context.Context, Disclosure, fabric.DiscoverRequest, []fabric.Candidate) error
type Config struct {
	Lexical                                     Provider
	Semantic                                    *Provider
	Reranker                                    *RerankProvider
	Gate                                        CandidateGate
	DisclosureGate                              DisclosureGate
	LexicalLimit, SemanticLimit, FusionLimit    int
	LexicalWeight, SemanticWeight, RankConstant float64
	MaxSnapshots, MaxSnapshotBytes              int
	SnapshotTTL                                 time.Duration
	// Omitted generates a private ephemeral key. Restart then invalidates cursors.
	CursorKey []byte
}
type Backend struct {
	config Config
	pager  *snapshot.Pager
}

func New(c Config) (*Backend, error) {
	if !validProvider(c.Lexical) || c.Gate == nil {
		return nil, errors.New("lexical provider and authenticated candidate gate are required")
	}
	if c.Semantic != nil {
		p := *c.Semantic
		c.Semantic = &p
		if !validProvider(p) || p.ID == c.Lexical.ID {
			return nil, errors.New("semantic provider needs a distinct explicit identity/version")
		}
	}
	if c.Reranker != nil {
		p := *c.Reranker
		c.Reranker = &p
		if p.ID == "" || len(p.ID) > 256 || p.Version == "" || len(p.Version) > 256 || p.Reranker == nil {
			return nil, errors.New("reranker identity/version/implementation required")
		}
	}
	if (c.Lexical.External || c.Semantic != nil && c.Semantic.External || c.Reranker != nil && c.Reranker.External) && c.DisclosureGate == nil {
		return nil, errors.New("external provider requires an explicit disclosure gate")
	}
	if c.LexicalLimit == 0 {
		c.LexicalLimit = 100
	}
	if c.SemanticLimit == 0 {
		c.SemanticLimit = 100
	}
	if c.FusionLimit == 0 {
		c.FusionLimit = 100
	}
	if c.LexicalLimit < 1 || c.LexicalLimit > 100 || c.SemanticLimit < 1 || c.SemanticLimit > 100 || c.FusionLimit < 1 || c.FusionLimit > 200 {
		return nil, errors.New("invalid bounded retrieval horizon")
	}
	if c.LexicalWeight == 0 {
		c.LexicalWeight = 1
	}
	if c.SemanticWeight == 0 {
		c.SemanticWeight = 1
	}
	if c.RankConstant == 0 {
		c.RankConstant = 60
	}
	if !positive(c.LexicalWeight) || !positive(c.SemanticWeight) || !positive(c.RankConstant) {
		return nil, errors.New("fusion parameters must be positive finite numbers")
	}
	if c.MaxSnapshots == 0 {
		c.MaxSnapshots = 64
	}
	if c.MaxSnapshotBytes == 0 {
		c.MaxSnapshotBytes = 4 << 20
	}
	if c.SnapshotTTL == 0 {
		c.SnapshotTTL = 5 * time.Minute
	}
	if c.MaxSnapshots < 1 || c.MaxSnapshots > 4096 || c.MaxSnapshotBytes < 1 || c.MaxSnapshotBytes > 64<<20 || c.SnapshotTTL <= 0 || c.SnapshotTTL > time.Hour {
		return nil, errors.New("invalid finite snapshot limits")
	}
	if (c.Semantic != nil || c.Reranker != nil) && (c.Lexical.CurrentRevision == nil || c.Semantic != nil && c.Semantic.CurrentRevision == nil) {
		return nil, errors.New("hybrid paging requires cheap current index revision callbacks")
	}
	pager, err := snapshot.New(snapshot.Config{MaxSnapshots: c.MaxSnapshots, MaxBytes: c.MaxSnapshotBytes, TTL: c.SnapshotTTL, Key: c.CursorKey})
	if err != nil {
		return nil, err
	}
	c.CursorKey = nil
	return &Backend{config: c, pager: pager}, nil
}
func validProvider(p Provider) bool {
	return p.ID != "" && len(p.ID) <= 256 && p.Version != "" && len(p.Version) <= 256 && p.Retriever != nil
}
func positive(n float64) bool { return n > 0 && !math.IsNaN(n) && !math.IsInf(n, 0) }
func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func sameDocument(a, b fabric.SearchDocument) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}
func candidateMap(cs []fabric.Candidate, max int) (map[string]fabric.Candidate, error) {
	if len(cs) > max {
		return nil, ErrProviderResult
	}
	m := make(map[string]fabric.Candidate, len(cs))
	for _, c := range cs {
		key := c.Document.Ref.String()
		if _, err := fabric.ParseEndpointRef(key); err != nil || !validDocumentText(c.Document) || c.Document.Revision == "" || len(c.Document.Revision) > 256 || math.IsNaN(c.Score) || math.IsInf(c.Score, 0) {
			return nil, ErrProviderResult
		}
		raw, err := json.Marshal(c.Document)
		if err != nil || len(raw) > search.MaxDocumentBytes {
			return nil, ErrProviderResult
		}
		if _, ok := m[key]; ok {
			return nil, ErrProviderResult
		}
		m[key] = c
	}
	return m, nil
}
func validDocumentText(d fabric.SearchDocument) bool {
	if !fabric.ValidNamespacedName(d.Kind) || len(d.Tags) > 32 || len(d.Examples) > 8 {
		return false
	}
	fields := append([]string{string(d.Revision), d.Name, d.ShortDescription, d.Provider, d.SchemaFingerprint}, d.Tags...)
	fields = append(fields, d.Examples...)
	for _, field := range fields {
		if !utf8.ValidString(field) {
			return false
		}
	}
	return true
}
func subset(original, out []fabric.Candidate, metadata bool) ([]fabric.Candidate, error) {
	m, err := candidateMap(original, 200)
	if err != nil {
		return nil, err
	}
	if _, err = candidateMap(out, len(original)); err != nil {
		return nil, err
	}
	safe := make([]fabric.Candidate, 0, len(out))
	selected := make(map[string]bool, len(out))
	for _, c := range out {
		old, ok := m[c.Document.Ref.String()]
		if !ok || old.Document.Revision != c.Document.Revision || metadata && !sameDocument(old.Document, c.Document) {
			return nil, ErrProviderResult
		}
		if !metadata {
			old.Score = c.Score
		}
		safe = append(safe, old)
		selected[old.Document.Ref.String()] = true
	}
	if metadata {
		safe = safe[:0]
		for _, originalCandidate := range original {
			if selected[originalCandidate.Document.Ref.String()] {
				safe = append(safe, originalCandidate)
			}
		}
	}
	return safe, nil
}
func (b *Backend) gate(ctx context.Context, r fabric.DiscoverRequest, cs []fabric.Candidate, expected *GateResult) (GateResult, error) {
	if err := ctx.Err(); err != nil {
		return GateResult{}, err
	}
	g, err := b.config.Gate(ctx, clone(r), clone(cs))
	if err != nil {
		return GateResult{}, err
	}
	if g.ScopeKey == "" || len(g.ScopeKey) > 1024 || !utf8.ValidString(g.ScopeKey) || g.PolicyRevision == "" || len(g.PolicyRevision) > 256 || !utf8.ValidString(string(g.PolicyRevision)) {
		return GateResult{}, errors.New("gate did not supply authenticated scope and policy revision")
	}
	if expected != nil && (g.ScopeKey != expected.ScopeKey || g.PolicyRevision != expected.PolicyRevision) {
		return GateResult{}, ErrStaleSnapshot
	}
	g.Candidates, err = subset(cs, g.Candidates, true)
	return g, err
}
func (b *Backend) disclose(ctx context.Context, p Provider, stage string, r fabric.DiscoverRequest, g GateResult, cs []fabric.Candidate) error {
	if !p.External {
		return ctx.Err()
	}
	return b.config.DisclosureGate(ctx, Disclosure{stage, p.ID, p.Version, g.PolicyRevision, g.ScopeKey}, clone(r), clone(cs))
}
func (b *Backend) retrieve(ctx context.Context, p Provider, r fabric.DiscoverRequest, g GateResult, limit int) (fabric.DiscoverResult, error) {
	r.Cursor = ""
	r.Limit = limit
	if err := b.disclose(ctx, p, "query", r, g, nil); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	result, err := p.Retriever.Search(ctx, clone(r))
	if err != nil {
		return result, err
	}
	if result.IndexRevision == "" || len(result.IndexRevision) > 256 {
		return result, ErrProviderResult
	}
	if _, err = candidateMap(result.Candidates, limit); err != nil {
		return result, err
	}
	allowed, err := b.gate(ctx, r, result.Candidates, &g)
	if err != nil {
		return result, err
	}
	result.Candidates = allowed.Candidates
	result.NextCursor = ""
	return result, nil
}
func (b *Backend) Search(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := r.Validate(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if b.config.Semantic == nil && b.config.Reranker == nil {
		g, err := b.gate(ctx, r, nil, nil)
		if err != nil {
			return fabric.DiscoverResult{}, err
		}
		if err = b.disclose(ctx, b.config.Lexical, "query", r, g, nil); err != nil {
			return fabric.DiscoverResult{}, err
		}
		result, err := b.config.Lexical.Retriever.Search(ctx, clone(r))
		if err != nil {
			return result, err
		}
		if result.IndexRevision == "" || len(result.IndexRevision) > 256 {
			return fabric.DiscoverResult{}, ErrProviderResult
		}
		if _, err = candidateMap(result.Candidates, r.Limit); err != nil {
			return fabric.DiscoverResult{}, err
		}
		allowed, err := b.gate(ctx, r, result.Candidates, &g)
		if err != nil {
			return fabric.DiscoverResult{}, err
		}
		result.Candidates = allowed.Candidates
		return result, ctx.Err()
	}
	if r.Cursor != "" {
		return b.page(ctx, r)
	}
	g, err := b.gate(ctx, r, nil, nil)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	lexical, err := b.retrieve(ctx, b.config.Lexical, r, g, b.config.LexicalLimit)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	sources := [][]fabric.Candidate{lexical.Candidates}
	weights := []float64{b.config.LexicalWeight}
	revisions := []fabric.Revision{lexical.IndexRevision}
	if b.config.Semantic != nil {
		semantic, e := b.retrieve(ctx, *b.config.Semantic, r, g, b.config.SemanticLimit)
		if e != nil {
			return fabric.DiscoverResult{}, e
		}
		sources = append(sources, semantic.Candidates)
		weights = append(weights, b.config.SemanticWeight)
		revisions = append(revisions, semantic.IndexRevision)
	}
	pool, err := fuse(sources, weights, b.config.RankConstant, b.config.FusionLimit)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	allowed, err := b.gate(ctx, r, pool, &g)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	pool = allowed.Candidates
	if b.config.Reranker != nil {
		p := b.config.Reranker
		if p.External {
			if err = b.config.DisclosureGate(ctx, Disclosure{"rerank", p.ID, p.Version, g.PolicyRevision, g.ScopeKey}, clone(r), clone(pool)); err != nil {
				return fabric.DiscoverResult{}, err
			}
		}
		if err = ctx.Err(); err != nil {
			return fabric.DiscoverResult{}, err
		}
		ranked, e := p.Reranker.Rerank(ctx, clone(r), clone(pool))
		if e != nil {
			return fabric.DiscoverResult{}, e
		}
		pool, err = subset(pool, ranked, false)
		if err != nil {
			return fabric.DiscoverResult{}, err
		}
		sortCandidates(pool)
	}
	allowed, err = b.gate(ctx, r, pool, &g)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	pool = allowed.Candidates
	s := snapshot.State{Scope: g.ScopeKey, Policy: g.PolicyRevision, IndexRevisions: revisions, Candidates: clone(pool)}
	raw, _ := json.Marshal(struct {
		Revisions []fabric.Revision
		Pool      []fabric.Candidate
	}{revisions, pool})
	hash := sha256.Sum256(raw)
	s.Revision = fabric.Revision("hybrid:" + hex.EncodeToString(hash[:]))
	s.Binding = b.binding(r)
	if err = b.checkRevisions(ctx, s); err != nil {
		return fabric.DiscoverResult{}, err
	}
	return b.pager.Store(ctx, r, s)
}
func fuse(sources [][]fabric.Candidate, weights []float64, k float64, limit int) ([]fabric.Candidate, error) {
	m := map[string]fabric.Candidate{}
	for i, source := range sources {
		for rank, c := range source {
			key := c.Document.Ref.String()
			old, ok := m[key]
			if ok && !sameDocument(old.Document, c.Document) {
				return nil, ErrProviderResult
			}
			if !ok {
				old = c
				old.Score = 0
			}
			old.Score += weights[i] / (k + float64(rank+1))
			if math.IsNaN(old.Score) || math.IsInf(old.Score, 0) {
				return nil, ErrProviderResult
			}
			m[key] = old
		}
	}
	result := make([]fabric.Candidate, 0, len(m))
	for _, c := range m {
		result = append(result, c)
	}
	sortCandidates(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}
func sortCandidates(cs []fabric.Candidate) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Score == cs[j].Score {
			return cs[i].Document.Ref.String() < cs[j].Document.Ref.String()
		}
		return cs[i].Score > cs[j].Score
	})
}
func (b *Backend) binding(r fabric.DiscoverRequest) string {
	r.Cursor = ""
	raw, _ := json.Marshal(struct {
		Request                                                                             fabric.DiscoverRequest
		LexicalID, LexicalVersion, SemanticID, SemanticVersion, RerankerID, RerankerVersion string
		LexicalLimit, SemanticLimit, FusionLimit                                            int
		LexicalWeight, SemanticWeight, RankConstant                                         float64
	}{r, b.config.Lexical.ID, b.config.Lexical.Version, providerID(b.config.Semantic), providerVersion(b.config.Semantic), rerankerID(b.config.Reranker), rerankerVersion(b.config.Reranker), b.config.LexicalLimit, b.config.SemanticLimit, b.config.FusionLimit, b.config.LexicalWeight, b.config.SemanticWeight, b.config.RankConstant})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func providerID(p *Provider) string {
	if p == nil {
		return ""
	}
	return p.ID
}
func providerVersion(p *Provider) string {
	if p == nil {
		return ""
	}
	return p.Version
}
func rerankerID(p *RerankProvider) string {
	if p == nil {
		return ""
	}
	return p.ID
}
func rerankerVersion(p *RerankProvider) string {
	if p == nil {
		return ""
	}
	return p.Version
}
func (b *Backend) checkRevisions(ctx context.Context, s snapshot.State) error {
	ps := []Provider{b.config.Lexical}
	if b.config.Semantic != nil {
		ps = append(ps, *b.config.Semantic)
	}
	for i, p := range ps {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := p.CurrentRevision(ctx)
		if err != nil {
			return err
		}
		if current != s.IndexRevisions[i] {
			return ErrStaleSnapshot
		}
	}
	return ctx.Err()
}
func (b *Backend) page(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	return b.pager.Page(ctx, r, b.binding(r), func(ctx context.Context, r fabric.DiscoverRequest, s snapshot.State, cs []fabric.Candidate) error {
		expected := GateResult{ScopeKey: s.Scope, PolicyRevision: s.Policy}
		if _, err := b.gate(ctx, r, nil, &expected); err != nil {
			return err
		}
		if err := b.checkRevisions(ctx, s); err != nil {
			return err
		}
		allowed, err := b.gate(ctx, r, cs, &expected)
		if err != nil {
			return err
		}
		if len(allowed.Candidates) != len(cs) {
			return ErrStaleSnapshot
		}
		if _, err = subset(allowed.Candidates, cs, true); err != nil {
			return ErrStaleSnapshot
		}
		return nil
	})
}

// String reveals only explicitly configured providers, never key/snapshot contents.
func (b *Backend) String() string {
	return fmt.Sprintf("hybrid discovery lexical=%s semantic=%s", b.config.Lexical.ID, providerID(b.config.Semantic))
}
