// Package hybrid composes explicitly selected compact discovery retrievers.
// It owns no authorization policy, schemas, invocation adapter or model loader.
package hybrid

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
)

var ErrStaleSnapshot = errors.New("hybrid discovery snapshot expired or its authority/index changed")
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
type snapshot struct {
	id, binding, scope string
	policy             fabric.Revision
	revisions          []fabric.Revision
	candidates         []fabric.Candidate
	revision           fabric.Revision
	expires            time.Time
	size               int
	sequence           uint64
}
type Backend struct {
	config    Config
	key       []byte
	mu        sync.Mutex
	snapshots map[string]*snapshot
	bytes     int
	sequence  uint64
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
	key := append([]byte(nil), c.CursorKey...)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	if len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("cursor authentication key must contain32..4096 bytes")
	}
	c.CursorKey = nil
	return &Backend{config: c, key: key, snapshots: map[string]*snapshot{}}, nil
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
	s := &snapshot{scope: g.ScopeKey, policy: g.PolicyRevision, revisions: revisions, candidates: clone(pool), expires: time.Now().Add(b.config.SnapshotTTL)}
	raw, _ := json.Marshal(struct {
		Revisions []fabric.Revision
		Pool      []fabric.Candidate
	}{revisions, pool})
	hash := sha256.Sum256(raw)
	s.revision = fabric.Revision("hybrid:" + hex.EncodeToString(hash[:]))
	s.binding = b.binding(r)
	s.size = len(raw) + len(s.binding) + len(s.scope) + len(s.policy) + 256
	if err = b.checkRevisions(ctx, s); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if len(pool) <= r.Limit {
		return fabric.DiscoverResult{Candidates: clone(pool), IndexRevision: s.revision}, ctx.Err()
	}
	id := make([]byte, 24)
	if _, err = rand.Read(id); err != nil {
		return fabric.DiscoverResult{}, err
	}
	s.id = base64.RawURLEncoding.EncodeToString(id)
	if err = b.save(ctx, s); err != nil {
		return fabric.DiscoverResult{}, err
	}
	return b.slice(s, 0, r.Limit), ctx.Err()
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
func (b *Backend) checkRevisions(ctx context.Context, s *snapshot) error {
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
		if current != s.revisions[i] {
			return ErrStaleSnapshot
		}
	}
	return ctx.Err()
}
func (b *Backend) save(ctx context.Context, s *snapshot) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.size > b.config.MaxSnapshotBytes {
		return errors.New("ranked snapshot exceeds configured byte budget")
	}
	now := time.Now()
	for id, old := range b.snapshots {
		if !old.expires.After(now) {
			delete(b.snapshots, id)
			b.bytes -= old.size
		}
	}
	for len(b.snapshots) >= b.config.MaxSnapshots || b.bytes+s.size > b.config.MaxSnapshotBytes {
		var oldest *snapshot
		for _, old := range b.snapshots {
			if oldest == nil || old.sequence < oldest.sequence {
				oldest = old
			}
		}
		delete(b.snapshots, oldest.id)
		b.bytes -= oldest.size
	}
	b.sequence++
	s.sequence = b.sequence
	b.snapshots[s.id] = s
	b.bytes += s.size
	return nil
}

type cursor struct {
	Snapshot, Binding, Scope string
	Policy                   fabric.Revision
	Offset                   int
}

func (b *Backend) token(s *snapshot, offset int) string {
	raw, _ := json.Marshal(cursor{s.id, s.binding, s.scope, s.policy, offset})
	mac := hmac.New(sha256.New, b.key)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (b *Backend) decode(token string) (cursor, error) {
	var c cursor
	if len(token) > 4096 {
		return c, ErrStaleSnapshot
	}
	var left, right string
	for i, ch := range token {
		if ch == '.' {
			left, right = token[:i], token[i+1:]
			break
		}
	}
	raw, e := base64.RawURLEncoding.DecodeString(left)
	sig, e2 := base64.RawURLEncoding.DecodeString(right)
	if e != nil || e2 != nil {
		return c, ErrStaleSnapshot
	}
	mac := hmac.New(sha256.New, b.key)
	_, _ = mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(raw, &c) != nil {
		return c, ErrStaleSnapshot
	}
	return c, nil
}
func (b *Backend) slice(s *snapshot, offset, limit int) fabric.DiscoverResult {
	end := offset + limit
	if end > len(s.candidates) {
		end = len(s.candidates)
	}
	result := fabric.DiscoverResult{Candidates: clone(s.candidates[offset:end]), IndexRevision: s.revision}
	if end < len(s.candidates) {
		result.NextCursor = b.token(s, end)
	}
	return result
}
func (b *Backend) page(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	c, err := b.decode(r.Cursor)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	b.mu.Lock()
	s := b.snapshots[c.Snapshot]
	b.mu.Unlock()
	if s == nil || !s.expires.After(time.Now()) || c.Offset < 1 || c.Offset >= len(s.candidates) || c.Binding != s.binding || c.Scope != s.scope || c.Policy != s.policy || b.binding(r) != s.binding {
		return fabric.DiscoverResult{}, ErrStaleSnapshot
	}
	expected := GateResult{ScopeKey: s.scope, PolicyRevision: s.policy}
	if _, err = b.gate(ctx, r, nil, &expected); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err = b.checkRevisions(ctx, s); err != nil {
		return fabric.DiscoverResult{}, err
	}
	result := b.slice(s, c.Offset, r.Limit)
	allowed, err := b.gate(ctx, r, result.Candidates, &expected)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	if len(allowed.Candidates) != len(result.Candidates) {
		return fabric.DiscoverResult{}, ErrStaleSnapshot
	}
	// Gate may filter or preserve order only; retain the authenticated snapshot order.
	if _, err = subset(allowed.Candidates, result.Candidates, true); err != nil {
		return fabric.DiscoverResult{}, ErrStaleSnapshot
	}
	return result, ctx.Err()
}

// String reveals only explicitly configured providers, never key/snapshot contents.
func (b *Backend) String() string {
	return fmt.Sprintf("hybrid discovery lexical=%s semantic=%s", b.config.Lexical.ID, providerID(b.config.Semantic))
}
