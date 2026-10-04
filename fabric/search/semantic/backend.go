package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/hybrid"
	"github.com/pagnet-code/pagnet/fabric/search/internal/snapshot"
)

type Backend struct {
	config      Config
	identity    EmbeddingIdentity
	annIdentity string
	catalog     *search.Backend
	pager       *snapshot.Pager
	mu          sync.RWMutex
	generation  atomic.Uint64
	reads       atomic.Uint64
	usageMu     sync.Mutex
	usage       Usage
	pendingSHA  string
}

func New(c Config) (*Backend, error) {
	if c.Embeddings == nil || c.ANN == nil || c.DisclosureGate == nil || c.IndexGate == nil || c.CandidateGate == nil {
		return nil, errors.New("explicit embedding/ANN providers and index/candidate/disclosure gates required")
	}
	id := c.Embeddings.Identity()
	if id.Provider == "" || id.Model == "" || id.Version == "" || id.Dimensions < 1 || id.Dimensions > 4096 || c.ANN.Identity() == "" {
		return nil, errors.New("invalid selected embedding/ANN identity")
	}
	if c.Horizon == 0 {
		c.Horizon = 100
	}
	if c.Ef == 0 {
		c.Ef = 128
	}
	if c.Horizon < 1 || c.Horizon > 100 || c.Ef < c.Horizon || c.Ef > 4096 {
		return nil, errors.New("invalid finite semantic horizon/ef")
	}
	catalog, err := search.New(c.CatalogConfig)
	if err != nil {
		return nil, err
	}
	pager, err := snapshot.New(snapshot.Config{MaxSnapshots: c.PagerMaxSnapshots, MaxBytes: c.PagerMaxBytes, Key: c.CursorKey})
	if err != nil {
		return nil, err
	}
	c.CursorKey = nil
	return &Backend{config: c, identity: id, annIdentity: c.ANN.Identity(), catalog: catalog, pager: pager}, nil
}
func (b *Backend) Identity() EmbeddingIdentity { return b.identity }
func (b *Backend) checkProviders() error {
	if b.config.Embeddings.Identity() != b.identity || b.config.ANN.Identity() != b.annIdentity {
		return errors.New("selected provider identity changed")
	}
	return nil
}
func (b *Backend) IndexRevision(ctx context.Context) (fabric.Revision, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fabric.Revision(fmt.Sprintf("semantic-v1:%d", b.generation.Load())), nil
}
func modelFingerprint(id EmbeddingIdentity) string {
	raw, _ := json.Marshal(id)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func pointKey(id EmbeddingIdentity, ref fabric.EndpointRef, revision fabric.Revision) string {
	raw, _ := json.Marshal(struct {
		Identity EmbeddingIdentity
		Ref      fabric.EndpointRef
		Revision fabric.Revision
	}{id, ref, revision})
	h := sha256.Sum256(raw)
	s := hex.EncodeToString(h[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func embeddingText(d fabric.SearchDocument) string {
	return strings.Join(append(append([]string{d.Name, d.ShortDescription}, d.Tags...), d.Examples...), "\n")
}
func (b *Backend) Apply(ctx context.Context, batch search.Batch) error {
	return b.apply(ctx, batch, false)
}
func (b *Backend) apply(ctx context.Context, batch search.Batch, preserveCursor bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.checkProviders(); err != nil {
		return err
	}
	if len(batch.Upserts)+len(batch.Deletes) > 128 {
		return errors.New("semantic mutation batch exceeds128 compact documents")
	}
	if preserveCursor {
		batch.UpstreamCursor = b.catalog.CurrentCursor()
	}
	prepared, err := b.catalog.Prepare(ctx, batch)
	if err != nil {
		return err
	}
	record := prepared.Record()
	if record.Generation > math.MaxInt64-1 {
		return errors.New("semantic generation exhausted")
	}
	refs := map[string]fabric.EndpointRef{}
	for _, d := range batch.Upserts {
		refs[d.Ref.String()] = d.Ref
	}
	for _, d := range batch.Deletes {
		refs[d.Ref.String()] = d.Ref
	}
	keys := make([]string, 0, len(refs))
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	docs := []fabric.SearchDocument{}
	changedDocuments := []fabric.SearchDocument{}
	retire := []string{}
	for _, key := range keys {
		ref := refs[key]
		old, oldOK, e := b.catalog.Document(ctx, ref, "")
		if e != nil {
			return e
		}
		next, nextOK, e := prepared.Document(ctx, ref)
		if e != nil {
			return e
		}
		if oldOK && nextOK && old.Revision == next.Revision {
			continue
		}
		if oldOK {
			changedDocuments = append(changedDocuments, old)
			retire = append(retire, pointKey(b.identity, old.Ref, old.Revision))
		}
		if nextOK {
			changedDocuments = append(changedDocuments, next)
			docs = append(docs, next)
		}
	}
	if err = b.config.IndexGate(ctx, clone(changedDocuments)); err != nil {
		return err
	}
	if b.pendingSHA == record.SHA256 {
		if err = b.config.ANN.Ready(ctx); err != nil {
			return err
		}
		if err = b.catalog.Publish(ctx, prepared, b.config.Commit); err != nil {
			return err
		}
		b.generation.Store(record.Generation)
		b.pendingSHA = ""
		return nil
	}
	if err = b.config.DisclosureGate(ctx, Disclosure{Stage: "document-embedding", Provider: b.identity.Provider, Identity: b.identity, Documents: clone(docs)}); err != nil {
		return err
	}
	texts := make([]string, len(docs))
	for i, d := range docs {
		texts[i] = embeddingText(d)
	}
	vectors := [][]float32{}
	if len(texts) > 0 {
		vectors, err = b.config.Embeddings.Embed(ctx, texts)
		if err != nil {
			return err
		}
		if err = validateVectors(vectors, len(docs), b.identity.Dimensions); err != nil {
			return err
		}
	}
	if err = b.checkProviders(); err != nil {
		return err
	}
	if err = b.config.DisclosureGate(ctx, Disclosure{Stage: "index-update", Provider: b.annIdentity, Identity: b.identity, Documents: clone(changedDocuments)}); err != nil {
		return err
	}
	if err = b.config.ANN.ResetStage(ctx, record.Generation); err != nil {
		return err
	}
	points := make([]VectorPoint, len(docs))
	for i, d := range docs {
		points[i] = VectorPoint{Key: pointKey(b.identity, d.Ref, d.Revision), Ref: d.Ref, Revision: d.Revision, Vector: append([]float32(nil), vectors[i]...), Domain: d.Ref.Domain(), Kind: d.Kind, Provider: d.Provider, Tags: append([]string(nil), d.Tags...), From: record.Generation, Model: modelFingerprint(b.identity)}
	}
	if err = b.config.ANN.Stage(ctx, record.Generation, points, retire); err != nil {
		return err
	}
	b.pendingSHA = record.SHA256
	if err = b.config.ANN.Ready(ctx); err != nil {
		return err
	}
	if err = b.catalog.Publish(ctx, prepared, b.config.Commit); err != nil {
		return err
	}
	b.generation.Store(record.Generation)
	b.pendingSHA = ""
	return nil
}
func (b *Backend) Upsert(ctx context.Context, d fabric.SearchDocument) error {
	return b.apply(ctx, search.Batch{Upserts: []fabric.SearchDocument{d}}, true)
}
func (b *Backend) Delete(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision) error {
	return b.apply(ctx, search.Batch{Deletes: []search.Deletion{{Ref: ref, ExpectedRevision: revision}}}, true)
}
func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func (b *Backend) gate(ctx context.Context, r fabric.DiscoverRequest, cs []fabric.Candidate, expected *hybrid.GateResult) (hybrid.GateResult, error) {
	g, err := b.config.CandidateGate(ctx, clone(r), clone(cs))
	if err != nil {
		return g, err
	}
	if g.ScopeKey == "" || len(g.ScopeKey) > 1024 || g.PolicyRevision == "" || len(g.PolicyRevision) > 256 {
		return g, errors.New("authenticated semantic scope/policy required")
	}
	if expected != nil && (g.ScopeKey != expected.ScopeKey || g.PolicyRevision != expected.PolicyRevision) {
		return g, snapshot.ErrStale
	}
	allowed := map[string]bool{}
	original := map[string]fabric.Candidate{}
	for _, c := range cs {
		original[c.Document.Ref.String()] = c
	}
	for _, c := range g.Candidates {
		key := c.Document.Ref.String()
		old, ok := original[key]
		a, _ := json.Marshal(old.Document)
		z, _ := json.Marshal(c.Document)
		if !ok || allowed[key] || string(a) != string(z) || math.IsNaN(c.Score) || math.IsInf(c.Score, 0) {
			return g, hybrid.ErrProviderResult
		}
		allowed[key] = true
	}
	g.Candidates = []fabric.Candidate{}
	for _, c := range cs {
		if allowed[c.Document.Ref.String()] {
			g.Candidates = append(g.Candidates, c)
		}
	}
	return g, nil
}
func (b *Backend) binding(r fabric.DiscoverRequest) string {
	r.Cursor = ""
	raw, _ := json.Marshal(struct {
		Request     fabric.DiscoverRequest
		Embedding   EmbeddingIdentity
		ANN         string
		Horizon, Ef int
	}{r, b.identity, b.annIdentity, b.config.Horizon, b.config.Ef})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (b *Backend) Search(ctx context.Context, r fabric.DiscoverRequest) (fabric.DiscoverResult, error) {
	if err := ctx.Err(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := b.checkProviders(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err := r.Validate(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if r.Cursor != "" {
		return b.pager.Page(ctx, r, b.binding(r), func(ctx context.Context, r fabric.DiscoverRequest, s snapshot.State, cs []fabric.Candidate) error {
			b.mu.RLock()
			defer b.mu.RUnlock()
			rev, err := b.IndexRevision(ctx)
			if err != nil {
				return err
			}
			if rev != s.Revision {
				return snapshot.ErrStale
			}
			expected := hybrid.GateResult{ScopeKey: s.Scope, PolicyRevision: s.Policy}
			if _, err = b.gate(ctx, r, nil, &expected); err != nil {
				return err
			}
			for _, c := range cs {
				if _, ok, e := b.catalog.Document(ctx, c.Document.Ref, c.Document.Revision); e != nil || !ok {
					return snapshot.ErrStale
				}
			}
			g, err := b.gate(ctx, r, cs, &expected)
			if err != nil {
				return err
			}
			if len(g.Candidates) != len(cs) {
				return snapshot.ErrStale
			}
			return nil
		})
	}
	admitted, err := b.gate(ctx, r, nil, nil)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err = b.config.DisclosureGate(ctx, Disclosure{Stage: "query-embedding", Provider: b.identity.Provider, Identity: b.identity, Query: r.Query}); err != nil {
		return fabric.DiscoverResult{}, err
	}
	vectors, err := b.config.Embeddings.Embed(ctx, []string{r.Query})
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err = validateVectors(vectors, 1, b.identity.Dimensions); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err = b.checkProviders(); err != nil {
		return fabric.DiscoverResult{}, err
	}
	if err = b.config.DisclosureGate(ctx, Disclosure{Stage: "index-query", Provider: b.annIdentity, Identity: b.identity, Query: r.Query}); err != nil {
		return fabric.DiscoverResult{}, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	generation := b.generation.Load()
	if err = b.config.ANN.Ready(ctx); err != nil {
		return fabric.DiscoverResult{}, err
	}
	found, err := b.config.ANN.Query(ctx, VectorQuery{Vector: vectors[0], Generation: generation, Model: modelFingerprint(b.identity), Domains: r.Scope.Domains, Kinds: r.Filters.Kinds, Providers: r.Filters.Providers, Tags: r.Filters.Tags, Limit: b.config.Horizon, Ef: b.config.Ef})
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	if len(found.Hits) > b.config.Horizon {
		return fabric.DiscoverResult{}, hybrid.ErrProviderResult
	}
	pool := make([]fabric.Candidate, 0, len(found.Hits))
	seen := map[string]bool{}
	for _, hit := range found.Hits {
		key := hit.Ref.String()
		if seen[key] || math.IsNaN(hit.Score) || math.IsInf(hit.Score, 0) {
			return fabric.DiscoverResult{}, hybrid.ErrProviderResult
		}
		seen[key] = true
		doc, ok, e := b.catalog.Document(ctx, hit.Ref, hit.Revision)
		if e != nil || !ok || !matches(doc, r) {
			return fabric.DiscoverResult{}, hybrid.ErrProviderResult
		}
		pool = append(pool, fabric.Candidate{Document: doc, Score: hit.Score})
	}
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].Score == pool[j].Score {
			return pool[i].Document.Ref.String() < pool[j].Document.Ref.String()
		}
		return pool[i].Score > pool[j].Score
	})
	allowed, err := b.gate(ctx, r, pool, &admitted)
	if err != nil {
		return fabric.DiscoverResult{}, err
	}
	rev, _ := b.IndexRevision(ctx)
	b.reads.Add(uint64(len(pool)))
	b.usageMu.Lock()
	b.usage = found.Usage
	b.usageMu.Unlock()
	return b.pager.Store(ctx, r, snapshot.State{Binding: b.binding(r), Scope: admitted.ScopeKey, Policy: admitted.PolicyRevision, Revision: rev, IndexRevisions: []fabric.Revision{rev}, Candidates: allowed.Candidates})
}
func (b *Backend) Stats(ctx context.Context) (fabric.SearchStats, error) {
	s, e := b.catalog.Stats(ctx)
	s.CandidatesVisited = b.reads.Load()
	return s, e
}
func (b *Backend) LastUsage() Usage { b.usageMu.Lock(); defer b.usageMu.Unlock(); return b.usage }

func matches(d fabric.SearchDocument, r fabric.DiscoverRequest) bool {
	groups := []struct{ wanted, have []string }{{r.Scope.Domains, []string{d.Ref.Domain()}}, {r.Filters.Kinds, []string{d.Kind}}, {r.Filters.Providers, []string{d.Provider}}, {r.Filters.Tags, d.Tags}}
	for _, group := range groups {
		if len(group.wanted) == 0 {
			continue
		}
		found := false
		for _, wanted := range group.wanted {
			for _, have := range group.have {
				if wanted == have {
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
