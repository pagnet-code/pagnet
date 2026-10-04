package search

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pagnet-code/pagnet/fabric"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

type corpus struct {
	count, totalLength uint64
	df                 *dictionary[uint64]
}
type entry struct {
	id       uint64
	value    *indexed
	revision fabric.Revision
}
type generation struct {
	number, nextID, span, bytes, versions, sourceSequence, replayFloor uint64
	root                                                               *node
	refs                                                               *dictionary[entry]
	seen                                                               *dictionary[string]
	stats                                                              corpus
	cursor                                                             string
	commitHash                                                         string
}
type Backend struct {
	mu          sync.Mutex
	current     atomic.Pointer[generation]
	parameters  Parameters
	commit      CommitFunc
	replayOrder *ReplayOrder
	visited     atomic.Uint64
	candidates  atomic.Uint64
}
type Prepared struct {
	owner      *Backend
	base, next *generation
	record     CommitRecord
	Work       PublicationWork
}

var _ fabric.SearchBackend = (*Backend)(nil)

func New(config Config) (*Backend, error) {
	p := Parameters{1.2, .75}
	if config.Parameters != nil {
		p = *config.Parameters
	}
	if math.IsNaN(p.K1) || math.IsInf(p.K1, 0) || math.IsNaN(p.B) || math.IsInf(p.B, 0) || p.K1 < 0 || p.K1 > 1000 || p.B < 0 || p.B > 1 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Unsupported BM25 parameters")
	}
	b := &Backend{parameters: p, commit: config.Commit}
	if config.ReplayOrder != nil {
		order := *config.ReplayOrder
		if !fabric.ValidNamespacedName(order.Format) || len(order.Format) > 128 || order.Sequence == nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Invalid ordered replay source")
		}
		b.replayOrder = &order
	}
	b.current.Store(&generation{span: leafSize})
	return b, nil
}
func cloneDocument(d fabric.SearchDocument) fabric.SearchDocument {
	d.Tags = append([]string(nil), d.Tags...)
	d.Examples = append([]string(nil), d.Examples...)
	if d.Availability != nil {
		a := *d.Availability
		d.Availability = &a
	}
	return d
}
func encodeRecord(r CommitRecord) ([]byte, error) {
	r.SHA256 = ""
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxCommitBytes {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Index commit exceeds byte budget")
	}
	return data, nil
}
func hashRecord(r CommitRecord) (string, error) {
	data, err := encodeRecord(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
func cloneCommit(r CommitRecord) CommitRecord {
	r.Batch.Upserts = append([]fabric.SearchDocument(nil), r.Batch.Upserts...)
	for i := range r.Batch.Upserts {
		r.Batch.Upserts[i] = cloneDocument(r.Batch.Upserts[i])
	}
	r.Batch.Deletes = append([]Deletion(nil), r.Batch.Deletes...)
	return r
}
func (p *Prepared) Record() CommitRecord { return cloneCommit(p.record) }
func (b *Backend) Prepare(ctx context.Context, batch Batch) (*Prepared, error) {
	return b.prepare(ctx, b.current.Load(), batch)
}
func compact(d fabric.SearchDocument) (*indexed, string, error) {
	if _, err := fabric.ParseEndpointRef(d.Ref.String()); err != nil {
		return nil, "", err
	}
	if d.Revision == "" || len(d.Revision) > 256 || !utf8.ValidString(string(d.Revision)) || !utf8.ValidString(d.Name) || !utf8.ValidString(d.ShortDescription) || !fabric.ValidNamespacedName(d.Kind) || len(d.Tags) > 32 || len(d.Examples) > 8 {
		return nil, "", fabric.NewError(fabric.CodeInvalidInput, "Invalid compact search document")
	}
	for _, s := range append(append([]string{d.Provider, d.SchemaFingerprint}, d.Tags...), d.Examples...) {
		if !utf8.ValidString(s) {
			return nil, "", fabric.NewError(fabric.CodeInvalidInput, "Invalid searchable text")
		}
	}
	d = cloneDocument(d)
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > MaxDocumentBytes {
		return nil, "", fabric.NewError(fabric.CodeInvalidInput, "Search document exceeds compact field budget")
	}
	digest := sha256.Sum256(raw)
	counts := map[string]uint32{}
	length := uint32(0)
	fields := append([]string{d.Name, d.ShortDescription}, d.Tags...)
	fields = append(fields, d.Examples...)
	for _, field := range fields {
		for _, token := range tokenize(field) {
			counts[token]++
			length++
		}
	}
	terms := make([]term, 0, len(counts))
	for name, tf := range counts {
		terms = append(terms, term{name, tf})
	}
	sort.Slice(terms, func(i, j int) bool { return terms[i].name < terms[j].name })
	keys := []string{"k:" + d.Kind, "p:" + d.Provider, "d:" + d.Ref.Domain()}
	for _, tag := range d.Tags {
		keys = append(keys, "g:"+tag)
	}
	sort.Strings(keys)
	keys = unique(keys)
	return &indexed{d, terms, keys, length, uint64(len(raw))}, hex.EncodeToString(digest[:]), nil
}
func unique(values []string) []string {
	out := values[:0]
	for _, s := range values {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
func adjustStats(c corpus, d *indexed, add bool) corpus {
	if d == nil {
		return c
	}
	if add {
		c.count++
		c.totalLength += uint64(d.length)
	} else {
		c.count--
		c.totalLength -= uint64(d.length)
	}
	for _, t := range d.terms {
		df, _ := get(c.df, t.name)
		if add {
			df++
		} else {
			df--
		}
		if df == 0 {
			c.df = remove(c.df, t.name)
		} else {
			c.df = put(c.df, t.name, df)
		}
	}
	return c
}
func (b *Backend) prepare(ctx context.Context, base *generation, batch Batch) (*Prepared, error) {
	if len(batch.Upserts)+len(batch.Deletes) > MaxBatchDocuments || len(batch.UpstreamCursor) > 4096 || !utf8.ValidString(batch.UpstreamCursor) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Index publication bounds exceeded")
	}
	next := *base
	if b.replayOrder != nil {
		sequence, err := b.replayOrder.Sequence(batch.UpstreamCursor)
		if err != nil {
			return nil, err
		}
		if sequence <= base.sourceSequence || sequence <= base.replayFloor {
			return nil, ErrReplayBeforeFloor
		}
		next.sourceSequence = sequence
	}
	p := &Prepared{owner: b, base: base, next: &next}
	batch = cloneCommit(CommitRecord{Batch: batch}).Batch
	for _, d := range batch.Upserts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, digest, err := compact(d)
		if err != nil {
			return nil, err
		}
		ref := d.Ref.String()
		historyKey := ref + "\x00" + string(d.Revision)
		if prior, ok := get(next.seen, historyKey); ok {
			if prior != digest {
				return nil, ErrRevisionConflict
			}
			continue
		}
		if next.versions >= MaxRevisions {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Index revision ledger budget exceeded")
		}
		next.versions++
		e, exists := get(next.refs, ref)
		if !exists {
			if next.nextID >= MaxDocuments {
				return nil, fabric.NewError(fabric.CodeInvalidInput, "Index storage-ID budget exceeded; compact the trusted catalogue")
			}
			e.id = next.nextID
			next.nextID++
			for e.id >= next.span {
				if next.root != nil {
					next.root = &node{left: next.root, summaries: next.root.summaries, minRef: next.root.minRef, count: next.root.count}
				}
				next.span *= 2
			}
		}
		// Empty tree expansion needs no nonempty-child dereference.
		old := e.value
		keys := keysUnion(old, value)
		next.root = updateNode(next.root, 0, next.span, e.id, value, keys, &p.Work)
		next.stats = adjustStats(adjustStats(next.stats, old, false), value, true)
		if old != nil {
			next.bytes -= old.encodedBytes
		}
		next.bytes += value.encodedBytes
		e.value = value
		e.revision = d.Revision
		next.refs = put(next.refs, ref, e)
		next.seen = put(next.seen, historyKey, digest)
		p.Work.Documents++
		p.Work.Terms += uint64(len(keys))
		p.Work.EncodedBytes += value.encodedBytes
	}
	for _, deletion := range batch.Deletes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := fabric.ParseEndpointRef(deletion.Ref.String()); err != nil {
			return nil, err
		}
		e, exists := get(next.refs, deletion.Ref.String())
		if !exists {
			return nil, fabric.NewError(fabric.CodeNotFound, "Search document not found")
		}
		if e.revision != deletion.ExpectedRevision {
			return nil, ErrRevisionConflict
		}
		if e.value == nil {
			continue
		}
		old := e.value
		keys := keysUnion(old, nil)
		next.root = updateNode(next.root, 0, next.span, e.id, nil, keys, &p.Work)
		next.stats = adjustStats(next.stats, old, false)
		next.bytes -= old.encodedBytes
		e.value = nil
		next.refs = put(next.refs, deletion.Ref.String(), e)
		p.Work.Documents++
		p.Work.Terms += uint64(len(keys))
	}
	next.number = base.number + 1
	if next.number == 0 {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Index generation exhausted")
	}
	next.cursor = batch.UpstreamCursor
	sourceOrder := ""
	if b.replayOrder != nil {
		sourceOrder = b.replayOrder.Format
	}
	p.record = CommitRecord{SourceOrder: sourceOrder, SourceSequence: next.sourceSequence, Tokenizer: TokenizerVersion, Scorer: ScorerVersion, Parameters: b.parameters, Format: FormatVersion, BaseGeneration: base.number, Generation: next.number, Batch: batch}
	hash, err := hashRecord(p.record)
	if err != nil {
		return nil, err
	}
	p.record.SHA256 = hash
	next.commitHash = hash
	return p, nil
}
func (b *Backend) Publish(ctx context.Context, p *Prepared, commit CommitFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.publish(ctx, p, commit)
}
func (b *Backend) publish(ctx context.Context, p *Prepared, commit CommitFunc) error {
	if p == nil || p.owner != b || b.current.Load() != p.base {
		return ErrStaleGeneration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if commit != nil {
		if err := commit(ctx, p.Record()); err != nil {
			return err
		}
	}
	b.current.Store(p.next)
	return nil
}
func (b *Backend) apply(ctx context.Context, batch Batch, preserveCursor bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	base := b.current.Load()
	if preserveCursor {
		batch.UpstreamCursor = base.cursor
	}
	p, err := b.prepare(ctx, base, batch)
	if err != nil {
		return err
	}
	return b.publish(ctx, p, b.commit)
}
func (b *Backend) Apply(ctx context.Context, batch Batch) error { return b.apply(ctx, batch, false) }
func (b *Backend) Upsert(ctx context.Context, d fabric.SearchDocument) error {
	return b.apply(ctx, Batch{Upserts: []fabric.SearchDocument{d}}, true)
}
func (b *Backend) Delete(ctx context.Context, ref fabric.EndpointRef, revision fabric.Revision) error {
	return b.apply(ctx, Batch{Deletes: []Deletion{{ref, revision}}}, true)
}
func (b *Backend) Restore(ctx context.Context, r CommitRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	hash, err := hashRecord(r)
	if err != nil {
		return err
	}
	orderFormat := ""
	if b.replayOrder != nil {
		orderFormat = b.replayOrder.Format
	}
	if r.SourceOrder != orderFormat || (b.replayOrder == nil && r.SourceSequence != 0) || r.Tokenizer != TokenizerVersion || r.Scorer != ScorerVersion || r.Parameters != b.parameters || r.Format != FormatVersion || r.SHA256 != hash || r.Generation != r.BaseGeneration+1 || r.Generation == 0 {
		return fabric.NewError(fabric.CodeInvalidInput, "Corrupt index generation record")
	}
	current := b.current.Load()
	if current.number == r.Generation && current.commitHash == r.SHA256 {
		return nil
	}
	if current.number != r.BaseGeneration {
		return ErrStaleGeneration
	}
	p, err := b.prepare(ctx, current, r.Batch)
	if err != nil {
		return err
	}
	if p.record.SHA256 != r.SHA256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Index replay generation differs")
	}
	return b.publish(ctx, p, nil)
}

// IndexRevision reads the current generation without retrieval or model work.
func (b *Backend) IndexRevision(ctx context.Context) (fabric.Revision, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return revision(b.current.Load()), nil
}
func (b *Backend) CurrentCursor() string { return b.current.Load().cursor }
func revision(g *generation) fabric.Revision {
	return fabric.Revision(fmt.Sprintf("lex-v1:%d", g.number))
}
func (b *Backend) Stats(ctx context.Context) (fabric.SearchStats, error) {
	if err := ctx.Err(); err != nil {
		return fabric.SearchStats{}, err
	}
	g := b.current.Load()
	return fabric.SearchStats{Documents: g.stats.count, IndexBytes: g.bytes, PostingsVisited: b.visited.Load(), CandidatesVisited: b.candidates.Load()}, nil
}
func (b *Backend) NewVisibility(ctx context.Context, refs []fabric.EndpointRef, authorityRevision fabric.Revision) (*Visibility, error) {
	if len(refs) > int(MaxDocuments) || len(authorityRevision) > 256 || !utf8.ValidString(string(authorityRevision)) {
		return nil, fabric.NewError(fabric.CodeInvalidInput, "Visibility bounds exceeded")
	}
	g := b.current.Load()
	v := &Visibility{generation: g, authorityRevision: authorityRevision}
	seen := map[uint64]bool{}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e, ok := get(g.refs, ref.String())
		if !ok || e.value == nil {
			return nil, fabric.NewError(fabric.CodeNotFound, "Visibility reference is not indexed")
		}
		if seen[e.id] {
			continue
		}
		seen[e.id] = true
		v.set = setAdd(v.set, 0, g.span, e.id, &v.ConstructionWork)
		v.stats = adjustStats(v.stats, e.value, true)
		v.ConstructionWork.Documents++
		v.ConstructionWork.Terms += uint64(len(e.value.terms))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identities := make([]string, 0, len(seen))
	for _, ref := range refs {
		identities = append(identities, ref.String())
	}
	sort.Strings(identities)
	identities = unique(identities)
	raw, _ := json.Marshal(identities)
	digest := sha256.Sum256(raw)
	v.fingerprint = hex.EncodeToString(digest[:])
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return v, nil
}

// Internal document filtering keys are separate from lexical terms.
func filterGroups(r fabric.DiscoverRequest) [][]string {
	groups := [][]string{}
	for _, field := range []struct {
		prefix string
		values []string
	}{{"k:", r.Filters.Kinds}, {"g:", r.Filters.Tags}, {"p:", r.Filters.Providers}, {"d:", r.Scope.Domains}} {
		if len(field.values) > 0 {
			keys := make([]string, len(field.values))
			for i, s := range field.values {
				keys[i] = field.prefix + s
			}
			groups = append(groups, keys)
		}
	}
	return groups
}
func unsupported(q string) bool { return strings.ContainsAny(q, "\"\x00:") }
