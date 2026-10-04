package search

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/pagnet-code/pagnet/fabric"
	"hash"
	"strings"
)

const (
	CheckpointReferences = "refs"
	CheckpointRevisions  = "revisions"
)

type CheckpointHeader struct {
	SourceOrder      string     `json:"sourceOrder"`
	SourceSequence   uint64     `json:"sourceSequence"`
	ReplayFloor      uint64     `json:"replayFloor"`
	Format           uint32     `json:"format"`
	Tokenizer        string     `json:"tokenizer"`
	Scorer           string     `json:"scorer"`
	Parameters       Parameters `json:"parameters"`
	Generation       uint64     `json:"generation"`
	NextID           uint64     `json:"nextId"`
	Span             uint64     `json:"span"`
	UpstreamCursor   string     `json:"upstreamCursor"`
	RootCommitSHA256 string     `json:"rootCommitSHA256"`
	ReferenceRows    uint64     `json:"referenceRows"`
	RevisionRows     uint64     `json:"revisionRows"`
	LiveDocuments    uint64     `json:"liveDocuments"`
	TotalLength      uint64     `json:"totalLength"`
	SHA256           string     `json:"sha256"`
}
type CheckpointReference struct {
	Ref       fabric.EndpointRef     `json:"ref"`
	StorageID uint64                 `json:"storageId"`
	Revision  fabric.Revision        `json:"revision"`
	Document  *fabric.SearchDocument `json:"document"`
}
type CheckpointRevision struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}
type CheckpointPage struct {
	Generation uint64                `json:"generation"`
	Section    string                `json:"section"`
	After      string                `json:"after"`
	Next       string                `json:"next"`
	References []CheckpointReference `json:"references,omitempty"`
	Revisions  []CheckpointRevision  `json:"revisions,omitempty"`
	SHA256     string                `json:"sha256"`
}
type CheckpointLoader func(context.Context, string, string, int) (CheckpointPage, error)
type Checkpoint struct {
	generation *generation
	base       *generation
	header     CheckpointHeader
}

func (c *Checkpoint) Header() CheckpointHeader { return c.header }
func checksumPage(p CheckpointPage) (string, error) {
	p.SHA256 = ""
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if len(data) > MaxCommitBytes {
		return "", fabric.NewError(fabric.CodeInvalidInput, "Checkpoint page byte budget exceeded")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func hashFrame(h hash.Hash, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	h.Write(size[:])
	h.Write(data)
	return nil
}
func hashHeader(header CheckpointHeader) (hash.Hash, error) {
	header.SHA256 = ""
	h := sha256.New()
	h.Write([]byte("pagnet.fabric.search-checkpoint.v1\x00"))
	return h, hashFrame(h, header)
}
func each[V any](ctx context.Context, n *dictionary[V], visit func(string, V) error) error {
	if n == nil {
		return ctx.Err()
	}
	if err := each(ctx, n.left, visit); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := visit(n.key, n.value); err != nil {
		return err
	}
	return each(ctx, n.right, visit)
}
func referenceRow(ref string, e entry) CheckpointReference {
	parsed, err := fabric.ParseEndpointRef(ref)
	if err != nil {
		panic("validated internal reference became invalid")
	}
	r := CheckpointReference{Ref: parsed, StorageID: e.id, Revision: e.revision}
	if e.value != nil {
		d := cloneDocument(e.value.doc)
		r.Document = &d
	}
	return r
}

// Checkpoint scans the pinned current state only during explicit maintenance.
// Its digest is pagination-independent; writes and queries need no full scan.
func (b *Backend) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	return b.makeCheckpoint(ctx, false)
}

// CheckpointAtReplayFloor is available only for an explicit ordered source. It
// preserves current and tombstoned revision digests, drops superseded hashes,
// and prevents publication of any cursor at or below this committed floor.
func (b *Backend) CheckpointAtReplayFloor(ctx context.Context) (*Checkpoint, error) {
	return b.makeCheckpoint(ctx, true)
}
func (b *Backend) makeCheckpoint(ctx context.Context, compactHistory bool) (*Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := b.current.Load()
	g := base
	sourceOrder := ""
	if b.replayOrder != nil {
		sourceOrder = b.replayOrder.Format
	}
	if compactHistory {
		if b.replayOrder == nil || g.sourceSequence == 0 {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Replay floor requires an attested ordered source cursor")
		}
		copy := *g
		copy.seen = nil
		copy.versions = 0
		copy.replayFloor = g.sourceSequence
		if err := each(ctx, g.refs, func(ref string, e entry) error {
			key := ref + "\x00" + string(e.revision)
			digest, ok := get(g.seen, key)
			if !ok {
				return fabric.NewError(fabric.CodeProtocolError, "Current revision digest missing")
			}
			copy.seen = put(copy.seen, key, digest)
			copy.versions++
			return nil
		}); err != nil {
			return nil, err
		}
		g = &copy
	}
	header := CheckpointHeader{SourceOrder: sourceOrder, SourceSequence: g.sourceSequence, ReplayFloor: g.replayFloor, Format: FormatVersion, Tokenizer: TokenizerVersion, Scorer: ScorerVersion, Parameters: b.parameters, Generation: g.number, NextID: g.nextID, Span: g.span, UpstreamCursor: g.cursor, RootCommitSHA256: g.commitHash, ReferenceRows: g.nextID, RevisionRows: g.versions, LiveDocuments: g.stats.count, TotalLength: g.stats.totalLength}
	h, err := hashHeader(header)
	if err != nil {
		return nil, err
	}
	if err = each(ctx, g.refs, func(ref string, e entry) error { return hashFrame(h, referenceRow(ref, e)) }); err != nil {
		return nil, err
	}
	if err = each(ctx, g.seen, func(key, digest string) error { return hashFrame(h, CheckpointRevision{key, digest}) }); err != nil {
		return nil, err
	}
	header.SHA256 = hex.EncodeToString(h.Sum(nil))
	return &Checkpoint{generation: g, base: base, header: header}, nil
}

// seekRows visits O(log N + limit) nodes. It neither builds a catalogue-sized
// list nor starts from the beginning for each page.
func seekRows[V any](ctx context.Context, n *dictionary[V], after string, limit int, rows *[]struct {
	key   string
	value V
}) error {
	if n == nil || len(*rows) >= limit {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n.key <= after {
		return seekRows(ctx, n.right, after, limit, rows)
	}
	if err := seekRows(ctx, n.left, after, limit, rows); err != nil {
		return err
	}
	if len(*rows) < limit {
		*rows = append(*rows, struct {
			key   string
			value V
		}{n.key, n.value})
	}
	return seekRows(ctx, n.right, after, limit, rows)
}
func (c *Checkpoint) Page(ctx context.Context, section, after string, limit int) (CheckpointPage, error) {
	p := CheckpointPage{Generation: c.header.Generation, Section: section, After: after}
	if limit < 1 || limit > MaxBatchDocuments || len(after) > 1024 {
		return p, fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint page request")
	}
	switch section {
	case CheckpointReferences:
		rows := []struct {
			key   string
			value entry
		}{}
		if err := seekRows(ctx, c.generation.refs, after, limit+1, &rows); err != nil {
			return p, err
		}
		if len(rows) > limit {
			p.Next = rows[limit-1].key
			rows = rows[:limit]
		}
		for _, row := range rows {
			p.References = append(p.References, referenceRow(row.key, row.value))
		}
	case CheckpointRevisions:
		rows := []struct {
			key   string
			value string
		}{}
		if err := seekRows(ctx, c.generation.seen, after, limit+1, &rows); err != nil {
			return p, err
		}
		if len(rows) > limit {
			p.Next = rows[limit-1].key
			rows = rows[:limit]
		}
		for _, row := range rows {
			p.Revisions = append(p.Revisions, CheckpointRevision{row.key, row.value})
		}
	default:
		return p, fabric.NewError(fabric.CodeInvalidInput, "Unknown checkpoint section")
	}
	sum, err := checksumPage(p)
	if err != nil {
		return p, err
	}
	p.SHA256 = sum
	return p, nil
}
func validDigest(text string) bool {
	if len(text) != 64 {
		return false
	}
	raw, err := hex.DecodeString(text)
	return err == nil && len(raw) == 32 && text == strings.ToLower(text)
}

// RestoreCheckpoint constructs detached state, checks its complete commitment
// and only then publishes it. Registry storage authenticates the committed head;
// these SHA256 checks detect corruption, not a new authentication protocol.
func (b *Backend) RestoreCheckpoint(ctx context.Context, header CheckpointHeader, load CheckpointLoader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	base := b.current.Load()
	sourceOrder := ""
	if b.replayOrder != nil {
		sourceOrder = b.replayOrder.Format
	}
	if header.SourceOrder != sourceOrder || header.ReplayFloor > header.SourceSequence || (b.replayOrder == nil && (header.SourceSequence != 0 || header.ReplayFloor != 0)) {
		return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint ordered source mismatch")
	}
	if b.replayOrder != nil && header.Generation > 0 {
		sequence, err := b.replayOrder.Sequence(header.UpstreamCursor)
		if err != nil || sequence != header.SourceSequence {
			return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint ordered cursor mismatch")
		}
	}
	if header.Generation == 0 && (header.NextID != 0 || header.RevisionRows != 0 || header.SourceSequence != 0 || header.ReplayFloor != 0 || header.UpstreamCursor != "" || header.LiveDocuments != 0 || header.TotalLength != 0) {
		return fabric.NewError(fabric.CodeInvalidInput, "Initial checkpoint must be empty")
	}
	if header.Generation < base.number || (header.Generation == base.number && header.RootCommitSHA256 != base.commitHash) {
		return ErrStaleGeneration
	}
	if header.Format != FormatVersion || header.Tokenizer != TokenizerVersion || header.Scorer != ScorerVersion || header.Parameters != b.parameters || header.NextID > MaxDocuments || header.Span < leafSize || header.Span > MaxDocuments || header.Span&(header.Span-1) != 0 || header.NextID > header.Span || header.ReferenceRows != header.NextID || header.RevisionRows > MaxRevisions || header.LiveDocuments > header.ReferenceRows || header.TotalLength > header.LiveDocuments*MaxDocumentBytes || !validDigest(header.SHA256) || (header.Generation == 0 && header.RootCommitSHA256 != "") || (header.Generation > 0 && !validDigest(header.RootCommitSHA256)) || len(header.UpstreamCursor) > 4096 || load == nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint header")
	}
	next := &generation{sourceSequence: header.SourceSequence, replayFloor: header.ReplayFloor, number: header.Generation, nextID: header.NextID, span: header.Span, cursor: header.UpstreamCursor, commitHash: header.RootCommitSHA256, versions: header.RevisionRows}
	h, err := hashHeader(header)
	if err != nil {
		return err
	}
	counts := map[string]uint64{}
	var allocated *idSet
	work := PublicationWork{}
	for _, section := range []string{CheckpointReferences, CheckpointRevisions} {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := load(ctx, section, after, MaxBatchDocuments)
			if err != nil {
				return err
			}
			sum, err := checksumPage(page)
			if err != nil {
				return err
			}
			if page.SHA256 != sum || page.Section != section || page.Generation != header.Generation || page.After != after {
				return fabric.NewError(fabric.CodeInvalidInput, "Corrupt or mixed checkpoint page")
			}
			last := after
			rows := 0
			if section == CheckpointReferences {
				if len(page.Revisions) != 0 || len(page.References) > MaxBatchDocuments {
					return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint reference page")
				}
				for _, r := range page.References {
					ref := r.Ref.String()
					if _, err := fabric.ParseEndpointRef(ref); err != nil {
						return err
					}
					if ref <= last || r.StorageID >= header.NextID || r.Revision == "" || len(r.Revision) > 256 {
						return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint reference order/identity")
					}
					last = ref
					rows++
					counts[section]++
					before := uint64(0)
					if allocated != nil {
						before = allocated.count
					}
					allocated = setAdd(allocated, 0, header.Span, r.StorageID, &work)
					if allocated.count == before {
						return fabric.NewError(fabric.CodeInvalidInput, "Duplicate checkpoint storage identity")
					}
					e := entry{id: r.StorageID, revision: r.Revision}
					if r.Document != nil {
						if r.Document.Ref != r.Ref || r.Document.Revision != r.Revision {
							return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint descriptor identity differs")
						}
						value, _, err := compact(*r.Document)
						if err != nil {
							return err
						}
						e.value = value
						next.root = updateNode(next.root, 0, next.span, e.id, value, keysUnion(nil, value), &work)
						next.stats = adjustStats(next.stats, value, true)
						next.bytes += value.encodedBytes
					}
					next.refs = put(next.refs, ref, e)
					if err := hashFrame(h, r); err != nil {
						return err
					}
				}
			} else {
				if len(page.References) != 0 || len(page.Revisions) > MaxBatchDocuments {
					return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint revision page")
				}
				for _, r := range page.Revisions {
					if r.Key <= last || !validDigest(r.SHA256) {
						return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint revision order/digest")
					}
					parts := strings.SplitN(r.Key, "\x00", 2)
					if len(parts) != 2 || len(parts[1]) == 0 || len(parts[1]) > 256 {
						return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint revision identity")
					}
					if _, ok := get(next.refs, parts[0]); !ok {
						return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint revision lacks its reference")
					}
					last = r.Key
					rows++
					counts[section]++
					next.seen = put(next.seen, r.Key, r.SHA256)
					if err := hashFrame(h, r); err != nil {
						return err
					}
				}
			}
			if counts[CheckpointReferences] > header.ReferenceRows || counts[CheckpointRevisions] > header.RevisionRows {
				return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint row count exceeded")
			}
			if page.Next == "" {
				break
			}
			if rows == 0 || page.Next != last || page.Next <= after {
				return fabric.NewError(fabric.CodeInvalidInput, "Invalid checkpoint continuation")
			}
			after = page.Next
		}
	}
	if counts[CheckpointReferences] != header.ReferenceRows || counts[CheckpointRevisions] != header.RevisionRows || next.stats.count != header.LiveDocuments || next.stats.totalLength != header.TotalLength || hex.EncodeToString(h.Sum(nil)) != header.SHA256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Incomplete or corrupt checkpoint commitment")
	}
	if err = each(ctx, next.refs, func(ref string, e entry) error {
		digest, ok := get(next.seen, ref+"\x00"+string(e.revision))
		if !ok {
			return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint current revision missing")
		}
		if e.value != nil {
			_, expected, err := compact(e.value.doc)
			if err != nil {
				return err
			}
			if digest != expected {
				return fabric.NewError(fabric.CodeInvalidInput, "Checkpoint current descriptor digest differs")
			}
		}
		return nil
	}); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.current.Load() != base {
		return ErrStaleGeneration
	}
	b.current.Store(next)
	return nil
}

// ActivateCheckpoint is called only AFTER its head/rows were durably committed
// by the registry. It releases compacted in-memory hash state in constant time.
// A concurrently advanced index is never rolled back; its saved checkpoint plus
// durable tail remain valid for a future reopen.
func (b *Backend) ActivateCheckpoint(ctx context.Context, c *Checkpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || b.current.Load() != c.base {
		return ErrStaleGeneration
	}
	b.current.Store(c.generation)
	return nil
}
