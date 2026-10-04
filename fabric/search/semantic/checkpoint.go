package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric/search"
)

type CheckpointHeader struct {
	Format    uint32
	Embedding EmbeddingIdentity
	ANN       ANNSnapshot
	Catalog   search.CheckpointHeader
	SHA256    string
}
type Checkpoint struct {
	header  CheckpointHeader
	catalog *search.Checkpoint
}

func (c *Checkpoint) Header() CheckpointHeader { return c.header }
func (c *Checkpoint) Page(ctx context.Context, section, after string, limit int) (search.CheckpointPage, error) {
	return c.catalog.Page(ctx, section, after, limit)
}
func checksum(h CheckpointHeader) string {
	h.SHA256 = ""
	raw, _ := json.Marshal(h)
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

// Checkpoint is explicit maintenance. The selected ANN service owns durable
// vector snapshot bytes; local descriptor/revision pages remain bounded.
func (b *Backend) Checkpoint(ctx context.Context) (*Checkpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkProviders(); err != nil {
		return nil, err
	}
	if err := b.config.DisclosureGate(ctx, Disclosure{Stage: "index-checkpoint", Provider: b.annIdentity, Identity: b.identity}); err != nil {
		return nil, err
	}
	if err := b.config.ANN.Ready(ctx); err != nil {
		return nil, err
	}
	catalog, err := b.catalog.Checkpoint(ctx)
	if err != nil {
		return nil, err
	}
	count, err := b.config.ANN.Count(ctx, catalog.Header().Generation, modelFingerprint(b.identity))
	if err != nil {
		return nil, err
	}
	if count != catalog.Header().LiveDocuments {
		return nil, errors.New("ANN/catalog committed generation count mismatch")
	}
	ann, err := b.config.ANN.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	h := CheckpointHeader{Format: 1, Embedding: b.identity, ANN: ann, Catalog: catalog.Header()}
	h.SHA256 = checksum(h)
	return &Checkpoint{header: h, catalog: catalog}, nil
}

// Load constructs private catalog state, verifies the complete checkpoint and
// durable tail, then checks the selected ANN service before returning. It never
// overwrites/restores a live remote collection or downloads server-provided URLs.
// If vector storage was lost, the operator must explicitly recover its referenced
// provider-owned snapshot first; a missing/changed snapshot fails closed.
func Load(ctx context.Context, c Config, h CheckpointHeader, pages search.CheckpointLoader, tail func(context.Context) (search.CommitRecord, bool, error)) (*Backend, error) {
	b, err := New(c)
	if err != nil {
		return nil, err
	}
	if h.Format != 1 || h.Embedding != b.identity || h.SHA256 != checksum(h) || h.ANN.IndexIdentity != b.annIdentity {
		return nil, errors.New("semantic checkpoint identity/commitment mismatch")
	}
	if err = b.config.DisclosureGate(ctx, Disclosure{Stage: "index-checkpoint-restore", Provider: b.annIdentity, Identity: b.identity}); err != nil {
		return nil, err
	}
	if err = b.config.ANN.VerifySnapshot(ctx, h.ANN); err != nil {
		return nil, err
	}
	if err = b.catalog.RestoreCheckpoint(ctx, h.Catalog, pages); err != nil {
		return nil, err
	}
	generation := h.Catalog.Generation
	if tail != nil {
		for {
			record, ok, e := tail(ctx)
			if e != nil {
				return nil, e
			}
			if !ok {
				break
			}
			if e = b.catalog.Restore(ctx, record); e != nil {
				return nil, e
			}
			generation = record.Generation
		}
	}
	if err = b.config.ANN.Ready(ctx); err != nil {
		return nil, err
	}
	stats, err := b.catalog.Stats(ctx)
	if err != nil {
		return nil, err
	}
	count, err := b.config.ANN.Count(ctx, generation, modelFingerprint(b.identity))
	if err != nil {
		return nil, err
	}
	if count != stats.Documents {
		return nil, errors.New("restored ANN/catalog live generation mismatch")
	}
	b.generation.Store(generation)
	return b, nil
}
