// Package semantic provides optional explicitly selected embedding and ANN adapters.
// It does not install models/processes, infer access or expose invocation schemas.
package semantic

import (
	"context"
	"errors"
	"math"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/hybrid"
)

var ErrIndexNotReady = errors.New("semantic ANN generation is not indexed and ready")
var ErrInvalidVector = errors.New("embedding vector count, dimensions or finite cosine norm is invalid")

type EmbeddingIdentity struct {
	Provider, Model, Version string
	Dimensions               int
}
type EmbeddingProvider interface {
	Identity() EmbeddingIdentity
	Embed(context.Context, []string) ([][]float32, error)
}
type Disclosure struct {
	Stage, Provider string
	Identity        EmbeddingIdentity
	Documents       []fabric.SearchDocument
	Query           string
}
type DisclosureGate func(context.Context, Disclosure) error
type VectorPoint struct {
	Key                    string
	Ref                    fabric.EndpointRef
	Revision               fabric.Revision
	Vector                 []float32
	Domain, Kind, Provider string
	Model                  string
	Tags                   []string
	From                   uint64
}
type VectorQuery struct {
	Vector                          []float32
	Generation                      uint64
	Model                           string
	Domains, Kinds, Providers, Tags []string
	Limit, Ef                       int
}
type VectorHit struct {
	Ref      fabric.EndpointRef
	Revision fabric.Revision
	Score    float64
}
type Usage struct {
	Reported                                                    bool
	CPU, VectorReads, VectorWrites, PayloadReads, PayloadWrites uint64
}
type VectorResult struct {
	Hits  []VectorHit
	Usage Usage
}
type ANNSnapshot struct{ Name, SHA256, IndexIdentity string }

// ANNIndex is an explicit selected service. ResetStage removes only the next
// unpublished indexed generation, never the authoritative published generation.
// The registry/composition must hold single-writer source ownership across calls.
type ANNIndex interface {
	Identity() string
	ResetStage(context.Context, uint64) error
	Stage(context.Context, uint64, []VectorPoint, []string) error
	Ready(context.Context) error
	Count(context.Context, uint64, string) (uint64, error)
	Query(context.Context, VectorQuery) (VectorResult, error)
	Snapshot(context.Context) (ANNSnapshot, error)
	VerifySnapshot(context.Context, ANNSnapshot) error
}
type Config struct {
	Embeddings                       EmbeddingProvider
	ANN                              ANNIndex
	DisclosureGate                   DisclosureGate
	IndexGate                        func(context.Context, []fabric.SearchDocument) error
	CandidateGate                    hybrid.CandidateGate
	CatalogConfig                    search.Config
	Commit                           search.CommitFunc
	Horizon, Ef                      int
	PagerMaxSnapshots, PagerMaxBytes int
	CursorKey                        []byte
}

func validateVectors(vectors [][]float32, count, dimensions int) error {
	if len(vectors) != count {
		return ErrInvalidVector
	}
	for _, v := range vectors {
		if len(v) != dimensions {
			return ErrInvalidVector
		}
		norm := float64(0)
		for _, n := range v {
			f := float64(n)
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return ErrInvalidVector
			}
			norm += f * f
		}
		if norm == 0 || math.IsNaN(norm) || math.IsInf(norm, 0) {
			return ErrInvalidVector
		}
	}
	return nil
}
