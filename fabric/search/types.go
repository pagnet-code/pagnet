// Package search provides a replaceable, owner-local exact lexical backend.
// An instance indexes a trusted discovery-visible universe, not an authority
// policy. Compact documents never contain invocation schemas or credentials.
package search

import (
	"context"
	"errors"
	"github.com/pagnet-code/pagnet/fabric"
	"unicode"
)

const (
	ScorerVersion           = "bm25-positive-v1"
	FormatVersion    uint32 = 1
	TokenizerVersion        = "unicode-" + unicode.Version + "-letter-number-lower-v1"
	MaxDocuments     uint64 = 1 << 30
	MaxDocumentBytes        = 16384
	MaxQueryTerms           = 64
	leafSize         uint64 = 32
)

const (
	MaxBatchDocuments        = 4096
	MaxCommitBytes           = 64 << 20
	MaxRevisions      uint64 = 1 << 32
)

var (
	ErrStaleGeneration  = errors.New("search generation changed; prepare a fresh update or page")
	ErrRevisionConflict = errors.New("search descriptor revision conflicts with current or previously committed content")
	ErrUnsupportedQuery = errors.New("search supports OR/AND bags of terms; phrase and field syntax are not supported")
)

type Parameters struct{ K1, B float64 }
type Config struct {
	Parameters  *Parameters
	Commit      CommitFunc
	ReplayOrder *ReplayOrder
}

// ReplayOrder is an explicit trusted source contract, not an interpretation
// of opaque descriptor revisions. The source must attest monotonic committed
// cursors and reject stale/forged descriptors through CommitFunc.
type ReplayOrder struct {
	Format   string
	Sequence func(string) (uint64, error)
}

var ErrReplayBeforeFloor = errors.New("search publication cursor is at or below the committed replay boundary")

type Deletion struct {
	Ref              fabric.EndpointRef `json:"ref"`
	ExpectedRevision fabric.Revision    `json:"expectedRevision"`
}
type Batch struct {
	Upserts        []fabric.SearchDocument `json:"upserts,omitempty"`
	Deletes        []Deletion              `json:"deletes,omitempty"`
	UpstreamCursor string                  `json:"upstreamCursor,omitempty"`
}

// CommitRecord is one exact versioned generation delta. Its checksum covers all
// fields except SHA256. The registry owns durable storage, atomic outbox/cursor
// commits, fsync policy and compaction; memory publication follows that commit.
type CommitRecord struct {
	SourceOrder    string     `json:"sourceOrder"`
	SourceSequence uint64     `json:"sourceSequence"`
	Tokenizer      string     `json:"tokenizer"`
	Scorer         string     `json:"scorer"`
	Parameters     Parameters `json:"parameters"`
	Format         uint32     `json:"format"`
	BaseGeneration uint64     `json:"baseGeneration"`
	Generation     uint64     `json:"generation"`
	Batch          Batch      `json:"batch"`
	SHA256         string     `json:"sha256"`
}
type CommitFunc func(context.Context, CommitRecord) error
type Operator string

const (
	OR  Operator = "or"
	AND Operator = "and"
)

type Options struct {
	Operator   Operator
	Visibility *Visibility
	// FinalValidate belongs to trusted composition/policy. It must revalidate
	// current discovery authority before any pinned candidates are returned.
	FinalValidate func(context.Context, fabric.Revision) error
}
type Work struct {
	Roots, Nodes, Edges, ScorePrunes, TiePrunes, EligibilityPrunes, SummaryLookups        uint64
	LeafSlots, Postings, ScoredDocuments, MembershipProbes, HeapOperations, DocumentLoads uint64
	DictionaryNodes, StatisticsLookups, TermProbes                                        uint64
}
type PublicationWork struct{ Documents, Terms, HierarchyNodes, SummaryUpdates, EncodedBytes uint64 }

// Visibility is an immutable indexed eligibility/ranking view. It shares the
// posting hierarchy; only eligible IDs and visible corpus statistics are held.
// Build it outside the query from authenticated policy's exact visible refs.
// The backend never infers authorization from a label, domain or query filter.
type Visibility struct {
	generation        *generation
	set               *idSet
	stats             corpus
	authorityRevision fabric.Revision
	fingerprint       string
	ConstructionWork  PublicationWork
}

func (v *Visibility) AuthorityRevision() fabric.Revision { return v.authorityRevision }
