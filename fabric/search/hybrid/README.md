# Optional bounded hybrid discovery

`New(Config)` composes an explicit lexical retriever, optional semantic retriever
and optional reranker. It does not download a model, instantiate a cloud provider,
upload a corpus or automatically invoke any returned endpoint. Providers have
operator-selected identities and versions. A semantic index must already represent
the authorized owner-local universe; indexing/export policy belongs to its owner.
`search.Backend` supplies the lexical implementation and cheap `IndexRevision`.

Each retriever returns at most its configured horizon (1..100). Weighted
reciprocal-rank fusion combines those lists as `weight / (constant + rank)`,
with canonical endpoint reference ties and a final fusion horizon of 1..200.
Raw lexical, vector and reranker scores are not treated as interchangeable scales.
Fusion/reranking is exact for this bounded pool, not the entire corpus under a
new global scorer. Page size remains separately bounded by the discovery request.
Lexical-only composition delegates the backend's exact ranking and cursors.

`CandidateGate` is injected policy composition. It receives bounded compact
candidates and returns a permitted subset plus **authenticated** scope identity
and policy revision. Those values never come from request labels. The gate runs
at query admission, after each retrieval, before reranking and after reranking.
It can filter but cannot introduce targets, rewrite metadata/revisions or alter
the retained order/scores. The node still owns the final current-revision and
invoke authority barrier; discovery is not an authorization grant.

Every explicitly external provider also requires `DisclosureGate`. Before an
external retriever receives the query it must approve query-only disclosure;
that call contains no candidate metadata. Before an external reranker receives
metadata it approves the already-gated compact candidate pool. No invocation
schemas/credentials are available to this package. Provider/reranker arguments
are isolated copies. Reranker outputs must be a finite-score unique subset of
input refs at exact input revisions; original trusted documents are retained.
Provider errors fail explicitly, without silently selecting another model.

Hybrid paging retains the bounded ranked pool in an ephemeral authenticated
snapshot. Limits configure count (default64/max4096), serialized compact-content
bytes (default4MiB/max64MiB) and TTL (default5min/max1h). This byte accounting is
not a heap/RSS claim; candidate horizons also bound per-entry object counts.
Oldest snapshots are evicted to satisfy both count and byte budgets. Random
snapshot IDs and HMAC cursors bind query/scope/filters/page size, provider
identity/version/config, authenticated caller universe/policy and page offset.
Each retained snapshot records all retrieved index revisions and the exact pool.

Before **each** subsequent page, current authority is checked, cheap provider
`CurrentRevision` callbacks must match the recorded revisions, and every page
candidate is gated again. Changed/expired/evicted snapshots, changed caller,
policy/index/query or forged cursors fail stale; providers are never rerun to
hide staleness. A provider lacking a cheap freshness callback cannot configure
hybrid paging. Reranker/model calls run only once for the snapshot. Snapshots
are not persisted; restart invalidates them even when an explicit cursor key is
retained. Omitted key generates a private random key; supplied keys require
32..4096 bytes and must remain private.

Tests exercise denial before external query/rerank disclosure, candidate subset
and finite-score validation, immutable metadata, cancellation, exact lexical
paging, hybrid no-repeat paging, authority/index revocation, tampering, expiry,
eviction, byte/count limits and deterministic fusion. A separately graded
16-document/6-query corpus compares actual lexical BM25 with an explicit fixed
concept-cosine test provider: mean Recall@2/MRR/NDCG@2 is 0.333 lexical and1.0
hybrid. This synthetic transparent fixture verifies fusion and relevance metrics;
it is not evidence of arbitrary embedding quality or production semantic scale.
