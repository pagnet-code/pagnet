# Optional semantic retrieval

This package implements `fabric.SearchBackend` using an explicitly selected embedding provider and indexed ANN service. Lexical search remains standalone. Construction installs no process, downloads no model, pulls no container, and invokes no endpoint discovered through Pagnet.

`New` requires `EmbeddingProvider`, `ANNIndex`, `IndexGate`, `CandidateGate`, and `DisclosureGate`. The concrete adapters are Qdrant REST and Ollama `/api/embed`; neither is mandatory. Operator credentials remain adapter-private. Remote plaintext HTTP requires explicit opt-in, redirects are disabled, responses/requests are bounded, and errors omit private inputs and remote response bodies. Ollama verifies the installed model, optionally its exact digest, before and after embedding. It never pulls models or silently switches devices/providers.

## Publication and authority

The trusted registry composition owns single-writer admission/CAS and authenticated policy. The search package never grants access. `Apply` prepares the compact local catalog, gates changed old/new descriptors, separately approves document embedding and ANN disclosure, stages an unpublished generation, requires indexed readiness, then calls the configured durable `search.CommitFunc` before exposing that generation. Failed staging is reset only for the unpublished generation; a matching ready/commit retry avoids repeating embeddings. Other processes must not write the collection outside its authoritative source ownership contract.

Descriptions are compact search documents, not full invocation schemas, configuration, or credentials. Query embedding and ANN query disclosures require separate approvals. Candidate gates run before results leave the backend and before hybrid external reranking. Node composition must still fresh-read registry state and enforce its final policy barrier; an ANN hit never authorizes invocation. Filter mismatch, unknown reference, stale revision, duplicate hit, and nonfinite score fail closed.

## Indexed queries and paging

Queries use indexed domain/kind/provider/tag/model and generation filters, `indexed_only: true`, `exact: false`, a bounded horizon (1–100), HNSW ef (horizon–4096), and a context-bounded query deadline (default 15 seconds, configurable 1–60 seconds). No collection scroll or exhaustive fallback occurs during queries. Qdrant can exactly score an indexed eligible subset below its minimum supported `full_scan_threshold` of 10 KiB; this is a bounded small-subset optimization, not a whole-registry fallback. ANN recall is approximate and no universal constant graph-visit claim is made.

`Setup` explicitly creates the selected collection/indexes; constructors and queries never create it automatically. Required configuration is cosine vectors, HNSW M16/ef_construct128, indexing threshold1 KiB, full-scan threshold10 KiB, and indexed metadata. Strict mode permits maintenance exact counts, caps query limits/ef, and forbids unindexed filters. `Ready` checks configuration and all points indexed; warming returns `ErrIndexNotReady` immediately. The caller chooses a bounded maintenance schedule/retry, never infinite background readiness.

Pagination uses the shared bounded authenticated snapshot pager. Its defaults are 64 snapshots, 4 MiB total encoded state, and five minutes. Cursors bind query/filter/scope, authenticated policy revision, provider identities, source generation and ranked horizon. Every later page rechecks authority/current document revisions; it makes no second paid embedding or ANN query. Restart, eviction, expiry, policy changes, and catalog generation changes invalidate the cursor. Paging covers the configured retrieval horizon, not an exhaustive global ranking.

`LastUsage` preserves actual Qdrant hardware counters when enabled; `Reported: false` explicitly means the provider supplied no counters. These are provider work counters, not graph-visit counts. Catalog statistics are logical compact JSON bytes, not total process/server memory.

## Durable recovery

A checkpoint pins local compact catalog pages and the selected provider snapshot name/hash/identity. `Load` builds private state, checks the complete catalog plus durable commit tail, verifies provider snapshot bytes using a bounded streaming hash, and checks the generation/model live count before returning a visible backend. Exact counts and snapshot scans are maintenance, not query work. Snapshot bytes remain owned by the selected ANN service; loss of its vector storage requires explicit operator recovery of that snapshot first. `Load` never overwrites a live remote collection or follows server-provided URLs. Historical vector versions remain provider storage until explicit operator maintenance; checkpointing does not purge authoritative registry ownership/history.

## Verification

Ordinary `go test ./fabric/search/...` uses local fault fixtures and never calls a model/service. Opt-in fixtures use `QDRANT_TEST_URL`, `OLLAMA_TEST_URL`, and installed model settings. `ANN_SCALE=1` enables the actual HNSW scale harness (default10k/100k/1M, optionally `ANN_SCALE_SIZES`). Synthetic32-dimensional vectors are compared to an exhaustive cosine oracle outside timed queries; those scores measure ANN recall only. The separate installed-model language fixture compares semantic/lexical retrieval over a small independently graded English role corpus; it does not establish broad language/model quality.

The verified development service is [Qdrant v1.19.1](https://github.com/qdrant/qdrant/tree/v1.19.1), Apache-2.0, via REST, with no added Go dependencies. [Qdrant search configuration](https://qdrant.tech/documentation/guides/optimize/) and [Ollama embedding API](https://docs.ollama.com/api/embed) define the selected adapter protocols. Providers are explicit operator dependencies, never silently installed customer infrastructure.
