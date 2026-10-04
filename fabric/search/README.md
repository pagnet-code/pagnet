# Embedded lexical discovery

`Backend` implements `fabric.SearchBackend` without a relay, native library,
external process or model download. It indexes compact owner-local discovery
metadata. Invocation schemas, credentials and private endpoint configuration do
not belong in these documents.

## Ranking and indexed work

Queries tokenize Unicode letters/numbers, lowercase them and use positive BM25
with `K1=1.2`, `B=.75` by default. Tokenizer identity includes the Go Unicode
version; scorer/parameters are persisted and checked on restore. Terms match OR
by default; `SearchWithOptions` accepts explicit AND. Phrase/field syntax is
rejected. Equal scores sort by canonical endpoint reference. Tests compare the
ordered IDs and exact float64 score bits with an independent exhaustive scorer.

Immutable storage-ID range trees hold term frequency/document-length bounds,
metadata summaries and minimum canonical references. Best-first traversal uses
safe score bounds and reference tie bounds to skip losing subtrees. Fixed leaves
contain at most 32 entries. Updates replace affected tree/dictionary paths; they
do not rebuild the corpus or enumerate old index segments. Kind, provider,
domain and tag filtering is indexed and checked before a candidate is scored.

`Work` exposes visited nodes, summaries, dictionaries, leaf slots, terms,
candidates and heaps. Exact ranking does not guarantee sublinear work for every
adversarial corpus: loose bounds or disjoint filter summaries can require more
traversal. There is no hidden full-corpus sort or common-term LIMIT workaround.
Top-K memory is bounded by the requested limit (maximum 100), plus traversal
frontier. Cancellation checks bound traversal interruptions to a leaf.
`Stats.IndexBytes` is the sum of current compact document JSON bytes, **not**
resident heap or physical storage size.

## Authority, snapshots and paging

An instance represents a trusted discovery-visible universe. Search never grants
access based on a query, name, domain or filter. `NewVisibility` constructs an
indexed subset and its own visible BM25 corpus statistics from trusted refs. Its
construction cost is explicit and separate from query work; it must not be
repeated for every keystroke or copied as a complete index per principal.

`Options.FinalValidate` is the composition/policy hook to recheck current
visibility before returning pinned candidates. The node must additionally
resolve each candidate's current revision and authority before describe/invoke.
Neither a search hit nor its pinned descriptor authorizes invocation. A
publication, including checkpoint activation, invalidates existing visibility
objects; build a fresh view. Cursors bind generation, normalized query/operator,
parameters and the precise visibility fingerprint/revision. Changed generations
reject stale cursors rather than silently skipping or duplicating entries.

## Atomic publication and durability

`Prepare(ctx, Batch)` builds detached state. `Prepared.Record()` returns an
isolated versioned delta and checksum. `Publish(ctx, prepared, CommitFunc)` first
checks the prepared base, invokes the registry's durable transaction, and then
publishes memory. The callback must atomically commit descriptors, exact search
record, outbox/index watermark and cursor; it must not reenter the backend writer.
A callback failure exposes no staged state. Cancellation after successful durable
commit cannot prevent memory publication. `Restore` verifies exact version,
parameters, checksum and contiguous generation; exact committed retry is
idempotent. Separate stores do not become atomic merely by using this API.

Generic sources retain only SHA256 digests of all seen opaque revisions, together
with current/tombstoned ref entries; superseded descriptor bodies are not retained.
Conflicting revision reuse fails and old remembered revisions do not resurrect
retired refs. Historical entries have an explicit `MaxRevisions` bound and fail
with backpressure rather than silently evicting safety state. Publication batches
are capped at 4096 documents and compact documents at 16 KiB.

## Bounded checkpoint and ordered replay floor

`Checkpoint` pins one immutable generation. Header/page export computes a
pagination-independent commitment by streaming sorted rows. Export maintenance
may scan the corpus; hot queries and incremental writes do not. `Page` seeks by
key and emits bounded rows; no whole-million-document JSON blob is required.
`RestoreCheckpoint` reconstructs private state, validates ordered pages,
counts, physical identities, current revision hashes and the complete commitment,
and publishes only after the final page verifies. SHA detects corruption;
registry storage authenticates the checkpoint head. A startup composition should
build a private backend, restore checkpoint plus the complete durable tail, and
return it only after both succeed.

History compaction requires explicit `Config.ReplayOrder` with a versioned source
format and strict cursor-to-sequence function. Its owner must attest monotonic
committed cursors and authenticate every batch against the authoritative source
in `CommitFunc`. The backend does **not** infer revision ordering or accept a
claimed newer cursor as proof that stale descriptor content is current.
`CheckpointAtReplayFloor` retains each ref's current/tombstoned digest and sets
the floor to the attested source sequence. At/below-floor source publication is
rejected. Persist the checkpoint atomically first, then `ActivateCheckpoint`
releases old hash state with a constant-time base CAS. If another generation
advanced meanwhile, activation returns stale; the saved checkpoint plus durable
tail remains usable. Signed registry history and ownership/tombstones remain
separate and must not be purged by index maintenance. Ordered sources publish
with cursor-bearing batches; generic `Upsert`/`Delete` cannot invent cursors.

## Verification

Run `go test ./fabric/search -race` and `go vet ./fabric/search`. The opt-in
`SEARCH_SCALE=1 GOMAXPROCS=2 go test ./fabric/search -run '^TestScaleHarness$'
builds incremental 10k/100k/1M uniform/skew corpora, reports hot-query work, and
checks each top-20 result against an exhaustive oracle outside query timing.
`SEARCH_SCALE_SIZES` permits another comma-separated size set.

The measured 1M uniform common-term case visited 31 nodes and scored 32 documents;
the skew common+rare AND case visited 11,941 nodes and scored 1,004 documents.
All 18 scale cases matched the independent oracle. These are corpus-specific
measurements, not universal complexity claims. The entire harness reached about
3.21 GiB peak RSS, including retained source corpus, exhaustive oracle maps/sorts,
index and process overhead; it is not a measurement of backend-only resident
memory, and Go's `GOMEMLIMIT` is a soft target.
