# Local domain registry

`Bootstrap` creates an independent domain explicitly; `Open` never regenerates
an identity. Trusted composition supplies and pins the owner principal. Every
registry mutation, trust pin and import requires an authenticated context for
that domain and the exact pinned principal, kind and issuer. Invocation policy
and finalized dispatch admission remain separate engine responsibilities.

The root key lives in a private file, not SQLite, descriptors, adapters, prompts
or search documents. Linux/macOS use owner permissions, no-follow handles and a
lifetime nonblocking flock. Windows uses current-owner ACLs, rejects reparse
points, and holds a native nonblocking LockFileEx lock. Key publication uses a
flushed private temporary file, no replacement, and platform durability calls.
Windows compilation is verified; no Windows execution or power-loss proof is
claimed. Unsupported security or filesystem operations fail closed.

One serialized writer owns a state directory. Disconnected copies of the same
root are unsupported writable forks, not failover or consensus. Signed sequence,
previous head, CAS and retained tombstones reject conflicting imports. This does
not detect an offline clone before it communicates, or a complete old backup
without an external retained watermark. Independent disconnected writers create
independent domains. Restore, delegation, relocation and signing-key rotation
need explicit future authority contracts; they are not inferred here.

An update transaction holds the Store mutex, checks the authenticated owner,
reads the exact object and ledger head, reserves quota, and commits the signed
record, materialized revision and index outbox together. Exact mutation retries
return their committed revision; changed or stale retries fail. IDs never route
through aliases and retired refs cannot be reused. Offers own separate schemas
and revisions; their parent header carries no sibling schemas. Binding removal
requires explicit dependent-offer retirement. Parent retirement makes all its
offers unavailable and queues their index removal.

`DefaultOptions` supplies finite backpressure bounds. `BootstrapWithOptions`
and `OpenWithOptions` select larger or smaller explicit storage admissions;
smaller limits reject retained state, without purging it. SQLite page admission
also enforces the selected database cap. Key/genesis and canonical reference
bounds remain fixed. There is no automatic history or identity purge.

Search publication follows `PendingIndex` → backend `Prepare` → `Publish` with
`CommitIndex`. Search holds its publication lock before entering the Store
mutex. Registry calls never acquire the backend publication lock in reverse.
The commit callback validates the exact bounded outbox range, current generation
and prior indexed revisions, then commits its exact generation record, cursor
and metadata atomically. Memory visibility follows durable success. Stale index
candidates still require current registry revision and policy validation before
discovery output or invocation; a catalogue is not invocation authority.

Explicit `SaveCheckpoint` maintenance writes bounded pages from one immutable
index generation under an atomic SQLite transaction, then deletes only covered
index-generation bodies. A failed checkpoint retains the old checkpoint and
tail. Signed identity/tombstone/source records remain. `LoadIndex` creates a
private new backend and returns it only after complete checkpoint validation and
bounded tail replay; no partially recovered backend is returned. Startup streams
signed registry and outbox verification through private temporary SQLite
projections instead of accumulating descriptor bodies or old index generations.

Ordered hash-history compaction is opt-in through `IndexConfig` /
`OutboxReplayOrder`: `CheckpointAtReplayFloor` → `SaveCheckpoint` →
`ActivateCheckpoint`. The private source attests strict monotonic decimal
outbox cursors; `CommitIndex` rejects fabricated newer cursors with stale data.
Default search configuration retains its full opaque-revision hash protection.
