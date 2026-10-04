# Local native authority

This package provides durable local identity/admission primitives backed by the
**same existing registry domain root**. It creates no cloud server, cloud account,
transport runner or cloud receipt. Production native worker/daemon adapters have
not been switched to this authority; an actual offline real-binary acceptance
fixture remains required before that support is advertised.

`New(store, fence)` requires an explicitly configured trusted admission fence.
The root is immutable key revision 1; key rotation is not implemented. Public
proofs are not credentials. Every mutation receives a genuinely authenticated
owner context and checks the registry's pinned principal, issuer and audience.
Caller contexts must verify exact ORIGINAL bytes against this domain's audience,
principal and authenticated provenance. A context from another node cannot pass
by supplying its own audience string.

- `AcquireController` advances a per-endpoint/binding CAS epoch. Its immutable
  request receipt returns the original epoch on exact retries even after another
  controller takes over. Changed input under the same request ID conflicts.
  Replaying an old receipt never makes it current again.
- `BindWorker` records immutable worker/state-directory/ownership-generation,
  actual runtime and profile commitments after current controller verification.
  Trusted composition must obtain these facts from authenticated kernel peer and
  supervisor ownership evidence; the record alone asserts no process liveness.
- `Admit` binds exact original/finalized bytes, caller identity/provenance,
  target/descriptor revision, worker binding, original controller epoch and
  distinct original caller/final dispatch signatures. Invocation deadlines cannot
  be extended or removed. Stable admission retries preserve the original epoch.
- `RegisterOrigin` checks the original admission A, current controller B,
  unchanged worker binding, current descriptor and a fresh authorization fence
  before actual native activation. Origin, source generation and original A never
  change on reconnect; the fresh registration witness is separately retained.
- `RetireOrigin` permanently blocks new activation under that origin while
  allowing genuine historical source settlement. `RetireWorker` is a permanent
  binding tombstone. These methods do not themselves stop processes.
- `CommitSource` checks the exact original origin and native generation, then
  records immutable ciphertext/effect evidence. Changed retry content conflicts.
  It remains available to the current authenticated owner after endpoint
  retirement, without reactivating processes or pending choices. Trusted native
  adapters must establish source completeness/effects; arbitrary output or EOF
  cannot provide that evidence.

The registry transaction serializes owner, descriptor/binding, controller CAS,
root identity and native record/quota updates. Native tables are initialized as
registry format 2 only by an authenticated successful transaction; rollback also
rolls back their initialization. Open verifies signed contiguous history, CAS,
head/quota and materialized state with bounded records/private scratch SQLite.
Native records use the existing configurable store record/payload/ledger limits
and actual SQLite page capacity; no history is silently deleted to regain quota.

The admission fence must synchronously call its bounded commit callback exactly
once and hold its supported external revocation fence through SQLite COMMIT.
Callbacks are sealed after return or panic. Registry SQLite cannot atomically lock
an arbitrary external authorization database. Revocation linearization therefore
depends on the selected extension's documented fence contract; an opaque signed
witness alone is insufficient. A callback succeeding followed by a provider error
returns the known durable proof **and** an error: no actuation is authorized by
that error, and exact retry recovers the same proof.

Installed Go code is trusted composition. Public context constructors must never
be called with serialized identity assertions at ingress. A lifetime OS lock
protects one local writer; copied disconnected writable domains/backup counter
rollback are unsupported without external fencing. This is not distributed
consensus or universal clone detection.

## Proposed native adapter boundary (not implemented here)

Native ownership must use a closed `CloudAuthority | LocalAuthority` binding.
Local carries domain/store/key revision, endpoint/descriptor/binding and durable
worker/state-directory generation; Cloud retains genuine existing authenticated
server/account/host scope. Neither is represented by invented fields of the other.

The adapter must authenticate current control separately from original source
admission. Its required operations are authenticate control, admit finalized
operation, register original origin before paid activation, confirm live native
session using exact supervisor/kernel birth proof, settle complete source,
reconcile ambiguous receipts and retire the genuine generation. Original source
proofs, control epoch, worker lease, dispatch ordinal and native generation remain
separate counters. Existing cloud journals/capture AAD retain their original
format and adapter until settlement; they cannot be relabeled as local ownership.

The first real acceptance fixture must run pagnetd plus a genuine local native
worker with no Internet/cloud configuration, admit original/finalized calls,
replace controller A with B without replacing the native generation, retain A's
source evidence, reject A's new effects, restart and recover exact outcomes,
and reject wrong peer/root/state directory/revoked binding/replayed choices.
No such native fixture claim is made by the current registry/identity tests.
