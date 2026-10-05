# Private local installation

`Bootstrap(ctx, absoluteDirectory, Options)` is an explicit operator command. It
creates one registry root for the current OS UID or Windows process-token SID,
then an independent random AES-256 encryption key and bounded versioned private
configuration. Private files are flushed and published without overwrite before
the original registry commits their configuration digest and key commitment in
its signed FULL ledger. Success is returned only after reading that exact state.

`Load(ctx, directory, registryOptions)` opens the original registry and holds its
sole-writer lock. It verifies OS ownership/permissions, original root ownership,
configuration, encryption key and signed installation pin. It never initializes
missing state. Both methods return the same Store instance used by subsequent
node composition; do not reopen a second registry. No provider, model, software,
container or worker is installed by this package.

A complete repeated initialization returns `AlreadyInstalledError`. Partial,
missing or corrupt existing initialization returns `IncompleteInstallationError`
from Bootstrap and preserves its original files. A crash can leave a root or
private files without the final pin; this is deliberately unavailable, not an
opportunity to generate a replacement key. Recovery requires a consistent
original backup/operator maintenance. A complete internally consistent historical
backup cannot be distinguished from disk rollback without an external monotonic
anchor; this package does not claim that protection.

`Installation.Keys` implements the finite `DataProtector` interface. Its opaque
reference is configuration metadata, and it exposes no key bytes. The stable
secret is stored in an owner-private file inside the actual authority directory.
Native runtime sandbox composition denies that directory; no files are written
to `.claude`, `.qwen` or other runtime configuration directories. Close clears raw
key buffers and prevents new operations; Go's transient AES implementation does
not promise erasure of expanded cipher memory.

`Operator(ctx)` returns a private setup capability bound to this actual open
installation, Store/root, full OS principal, current PID/birth and exact setup
bytes. `WithCurrentOperator` checks this concrete binding, fresh kernel identity
and live root before and after a synchronous callback. Same-principal assertions,
historical contexts, previous loader capabilities and arbitrary wire identity do
not qualify. This capability provides infrastructure operator authority; it is
not a live external caller session and cannot impersonate a model/user request.

Close transport sessions and native resolver resources first. Then close the
installation to join active operator callbacks, clear its key and release the
registry. `CloseContext` returning a deadline means joining remains incomplete;
the Store is still held. Callback code must honor its context. Windows private
state uses the existing owner-only ACL, non-reparse and durable publication APIs;
Windows worker execution remains a separate explicitly unsupported boundary.
