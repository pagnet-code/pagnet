This private SQLite adapter preserves deferred pipeline evidence, not business
approval policy. Trusted composition bootstraps the audience; every call requires
an authenticated context. The engine resolves exact allowed resumer principals
(including kind and issuer) before creation. Original caller bytes and pipeline
bytes remain immutable and separately committed; transformed data belongs in
State. The stable engine DeferralID must already be durable before Create.

Bootstrap and Open require an explicit external DataProtector owned by trusted
composition. Format 2 encrypts snapshots, claim receipts and outcomes with exact
purpose, audience, deferral identity and pinned key-reference AAD. Even an empty
store verifies key custody through its protected identity pin. No key is created
by this adapter and the old plaintext storage format fails closed. Canonical
plaintext commitments preserve exact retry semantics; quotas charge the actual
stored ciphertext bytes. Installation composition separately signs the store
path, options and key-reference pin in its retained root.

Bootstrap creates new state explicitly. Open never regenerates missing or corrupt
state. A lifetime native OS lock admits one writer; disconnected writable copies
of one store are unsupported, and restoring an older complete backup requires
external fencing. FULL SQLite commits precede every successful mutation. A commit
whose acknowledgement is lost is uncertain, not permission to execute again.

Create returns a random 256-bit capability once and stores only its SHA-256 hash.
An exact retry returns the existing identity/revision without a secret. Explicit
pending-only rotation by an allowed authenticated resumer recovers lost delivery
and revokes the old capability. Private delivery calls Capability.Token(); public
formatting redacts it, and public JSON refuses to serialize it. Receipt/outcome
schemas contain no capability fields. Applications must not put credentials into
opaque outcome or state data.

A valid capability plus an allowed authenticated identity atomically claims once.
Exact same-claim retries return the original receipt with Fresh=false, including
after restart. They are never executable admissions. Competing claims and changed
receipts fail. Claimed recovery is uncertain until the engine explicitly settles
actual effect evidence through Complete. No automatic pending reset, target replay,
claim takeover or secret reissue occurs. Expiry denies new claims/rotation but does
not suppress truthful completion or receipt retrieval for an already claimed
operation. Completed receipts remain immutable, including unknown-effect results.

The default 8MiB encoded snapshot admits a near-1MiB original envelope, a
near-1MiB transformed state and 500 stages with 4KiB references including base64
overhead. Configurable JSON depth/member bounds (64/65536 by default) cover this
private evidence without changing the canonical ingress envelope limits.

Options configure positive finite record, encoded logical byte, per-snapshot,
per-outcome, database and expiry limits. Defaults provide bounded backpressure;
these are operational capacities rather than fixed protocol limits. Startup reads
and verifies one bounded row at a time and reconciles durable quota counters.
No automatic receipt deletion weakens replay evidence; archival or store replacement
needs explicit engine/external fencing rather than silently purging old claim IDs.
