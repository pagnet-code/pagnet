# Durable CloudEvent delivery

`Bootstrap` explicitly creates private state; `Open` never creates missing state
or replaces keys. Both require the same audience/domain scope, subscription
configuration and data-protector reference. A private native writer lock owns the
SQLite database for its lifetime. SQLite DELETE journaling, `synchronous=FULL` and
an explicit page cap bound physical storage; symlink/owner/mode checks use the
shared privatefs boundary.

The injected `DataProtector` owns encryption authorization. Its opaque ID/version
is metadata, never a key. The supplied AES-256-GCM implementation takes an
operator/key-provider supplied secret and owns its cipher state. Authentication
binds format version, scope, key reference, original source/ID and exact encoded
CloudEvent digest. Wrong/missing keys, foreign scopes and ciphertext tampering fail
closed. Open authenticates a scope/configuration checkpoint and all retained event
ciphertexts. No registry signing key is repurposed as an encryption key.

`Publish` returns a receipt only after FULL commit of the original event, all
matching delivery rows and budget counters. `(source,id)` binds the exact encoded
content digest; a same-identity conflict cannot replace data. Retrying an ambiguous
commit with identical original bytes returns the existing receipt and creates no
second delivery. There is no automatic retry using a freshly minted event ID.

Finite limits cover event/cipher size, subscriptions, fanout, global rows/logical
bytes, database pages, pending deliveries per subscription, attempts and retention.
Logical byte reservations include encrypted content and conservative repeated
identity/claim metadata; physical SQL/index overhead is separately page-bounded.
Acknowledged/failed identities continue consuming bounded deduplication storage.
`Expire` explicitly records old unconsumed deliveries as failed. `Inspect` exposes
only bounded state metadata. `Purge` explicitly forgets settled identities after
retention; it never deletes pending/claimed work. After explicit forgetting, the
same `(source,id)` can be admitted again: deduplication has a declared finite
horizon, not an exactly-once promise.

`Claim` uses two bounded indexed seeks for due pending and expired claimed work.
A FULL-committed generation, random lease token and worker binding authorize
`Ack`/`Nack`; late, foreign and superseded claims cannot settle. Restart may
redeliver after lease expiry, so consumers must be idempotent. Attempts exhausted
or retention expired means delivery failure, never target success. The optional
worker pool runs one sequential goroutine per configured handler, not per event.
A handler ignoring cancellation can occupy only its existing worker; `Close`
uses a caller deadline and does not claim to forcibly stop arbitrary Go code.

`Ingress.TryPublish` implements the node observation port with a **volatile**,
finite queue and one durable writer. Nil means owned volatile admission only.
Metrics distinguish volatile accepted, durable committed/duplicate, write failed,
overflow and shutdown discarded. The node never waits for a consumer or durable
writer. Direct `Store.Publish` is the separate durable-receipt boundary. Close
cancels writes and explicitly counts remaining volatile losses rather than
claiming a durable drain.

This package observes/delivers events. It does not infer an event caller's
identity, invoke target offers, cancel native work, or implement business policy.
Generic emit/trigger composition must authenticate source authority and use a
real idempotent invocation-admission boundary; at-least-once event retry alone
never authorizes replaying unknown endpoint effects.
