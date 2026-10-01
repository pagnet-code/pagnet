# Durable events and invocation outcomes

SDK connections negotiate `dispatch-id-v1` at registration. An SDK without the
feature receives upgrade guidance before it can advertise a connected endpoint.
A current SDK refuses an older server that does not acknowledge the feature.
Upgrade the server before upgrading attached SDK services. This protocol change
has no fallback that accepts an absent dispatch ID.

Events use at-least-once delivery. A delivery attempt has a durable dispatch ID,
endpoint connection and credential. Another replica can recover an expired
attempt and retry it with backoff; an ACK for an older attempt cannot acknowledge
the replacement. Handlers should deduplicate durable delivery IDs for external
side effects. A process restart can lose its local duplicate cache. Managed
runtime events associate their durable host command before dispatch and commit
turn-admission ACKs with the event delivery mark.

Invocations are not automatically replayed after they may have reached a
provider. If admission is not recorded within 120 seconds, the durable outcome
becomes `outcome_unknown`. Accepted operations have no arbitrary running expiry.
When their assigned connection disappears, they need reconciliation rather than
reexecution. Neither status proves whether a provider operation ran.

The SDK retains the original encrypted outcome until it receives a receipt for
the server's committed result. Receipt loss retries the same ciphertext, not the
handler. A reconnect can reconcile that outcome only with the original dispatch
ID and durable credential, after the old endpoint generation is offline and
current membership and credential restrictions are verified. Identical outcomes
are idempotent; contradictory outcomes are rejected. A permanent authorization
or assignment rejection retires the local retry without claiming server storage.
Losing the SDK process before a receipt can lose its in-memory outcome; no
exactly-once execution or crash-durable client result cache is claimed.

Each result/error supports up to 256 KiB of serialized plaintext and 512 KiB of
encoded encrypted result payload. Oversized outputs become a small protected
`output_too_large` error. The SDK reserves output space before admitting up to
64 concurrent operations (32 MiB of retained encrypted result capacity). A full
reservation pool explicitly declines admission before running a handler; the
server reoffers that still-unaccepted operation with backoff. Unreceipted outcomes
are not silently evicted. Acknowledged outcome replay uses an 8 MiB byte-bounded
cache and a bounded ID cache. These limits bound retained result payloads, not
memory allocated by user handlers or temporary serialization buffers.

Terminal assignments remain with their durable source records for immutable
result/ACK replay checks and disappear when those source records are deleted.
Accepted or uncertain invocation records require explicit lifecycle retention
and reconciliation; queue recovery does not delete them on a guessed timeout.
