# Durable generic triggers and emits

This package queues explicitly authorized work. It is not a business scheduler,
endpoint selector, or replacement for node invocation admission. Composition
must supply four mandatory real authority ports: original source authentication,
signed trigger registration/current permission, finalized action authorization,
and idempotent durable admission/query. Missing ports deny Bootstrap/Open.
There is no `node.Execute` or adapter-dispatch fallback.

`Bootstrap` explicitly installs an immutable operator-selected trigger set.
Registrations include exact source/type, target/revision, provider/principal
binding digest and signed authorization; the injected authority must verify all
those fields. They are AEAD-protected in an owner-private, synced checkpoint.
`Open` requires the existing checkpoint, exact scope/config/key reference and
retained encrypted SQLite queue. Removing registration state does not regenerate
it. Changed configuration requires an explicit separately designed migration;
this packet does not claim dynamic registration or rollback-proof storage.
Local filesystem backup rollback remains an operator recovery boundary.

`Trigger` uses an exact source/type index compiled from owned immutable registrations; it iterates only the matched fanout. URI spellings are validated without DNS lookup, wildcard matching or hidden normalization. `Emit` takes one
explicit target/revision/input. Both require original exact CloudEvent bytes and
persistable cryptographic source evidence. Evidence must be a signature/proof,
not a reusable bearer token or provider credential. The source authority checks
that evidence, audience, producer and any original parent lineage; decoded
ExecutionContext is never stored or accepted as proof. Exact source/proof and
finalized envelope bytes are encoded as opaque byte strings in the private
record so JSON serialization cannot rewrite signed whitespace or numbers.

Canonical envelope headers carry target/revision and context carries idempotency;
`Envelope.Payload` is the application JSON alone, never an InvokeRequest wrapper.
The engine creates a distinct action ID from scoped source/event identity and
trigger revision. It copies genuine parent ancestry, increments bounded hops,
adds trigger lineage and rejects self-recursion/expired parents. Prepare must
honor that exact engine identity/time/context deterministically across retries,
and authorize the selected target/input. A changed source or action set under
the same event identity conflicts, rather than becoming new work. The complete
bounded action set is one CloudEvent and one FULL queue transaction: fanout is
all-or-none. Queue receipts mean **durably queued**, not runtime accepted,
executed, paid, or completed.

One owned sequential worker consumes the encrypted queue. Its private handler
rechecks source authentication, signed current registrations and final action
permission, then calls `AdmitOrGet` with the exact retained action bytes. The
port must atomically accept/query the same action identity and return its exact
committed admission receipt after reply loss. It must not repeat an uncertain
downstream effect. Previously accepted prefixes therefore return receipts on
retry, not another invocation. An admission receipt proves infrastructure
acceptance only. MCP, A2A and native targets use this same port without kind
switches. Product admission composition is not implemented by this library.

There are finite registration/fanout/bytes/SQLite/retry/lease/retention budgets,
32 concurrent API/callback slots, and one worker, never a goroutine per action.
Original lifecycle observation remains separate, nonblocking volatile ingress;
this explicit action API is a durable admission boundary. Exhaustion rejects
before a partial fanout commit. Purge is explicit and inherits the queue's TTL
and exact claim protections; dedup guarantees do not extend past administered
retention. Failed current authorization is retained/retried within those bounds,
not labeled successful. No target result is inferred from an empty queue.

`CloseContext` cancels the owned worker and joins actual callbacks before closing
SQLite/releasing the private writer lock. A provider ignoring cancellation can
outlive the caller deadline; the lock remains held until it really exits. The
shared done channel supports subsequent bounded joins without per-wait goroutines.

Tests use real encrypted FULL SQLite state and independently verified Ed25519
producer/registration signatures. An independent FULL SQLite admission fixture
commits then deliberately loses its reply; restart/prefix retry retrieves its
original receipts. That demonstrates the port contract, not genuine product
native/MCP/A2A admission integration.
