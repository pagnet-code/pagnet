# Private session worker boundary

This package is an internal implementation stage. The daemon does not yet route
production sessions through it, and its conservative active-endpoint update gate
is unchanged. It does not expose a network API or authorize control-plane tools.

The implemented foundation owns an exclusive private state journal and a
versioned owner-local Unix controller socket. Linux and Darwin authenticate the
socket's actual kernel owner and mutually authenticate fresh server/client
nonces with a separate 32-byte local control key. The canonical proof binds the
full server/tenant/account/host/instance/ownership generation, protocol, controller identity
and durable monotonic lease. Unsupported transports reject; incompatible
versions do not fall back. Failed authentication cannot acquire a lease.

Each controller must durably assign a stable command ID and intent ordinal
**before** writing an intent, and retain that mapping across controller updates.
Admission records only a digest/kind/identity and commits before a native effect.
Duplicate ordinals require the same digest and identity and return the existing
outcome. A new authenticated controller fences subsequent operations from the
old connection and closes its socket; already admitted work remains the worker's responsibility.
A crashed worker's unfinished outcomes become uncertain and are never rerun.

There are at most 128 retained intents, each outcome is at most 64 KiB, and frame
allocation is at most 1 MiB. Four concurrent connections and five-second
unauthenticated deadlines bound the local transport. Unacknowledged outcomes
apply backpressure. Receipts retire only a contiguous prefix, retaining its
ordinal floor forever, so pruned intent replay cannot become new work. Command
IDs are not an unbounded tombstone collection; replay safety requires the
controller to preserve its original ordinal. The intent journal retains digests rather than prompt bodies, and never stores
launch environments, host credentials or native approval secrets. Purposeful native lifecycle, plan and interaction sources retain their complete
original details encrypted in a bounded owner-local pending outbox. Incremental
runtime output is not durable evidence. Original private resolution answers are
captured before redaction, separately from the original approval secret. Capture
keys derive from the local control key with full scope and state-directory
binding; authenticated source bindings retain the exact origin, generation,
native session and original timestamp. Bounded slices require the current lease
inside the read transaction. Only ciphertext commitments appear in metadata;
plaintext hashes are never exported. Capture and projection commit atomically,
and controller journal acknowledgment removes both. This local pending capture
is not a server receipt or an automatic network publication. Raw PTY
echo is retained only in a bounded 2 MiB worker-owned memory ring, never as a
SQLite output transcript. Replacing a worker reports a distinct replay generation
and an explicit gap; replacing its controller preserves the ring.

A controller must durably store/project an outcome before acknowledging it.
Socket read/write errors close that connection; an unknown admission outcome
requires reconnecting and querying/replaying the same ordinal, never sending a
fresh intent. The worker state is 0700, journal/lock/socket are 0600, symlink
state paths are rejected, and a lifetime kernel file lock prevents two workers
from misclassifying each other's live effects as crash uncertainty. Invalid
scope, protocol, SQLite integrity, sequence holes or intent rows refuse opening.

The current internal owner runs the actual session.Manager, native Fake/Qwen/
Codex/Grok drivers and Supervisor in the worker, owns the sole PTY reader and
bounded sequenced replay, and retains exact native approval state. Native MCP
uses a separate worker-owned socket, activation nonce and captured kernel
process ancestry. Forwarding reaches only the current fenced controller with
fresh control-plane admission. Before every actual process generation starts,
the worker waits for its exact server-admitted source origin; reconnect does not
rewrite that source or the actual runtime/profile. Native source observations
have stable identities and original timestamps, wait for durable journal COMMIT,
and remain until a transactionally fenced controller ciphertext-journal receipt.
The actual native/two-controller subprocess fixture verifies uninterrupted PID,
PTY, session, timer and approvals across replacement and a controller-free gap.

The production daemon proxy and server admission/receipt integration are still
under construction. Darwin native runtimes intentionally share the owner's OS trust boundary. A
0600 control key restricts other users, but does not isolate an untrusted native
process with the same UID. Trusted local runtimes remain useful on Darwin; a
developer who needs mutual isolation can select an external execution boundary.
Fresh authenticated network/context grants and controller fences remain required. Production update admission
remains conservative until the complete pagnet serve replacement path is proven.

Only actual worker/native and two-controller subprocess acceptance, followed by
daemon routing migration and bridge/inspection/receipt integration, can justify
changing production update admission. No user-visible enablement flag or
supervisor-only PID adoption substitutes for whole ownership.
