# Private session worker boundary

This package is an internal implementation stage. The daemon does not yet route
production sessions through it, and its conservative active-endpoint update gate
is unchanged. It does not expose a network API or authorize control-plane tools.

The implemented foundation owns an exclusive private state journal and a
versioned owner-local Unix controller socket. Linux and Darwin authenticate the
socket's actual kernel owner and mutually authenticate fresh server/client
nonces with a separate 32-byte local control key. The canonical proof binds the
full account/host/instance/ownership generation, protocol, controller identity
and durable monotonic lease. Unsupported transports reject; incompatible
versions do not fall back. Failed authentication cannot acquire a lease.

Each controller must durably assign a stable command ID and intent ordinal
**before** writing an intent, and retain that mapping across controller updates.
Admission records only a digest/kind/identity and commits before a native effect.
Duplicate ordinals require the same digest and identity and return the existing
outcome. A new authenticated controller fences subsequent operations from the
old connection; already admitted work remains the worker's responsibility.
A crashed worker's unfinished outcomes become uncertain and are never rerun.

There are at most 128 retained intents, each outcome is at most 64 KiB, and frame
allocation is at most 1 MiB. Four concurrent connections and five-second
unauthenticated deadlines bound the local transport. Unacknowledged outcomes
apply backpressure. Receipts retire only a contiguous prefix, retaining its
ordinal floor forever, so pruned intent replay cannot become new work. Command
IDs are not an unbounded tombstone collection; replay safety requires the
controller to preserve its original ordinal. Prompt bodies, launch environments,
host credentials and native approval secrets are not stored in this journal.

A controller must durably store/project an outcome before acknowledging it.
Socket read/write errors close that connection; an unknown admission outcome
requires reconnecting and querying/replaying the same ordinal, never sending a
fresh intent. The worker state is 0700, journal/lock/socket are 0600, symlink
state paths are rejected, and a lifetime kernel file lock prevents two workers
from misclassifying each other's live effects as crash uncertainty. Invalid
scope, protocol, SQLite integrity, sequence holes or intent rows refuse opening.

The next implementation stage must instantiate the actual session.Manager,
production drivers and Supervisor within the worker, own the sole PTY reader
and bounded sequenced replay, native MCP socket/nonce/kernel ancestry and exact
pending native approval state. Tool forwarding must reach only the current
fenced controller and pass fresh control-plane admission; worker possession of
a local control key never supplies network authority. The native activation
origin descriptor from observation receipts remains immutable across controller
transport changes and is separate from bridge nonce and lease generation.

Only actual worker/native and two-controller subprocess acceptance, followed by
daemon routing migration and bridge/inspection/receipt integration, can justify
changing production update admission. No user-visible enablement flag or
supervisor-only PID adoption substitutes for whole ownership.
