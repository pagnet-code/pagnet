# Actual local MCP connection composition

`Server` connects the official MCP SDK to an injected real node executor. Its
only entrypoint is `ServeVerified`: trusted daemon composition must first prove
the local peer and supply a connection-bound `SessionFactory` implementing
original envelope construction and explicit session closure. No protocol field,
serialized execution context, username or asserted principal authenticates a
caller. Missing configuration fails closed; this package never initializes a
registry, generates an identity, chooses a cloud connection or selects a runtime.

The original buffered reader is retained after private peer authentication so
prefetched MCP initialization bytes are preserved. An actual official SDK server
session exposes only discover, describe and invoke; its private binding key and
factory are scoped to that connection. Calls from another SDK session are refused.
Malformed UTF-8, duplicate fields, trailing documents, incomplete lines, excessive
nesting/collections and oversized frames are rejected before SDK interpretation.
Disconnect fences pending admissions and opaque stream handles, cancels handlers,
and closes the original identity session. It does not imply runtime completion or
cancel a remote business task.

Connections, inbound frames and bridge streams have explicit finite limits.
`Server.Close` interrupts owned sockets. `CloseContext` additionally joins all
accepted SDK handlers, bridge streams and identity factory cleanup before shared
node/registry services may be closed. A caller deadline returns honestly while
a cancellation-ignoring provider remains active; a later CloseContext can join
its eventual exit. No per-wait goroutine is spawned. Operator-supplied
executors and factories must honor cancellation. No goroutine per frame is used.

`Forward` is a thin transport helper for root-owned CLI composition. The caller
must complete the genuine private handshake before invoking it. It owns all
three closeable streams, copies bounded original JSON lines without normalization,
and closes/joins both directions on EOF, failure or cancellation. It never replays
a request or logs message bodies, credentials or private evidence.

The daemon's explicit `fabric.mcp` managed handoff retains the existing activation
nonce, kind, cloud-row network check, live root and kernel ancestry checks. It
requires a trusted local-root binding factory and rechecks those guards on each
original envelope construction. Native local workers and local operators use
their own genuine retained authority/peer composition with ServeVerified; they
are not represented by invented cloud rows or tokens. Unconfigured Fabric requests
never fall back to the older cloud tool relay.

Tests exercise an actual official SDK connection and real node authentication
with independent signatures, exact forwarding and cancellation. Those signatures
are test peer admission, not evidence that CLI/bootstrap/native identity composition
has been deployed. Genuine owner/native composition is supplied separately by the
node/identity owners.
