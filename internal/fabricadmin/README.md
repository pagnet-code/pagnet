# Private owner administration

This package supplies the separate `fabric.admin.v1` protocol on the existing
owner-private Fabric socket. The runtime protocol remains `fabric.mcp`, with
only discover, describe and invoke. Protocol selection is explicit; there is no
authentication fallback or runtime management tool.

The host first binds the actual kernel owner session, including current
managed-process classification. The server accepts only that actual Session,
checks live PID/UID/birth and retained root before and after each request, and
passes an opaque request-digest-bound OwnerAdministration to a registered typed
handler. Managed sessions cannot use administration; omitting managed selectors
does not bypass the host's current owner-process guard. No invocation envelope
or ExecutionContext is fabricated to obtain management authority.

Handlers use the already-open installation resources. They obtain its genuine
operator capability within the verified callback, enforce their own typed
operation validation and revision CAS, and perform current checks outside SQL
transactions/provider locks. The callback capability cannot be serialized and
is invalid once the callback finishes, the peer disconnects or its request
context expires. The transport does not hold Session.mu over handlers. Actual
business handlers are injected by the installation composition; this foundation
alone does not initialize, install, launch or mutate a resource.

Requests are single bounded NDJSON documents (64 KiB); typed outer fields are
strict, application input retains exact JSON numbers. There are at most 128
registered operations and 256 concurrent connections. Each connection has one
reader and one synchronous handler, with a one-request pending queue; exceeding
that queue closes the connection. Replies are bounded to 1 MiB and provider
error text is never serialized. Handler result buffers are copied before use.
The client serializes calls and never retries a lost mutation response: effects
may be unknown, and exact recovery belongs to the operation's durable receipt.

Disconnect cancels the active handler. Shutdown interrupts all connections and
joins readers, callbacks and actual session cleanup before releasing the socket
lease. A handler ignoring cancellation cannot be forcibly stopped: CloseContext
returns its deadline while resources remain retained until genuine cleanup.
