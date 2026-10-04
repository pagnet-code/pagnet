# Three-tool MCP bridge

The official MCP server exposes exactly `discover`, `describe` and `invoke`.
Normal arguments contain routing and application input, never caller identity,
signatures, timestamps or invocation IDs. `SessionBinder` must authenticate the
actual transport session and return a key unique to both that session and its
principal. `EnvelopeFactory.Build` receives typed routing separately from exact
application JSON, assigns server-owned identity/IDs, and returns owned authenticated
envelope bytes plus peer evidence to the canonical node service. The bridge clears
the owned envelope slice after execution. Composition must call `CloseSession`
when the authenticated session ends, and reject future calls for that old key.

For unary MCP transport, `invoke` also accepts one mutually exclusive control:

```json
{"stream":{"handle":"opaque returned handle","afterSequence":"0"}}
```

That control pulls the next original Fabric frame. Repeating the exact previous
cursor returns the same retained page without another admission. Handles are
session-bound, count/byte/TTL bounded and carry only one retained frame. The cursor
is a decimal string to preserve uint64 precision. `cancel:true` closes the admitted
stream and acknowledges transport cancellation; it does not fabricate a native
completion, retry the target, or resume a business continuation. Genuine terminal
frames remain available for exact cursor retries until expiry.

Capacity is reserved before invocation. Session shutdown cancels pending admission
and fences late handle publication. Expiry and cancellation close the original
stream. Premature EOF is a protocol error, not completion; no truncation or synthetic
progress is presented as output. Tool results use bounded JSON TextContent so the
SDK does not renumber opaque application data through float64 maps.

Business DEFER is separate: a committed `deferredId` and optional notification
failure are returned without MCP input-required signals or destructive replay.
Root composition supplies its genuine durable continuation service.

Fixtures use real official client/server sessions and actual canonical envelope
signature verification. They cover both supported protocol generations, simple
arguments, precise numbers, cursor retries, cross-session denial, pre-admission
capacity, pending-admission cancellation, expiry, and committed DEFER notification
failure. Native vendor execution and production transport authentication are
composition responsibilities and are not claimed by these fixtures.
