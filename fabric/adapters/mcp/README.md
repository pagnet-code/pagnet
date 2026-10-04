# MCP adapter boundary

This package connects an explicitly registered binding using the official
[Go MCP SDK v1.8.0](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0).
The SDK negotiates protocol versions. Pagnet disables automatic multi-round-trip
tool replay; transport loss after dispatch returns an unknown effect, not a retry.
Input-required responses require explicit setup outside the invocation path.
`Config.Audience` is mandatory: a genuinely authenticated context for another node
is rejected before a tool call. Connection and catalog synchronization are trusted
operator setup methods, not caller-accessible authorization shortcuts.

`CredentialProvider` resolves credentials only during explicit `Connect`.
`RemoteFactory` uses configured HTTPS, refuses redirects and prevents credential
headers overriding MCP protocol, session or idempotency headers. HTTP is explicit
opt-in for local deployments. Stdio factories are injected by composition; they
must use SDK transports and `ResultTap.WrapLocal`. Remote factories use
`ResultTap.WrapHTTP` to preserve the SDK's private session/version state hooks.
The tap retains bounded results matched to the genuine session request ID and
method. It captures original JSON before SDK `any` conversion, preserving schema
constants, arguments and structured results above JavaScript's integer precision.
It never logs or persists credentials.

`Catalog` is a trusted durable authority port, not an in-memory product catalog.
Composition must provide atomic indexed publication, encrypted schema storage,
stable references, exact revisions and tombstones. `Current` returns only bounded
selector/fingerprint summaries. `Resolve` retrieves exactly one remembered offer;
Describe/Invoke do not load sibling schemas. Sync reads a bounded paginated
provider snapshot and publishes changed descriptors and removals atomically.
Unchanged tools retain identity. Names-only removal/reappearance does not prove a
rename or resurrect an old reference. A known list change blocks invocation until
synchronization succeeds.

MCP tools/call is unary. The adapter emits Fabric start, bounded chunks of the
original completed response, and the genuine tool completion/error. Progress
notifications are not assistant output. Results are bounded; this package does
not claim unlimited output or streaming deltas from a unary provider.

Official in-process client/server and HTTP fixtures verify negotiation, large
numbers, discovery without effects, remembered removals, setup cancellation,
input-required/error distinction, original result bounds, cancellation and lost
response after a real effect without replay. These fixtures do not prove daemon
composition, remote provider authorization, or the durable Catalog implementation.
