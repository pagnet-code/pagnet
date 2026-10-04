# Private local Fabric listener

`Start` requires an explicit private socket path, the actual retained node's
`fabricauth.Authority`, and its `fabricmcp.Server`. It creates neither an identity
nor a directory, downloads nothing, and never chooses a cloud connection.
The socket must live outside the denied local authority directory and private
worker state; root composition supplies the exact runtime-accessible path.

The socket parent must be owner-private 0700; the socket is 0600. A nofollow,
regular 0600, single-link per-socket lock is held for the listener lifetime.
An active listener, symlink, non-socket, foreign owner, insecure parent or linked
lock is refused. Only a genuine owner-private crash-stale socket can be replaced
under that lock. Cleanup uses the pinned parent directory and owned socket
inode, preserving a replacement socket. Unsupported platforms fail explicitly.

Authentication is one strict bounded JSON line. Owner mode is explicit:
`{"type":"fabric.auth","mode":"owner"}`. Managed mode requires all of
`endpoint`, `workerId`, `generation`, `nonce`. Partial, duplicate, unknown or
case-alias fields are refused. No mode falls back to another mode. Original
buffered MCP initialization bytes remain available after the handshake.

Managed selection is not authority. The mandatory injected resolver must query
the actual current signed local binding and mutually authenticated worker
snapshot, pinning endpoint/physical worker/native generation/session/PID/birth and
private activation nonce. The listener checks exact selected endpoint/worker/
generation and constant-time nonce equality, then calls `BindManaged` on the
original helper child's kernel Unix peer. `fabricauth` independently validates
current authority and ancestry. Worker forwarding cannot impersonate that peer.
When managed resolution is enabled, `Start` requires an authority with both
managed and owner-classification validators. Owner mode calls `BindOwner` for the
registered OS owner, never an asserted JSON principal. The trusted classifier
checks current kernel process/birth/ancestry against real worker ownership; a
managed child cannot become an owner by omitting selectors. All node envelopes originate from the resulting private session.

Connections and authentication bytes/time have finite limits. `Close` interrupts
the listener and all sockets. One lifetime coordinator joins the actual SDK server
and handlers before releasing the lock/socket; `CloseContext` waits on that
completion with the caller's deadline, without spawning per-wait goroutines.
A cancellation-ignoring resolver/provider may outlive a deadline; neither its
exit nor runtime/business completion is invented. Root composition must finish
this join before closing the retained registry.

`pagnet mcp fabric --socket <path>` is the thin stdio client. It performs one
private handshake then copies original bounded JSON frames; no effect/authentication
is retried. A managed runtime receives exactly these four scoped environment keys:
`PAGNET_FABRIC_ENDPOINT`, `PAGNET_FABRIC_WORKER_ID`,
`PAGNET_FABRIC_GENERATION`, `PAGNET_FABRIC_NONCE`.
A partial set is denied before dialing. An absent set selects explicit owner
mode. Provider credentials, root signing material and registry paths are not
needed in the helper. The caller supplies a socket; no default or DNS is inferred.

Actual tests cover direct kernel owner authentication, official SDK negotiation,
three tools, discovery, buffered initialize, real CLI child stdio, finite silent
peers/capacity, strict identity rejection, stale recovery and replacement-safe
cleanup. Native managed admission needs the separate actual worker resolver and
is not claimed by selector-only negative fixtures.
