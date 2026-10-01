# Local runtime bridge process binding

On Linux and macOS, managed runtime bridge authentication requires the current
activation nonce, identity/surface/network agreement, a live supervised runtime,
and a kernel-verified connecting process in that runtime's process tree.

Linux uses `SO_PEERCRED` and `/proc`. macOS uses `LOCAL_PEERCRED`,
`LOCAL_PEERPID` and `kern.proc.pid` process records. The macOS ancestry walk
checks ownership and start identities, bounds its depth, and rechecks every
process record before accepting. Missing credentials, an unavailable process,
a changed identity or an unrelated process rejects authentication. It does not
fall back to nonce-only authentication when these checks fail.

The activation nonce is included in the runtime's `PAGNET_MCP_CONFIG` launch
configuration. It is a rotated bridge credential, not a secret hidden from the
runtime or all other processes owned by the same operating-system user. An
unrelated same-user process that obtains the nonce is still rejected by kernel
process binding on Linux and macOS. Descendants of the authorized runtime are
within that runtime's bridge trust boundary and receive its scoped tool policy.

Runtime child environments omit Pagnet account/host credentials, encryption
keys and inherited database/SSH/Git secrets through an explicit allowlist.
Native provider credentials are deliberately allowed so the runtime can use
its provider. Configured runtime profiles explicitly add their own environment;
do not place Pagnet control-plane keys in a runtime profile.

Bridge authentication and filesystem containment are separate. macOS reports
filesystem sandboxing as `unsupported_platform`; process binding does not
provide Linux Landlock filesystem isolation. Other unsupported operating
systems report the nonce-only bridge boundary explicitly.

Native macOS regression tests exercise real Unix sockets and descendant versus
unrelated processes. Supervisor tests separately verify process-group creation,
termination, PTY cleanup, identity and resource-pressure refusal. Cross-compiling
a test binary is not evidence that these kernel operations passed; run that
binary on macOS to verify them.

Normal bridge sockets remain under the state directory. When a macOS state
path exceeds its 104-byte Unix socket limit, every listener and client uses a
full SHA-256 digest of the canonical state path in `/private/tmp/pagnet-UID`
(the canonical location of `/tmp`). This directory must be real, owned by the
current user, and mode `0700`; sockets remain mode `0600`. Unsafe existing
directories reject startup. This is local IPC only: state and credentials remain
in the configured state directory, and cleanup removes only the chosen socket.
