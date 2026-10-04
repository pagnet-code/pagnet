# Exact endpoint dispatch

This package composes the authenticated node invocation with a trusted private
binding resolver and current-authority admission. It does not search, select a
fallback, infer authorization from descriptions, or retry endpoint effects.

The node retains separately the original authenticated envelope and its bounded
final representation after interception. Final input is taken from that same
representation, preserving JSON values and large integers without rejecting
ordinary whitespace or HTML characters. Private context keys prevent a wire
caller from manufacturing the finalization capability.

Endpoint calls resolve exactly the selected revision. Offer calls load only that
offer schema and its endpoint header. A resolver must return a currently published
binding, matching endpoint revision and nonzero private configuration fingerprint.
The admission implementation must fence current identity/configuration through
its actual bounded durable acknowledgment; this package does not claim atomic
transactions across processes or databases.

Admission may call downstream once, synchronously while its capability is active.
Only the stream produced by that callback may escape. Substitution, dropped
results, lost context and expired/cancelled original requests fail closed. Owned
streams are closed on failure; terminal results and explicit cancellation release
the adapter lifetime once. Responses remain pull driven.

Tests use the actual node and extension engine with counted endpoint fixtures.
They demonstrate protocol/admission boundaries, not live vendor execution. The
actual native worker, MCP provider and A2A integration supply their own durable
admission and source-evidence boundaries during node composition.
