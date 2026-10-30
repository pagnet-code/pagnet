# Owner text console crypto v1

This unit provides cryptographic types and session state only. It does not admit
sessions, dispatch host operations, or expose a route or UI. Mailbox v1 bytes and
its protocol are unchanged.

The authenticated server pins the expected complete descriptor, including the
host public keys. The host's Ed25519 signature proves possession of that pinned
signing key. Substitution of host keys by a malicious control plane is outside
this trust model. The browser must compare the supplied descriptor with its
independently pinned expected descriptor and verify the signature before HPKE
unwrap. Session keys must come from that verified bootstrap (or from the host's
bootstrap creation); callers must never instantiate a second session with reused
keys, including on reconnect. Use a trusted clock and close/discard sessions when
connections end.

The protocol is `pagnet/owner-text-console/v1`. Descriptor, HPKE info, signature,
and frame domains are respectively `pagnet/owner-text-console/session/v1\0`,
`pagnet/owner-text-console/keys/v1`,
`pagnet/owner-text-console/bootstrap-signature/v1\0`, and
`pagnet/owner-text-console/frame/v1\0`. Each descriptor string or byte field is
encoded as a U32BE length followed by its bytes, in the declared type's field
order. The final issued/expiry timestamps are U64BE Unix seconds. Fixed values
are personal ownership, sender role, and `owner_text_project_v1` project contract.
The policy hash is lowercase hex in JSON and 32 raw bytes in the descriptor;
project descriptor hash and public keys are canonical padded base64 in JSON and
32 raw bytes in the descriptor. UUIDs are lowercase, decimal versions and
generations are positive strings through MaxInt64, and epoch timestamps are UTC
with exactly nine fractional digits. Unix seconds are safe integers with a
positive lifetime of at most 900 seconds. Untrusted JSON must enter through the
strict raw JSON parsers, which preserve duplicate detection; an object parsed
elsewhere has already lost duplicate information.

RFC9180 HPKE X25519/HKDF-SHA256/AES256GCM seals 64 independently sampled bytes to
the browser with descriptor B as AAD. The first and second 32 bytes are the
client-to-host and host-to-client AES256GCM keys. The host signs
`signature-domain || F(B) || F(enc) || F(ct)` with Ed25519. This signed transcript
T is hashed with SHA256 for both confirmations.

Sequence zero in each direction carries exact canonical JSON with fields in
order: `version: 1`, `type: "client_confirm"` or `"host_confirm"`, and
`transcriptHash` as padded base64 SHA256(T). The browser confirms first; the host
confirms after receiving the client confirmation. Operations begin at sequence
one after both confirmations. A frame nonce is four zero bytes followed by its
U64BE sequence. Frame AAD is `frame-domain || SHA256(B) || direction || U64BE(seq)`
(direction zero is client-to-host, one is host-to-client). Sequences must be
strictly consecutive, below 2^20, and plaintext is at most 64 KiB. Sessions own
copies of keys/context, serialize counters, check clock validity on every
operation, and permanently close after a receive failure. Stateless frame
helpers do not enforce replay protection; use session state for live traffic.

The shared golden fixture contains synthetic, public test private keys and
fixed entropy. Never use those values outside tests. Go and TypeScript tests
check exact descriptor, transcript, HPKE unwrap, confirmation and frame bytes.
