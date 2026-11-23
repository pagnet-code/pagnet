# Direct ASK/REPLY wire crypto v1

This is an internal, pure Go contract in `direct_channel_crypto.go`. It does not
activate a channel, call the network, access the keyring, persist keys, or provide
an SDK public API. N means the network identified by `networkId`; N has no public
key field and receives no content key. S initiates ASK; P returns REPLY.

Canonical bytes are exactly Go `encoding/json.Marshal` output for the declared
structs, in declaration order, including empty ASK linkage strings. Decoding
requires byte-for-byte equality with re-encoding. Duplicate/unknown/missing
fields, alternate field order, whitespace, escapes, padded base64, and nonzero
base64 trailing bits are rejected. All binary values are unpadded base64url.
`generation` is a positive uint64 encoded as a canonical decimal JSON string,
including values above JavaScript's exact integer range. IDs use the existing
pair path-ID rules. Epoch IDs are canonical UUIDv7; expiry is canonical UTC
RFC3339Nano and must be in the future.

The caller supplies an expected descriptor from trusted parent grant/consent
metadata and pinned endpoint keys. Received descriptor bytes must exactly equal
that expected descriptor. The descriptor binds domain, fixed authenticated HPKE
suite, parent grant and generation, N, S and P tenant/principal/endpoint/public
key, fresh epoch, expiry and limits. The caller allocates a fresh UUIDv7 epoch
for each new epoch; this stateless layer cannot enforce uniqueness. S and P must
have distinct principals and public keys. The initial bounds follow the pair
crypto limits: message wire 1024–65536 bytes, 1–10 ASK/minute, 1–200 ASK/day,
wire/day at least message wire and at most 8388608 bytes, 1–2 in flight.

`channelId` is base64url(SHA256(canonical JSON of the ordered fields domain,
parentGrantId, generation, s, p, epochId)). Its domain is
`pagnet/direct_ask_reply_v1/channel-id`. N, expiry and limits are also bound by
the complete descriptor hash in every key derivation and message. The descriptor
is immutable even when an identity field omitted from channelId changes.

`directPrepare` checks S's private key against its pin, draws a fresh random
32-byte K and calls the existing RFC 9180 authenticated HPKE helper with P's
public key, S's private key, info `pagnet/direct_ask_reply_v1/epoch-wrap`, and
SHA256(descriptor bytes) as AAD. `directAccept` pins both parties, checks P's
private key, and authenticates the same context. The publication contains only
the canonical descriptor, 32-byte encapsulation and 48-byte ciphertext. It is
safe to give N that publication and the derived readiness key. The local
`directMaterial` is deliberately unexported and has no serialized fields.

HKDF-SHA256 derives independent 32-byte keys using K as input, descriptor hash
as salt, and `pagnet/direct_ask_reply_v1/` followed by `readiness`, `ASK`, or
`REPLY` as info. N receives only `readinessKey()`; traffic keys and K stay local.

`readinessProof` MACs the exact canonical server challenge transcript with
HMAC-SHA256, after checking challenge identity/expiry, role S or P, the role's
pinned principal and endpoint, caller-supplied credential ID, channel, parent,
generation, descriptor hash, epoch and canonical 32-byte nonce. Credential ID is
an opaque path ID supplied from the caller's authenticated credential metadata;
this layer neither discovers credentials nor infers ownership. The server must
issue unpredictable nonce values, bind challenge expiry, validate the actor's
authenticated credentials, and consume challenges once. A local replay of the
same still-valid challenge produces the same proof by design.

Messages use AES-256-GCM with a fresh random 12-byte nonce and full canonical
header as AAD. ASK binds channel, descriptor hash, immutable message/root IDs,
and exact S→P parties. REPLY reverses parties and additionally binds the original
ASK message ID and SHA256 of its full canonical wire, including nonce and
ciphertext. Opening requires expected message/root IDs; opening a REPLY also
requires the exact original ASK wire. P authenticates that ASK before sealing a
reply. Ciphertext includes the 16-byte tag. Wire length is bounded by the
descriptor. Both opening and sealing enforce descriptor expiry and local role.

Replay detection, quotas, root creation, immutable IDs, one terminal reply per
ASK, challenge consumption, cancellation and revocation require server/store
state and are intentionally outside this pure layer. Identical deliveries can
be decrypted repeatedly; replay under another message/root/channel/epoch or
another original ASK wire fails. Shared symmetric traffic keys authenticate
context, not a malicious peer's honesty; role checks are local API invariants.
