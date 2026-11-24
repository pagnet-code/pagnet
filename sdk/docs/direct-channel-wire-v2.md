# Direct ASK/REPLY wire crypto v2

This is the private SDK contract for `directPrepare`, `directAccept`, local
`directMaterial`, readiness and durable pending-channel persistence. The shared
canonical transport contract is `transport/direct_channel_v2.go`. These helpers
do not expose a public SDK send or proof API, make HTTP calls, or activate a
channel on a server. S initiates ASK; P returns REPLY. N identifies the network;
N has no public key and receives no content root or traffic key.

V1 is a [legacy reference](direct-channel-wire-v1.md), not a fallback. V2 decoders
reject V1 descriptors, publications, messages and pending records. Existing V1
disk records must remain untouched: no rewrite, deletion, regeneration or
implicit migration follows rejection.

## Canonical transport

Canonical bytes are exactly Go `encoding/json.Marshal` output, in the declaration
order below, with every field required. Decoders require byte equality with
re-encoding and reject missing, duplicate or unknown fields, reordered fields,
whitespace, alternate escapes and invalid UTF-8. Nested objects follow their own
field order. Binary strings use strict unpadded base64url, including canonical
trailing bits. Digest fields named `authorizationDigest`, `keyEvidenceDigest`
and `termsDigest` are instead lowercase hex SHA256 (64 characters). Descriptor,
publication, challenge and proof bounds are respectively 8192, 12288, 4096 and
1024 bytes.

The exact transport fields, in canonical order, are:

- Endpoint: `tenantId`, `principalId`, `endpointId`, `publicKey`, `credentialId`,
  `keyEvidenceDigest`.
- Limits: `maxMessageWireBytes`, `maxMessagesPerMinute`, `maxMessagesPerDay`,
  `maxWireBytesPerDay`, `maxInFlight`, `maxTurnsPerThread`.
- Budget: `agreementId`, `acceptedRevision`, `termsDigest`, `expiresAt`,
  `countingVersion`, `grantLimits` (a limits object).
- Descriptor: `domain`, `suite`, `parentGrantId`, `grantGeneration`,
  `channelGeneration`, `directIntentId`, `networkId`, `authorizationDigest`,
  `s`, `p` (endpoint objects), `epochId`, `expiresAt`, `budget`, `limits`.
- Publication: `descriptor` (the complete descriptor object), `enc`, `ciphertext`.
- Readiness challenge: `domain`, `challengeId`, `role`, `principalId`,
  `endpointId`, `credentialId`, `channelId`, `parentGrantId`, `grantGeneration`,
  `channelGeneration`, `directIntentId`, `descriptorHash`, `publicationHash`,
  `epochId`, `nonce`, `issuedAt`, `expiresAt`.
- Readiness proof: `protocolVersion`, `challengeId`, `transcriptHash`,
  `confirmation`.

The descriptor domain is `pagnet/direct_ask_reply_v2`; its suite is
`X25519-HKDF-SHA256-AES-256-GCM-Auth`. All ID fields are canonical nonzero UUID
strings; `epochId` additionally requires UUIDv7 with the RFC4122 variant.
`grantGeneration`, `channelGeneration` and `acceptedRevision` are positive
uint64 values encoded as canonical decimal JSON strings, including values beyond
JavaScript's exact integer range. Accepted revision must be at least 2.
Times are canonical UTC RFC3339Nano, years 1–9999. Descriptor expiry must be in
the future and no later than the accepted budget expiry.

Public keys are canonical 32-byte X25519 field elements below 2^255-19, rejecting
low-order points. S and P must have distinct principals, endpoints and public
keys. The caller resolves authenticated retained grant, consent, authorization,
credential and key evidence and supplies the exact expected descriptor. Structural
transport validation alone authenticates none of that evidence. Pin the exact
selected S and P tenant, principal, endpoint, public key, credential ID and key
evidence digest; selecting another endpoint of the same principal is a different
binding. Managed credential secrets authenticate local authority; they are never
the content root and are never published.

The parent grant generation and channel generation are independent bindings.
`directIntentId` binds the exact direct-channel intent. `authorizationDigest`
binds retained authorization evidence. Budget acceptance binds the exact agreement,
accepted revision, terms digest, expiry, counting version and grant limits, not
merely an agreement ID or the latest offered terms. Channel limits must be no
greater than every corresponding grant limit.

Both grant and channel limits require message wire bytes 1024–65536, messages per
minute 1–10, messages per day 1–200, wire bytes per day at least the message limit
and at most 8388608, in flight 1–2, and turns per thread 1–16. Counting version is
`canonical_encrypted_wire_bytes_utc_minute_day_ask_reply_each_v1`: ASK and REPLY
each count as a message and each contributes its complete canonical encrypted
wire bytes, using UTC minute/day windows. These are not ASK-only quotas.
Enforcement and authoritative budget availability require server/store state.

`channelId` is base64url(SHA256(canonical JSON of the ordered fields `domain`,
`parentGrantId`, `grantGeneration`, `channelGeneration`, `directIntentId`, `s`,
`p`, `epochId`)), with domain `pagnet/direct_ask_reply_v2/channel-id`.
`descriptorHash` and `publicationHash` are base64url SHA256 of the entire exact
canonical descriptor and publication respectively. Fields outside the channel
identity remain bound by the complete immutable descriptor hash.

## Private key material and publication

`directPrepare` validates the exact expected descriptor and checks S's private
key against the selected public key. It draws a fresh random 32-byte content
root, then uses RFC 9180 authenticated HPKE with P's public key and S's private
key. Info is the literal bytes `pagnet/direct_ask_reply_v2/epoch-wrap`; AAD is
the raw 32-byte SHA256 of the canonical descriptor, not its base64url or hex
text. `directAccept` checks P's private key, pins S's public key, validates the
exact descriptor and authenticates the same context before accepting the root.
A new epoch uses a fresh UUIDv7; callers must ensure uniqueness.

The publication contains only `descriptor`, `enc` (32 bytes) and `ciphertext`
(48 bytes). It contains no credential secret, content root, readiness key or
traffic key. The local material is unexported and must not be serialized to N.
A readiness key may be supplied separately to the verifier where authorized.
HKDF-SHA256 uses the fresh content root as input, raw descriptor SHA256 as salt,
and the literal info strings `pagnet/direct_ask_reply_v2/readiness`,
`pagnet/direct_ask_reply_v2/ASK`, and `pagnet/direct_ask_reply_v2/REPLY` to derive
independent 32-byte keys.

Messages use AES-256-GCM with a fresh random 12-byte nonce, the full canonical
header as AAD and a 16-byte tag. They bind the V2 domain, channel and descriptor
hash, immutable message/root IDs and exact endpoint parties. REPLY additionally
binds the original ASK ID and SHA256 of its complete canonical wire. Opening a
REPLY requires the exact original ASK wire; P authenticates that ASK before
sealing the reply. Local role, descriptor expiry and message wire limits are
enforced. Replay detection, immutable server IDs, cancellation, revocation and
terminal-reply policy require state outside these helpers.

## Durable retry and reload

Reserve the channel durably before creating its pending record, and persist the
validated pending record before returning publication bytes for first use. Keep
the exact randomized HPKE publication and root. A retry returns the stored
publication, including its original encapsulation and ciphertext; it must never
prepare a new publication for the same reservation. Conflicting bindings and
missing, corrupt or incompatible reserved records fail closed without
regeneration. P retries must also match the exact accepted root and publication.

The authenticated private pending record binds the V2 descriptor, its hash,
channel identity, role, endpoint key fingerprints, root and exact publication.
On reload, validate the complete canonical V2 record, descriptor, fingerprints,
root, role and publication bindings before restoring the material's publication
hash. Merely hashing supplied publication bytes or reconstructing a descriptor
is insufficient. Readiness requires this validated exact publication binding.

Persist a complete authenticated outgoing wire before its first send. Reusing a
message ID permits only identical complete stored bytes; preserve its original
nonce, ciphertext and linkage on every retry. Store ciphertext, not plaintext.
A remote byte conflict is terminal and must never be retried under a new ID.
Local authenticated files do not provide an anti-rollback anchor; authoritative
status must bind the exact descriptor and publication hash before local active
state can authorize use. A local active marker is historical evidence, not
server activation or freshness proof.

## Readiness

The challenge domain is `pagnet/direct_ask_reply_v2/proof`. Its role is exactly
`S` or `P`; its principal, endpoint and credential must equal the selected role's
descriptor fields. Channel, parent grant, both generations, direct intent,
descriptor hash, exact publication hash and epoch must all match. Nonce is a
canonical 32-byte value. Challenge ID is a canonical nonzero UUID. `issuedAt`
must not be in the future, `expiresAt` must be after the current time and issued
time, at most five minutes after issuance, and no later than descriptor expiry.
The issuer must generate unpredictable nonces and authenticate current authority.

The private helper HMACs the exact canonical challenge bytes with the readiness
key using HMAC-SHA256. The canonical proof uses protocol version
`direct_channel_readiness_v2`, the exact challenge ID, base64url SHA256 of those
challenge bytes as `transcriptHash`, and base64url HMAC as `confirmation`.
Verification compares the transcript digest and MAC in constant time and checks
all bindings and times. Retrying the same still-valid challenge produces exactly
the same proof. Single-use replay consumption belongs outside the private helper;
proof possession alone establishes neither current consent/budget authority nor
server activation.
