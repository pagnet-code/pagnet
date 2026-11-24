# Closed direct managed source enrollment and credential v2

The transport primitives in `transport/direct_managed_source_*_v2.go` provide
public enrollment evidence and X25519/HKDF-SHA256/HMAC-SHA256 derivation only.
They do not install, retain, renew, activate or authorize a channel or process.
The existing host message names carry explicitly versioned payloads; this change
adds no dispatcher or daemon handlers.

V2 is an indivisible binding, Prepare, custody PoP and credential transcript.
All nested evidence uses V2 types. The Prepare receipt reference includes
`protocolVersion: "direct_managed_source_prepare_v2"` before `bindingId`,
`commandId` and `receiptDigest`. V2 decoders reject V1 payloads, and V1
encodings, five-minute bounds and equal credential/enrollment expiry rules
remain unchanged. There is no fallback or implicit migration.

Canonical JSON is exactly Go `encoding/json.Marshal` output in the corresponding
struct declaration order. Every field is required, including empty predecessor
fields for generation 1. Decoders compare complete canonical bytes and reject
unknown, missing, duplicate, reordered or differently escaped fields, malformed
Unicode, whitespace, alternate timestamps and trailing data. Times encode UTC.
Identifiers use the existing canonical UUID validation; keys, nonces and hashes
are 32-byte lowercase hex strings. X25519 points must be canonical and usable.

The V2 binding preserves the complete V1 source subject, source role `S`,
authorization snapshot and accepted budget reference. It changes
`bindingGeneration` to a positive decimal string without leading zeros, adds
`predecessorBindingId` and `previousCredentialId`, and replaces `expiresAt` with
`enrollmentExpiresAt` and `authorizationExpiresAt`. Both predecessor fields are
empty for generation `"1"`; later generations require canonical IDs. A binding
cannot name itself as predecessor, and an issue cannot reuse its previous
credential ID. `channelGeneration` is also a positive decimal string and must
exactly equal the nested binding generation. Generations are identifiers supplied
by the authority, never inferred from local counters. Exact predecessor identity
is established against independently retained evidence, including with
`DirectManagedSourceKeyReservationV2.VerifySubject`.

The deadline rules are:

- `createdAt < enrollmentExpiresAt <= authorizationExpiresAt`, with enrollment
  at most five minutes after creation.
- PoP issuance and expiry are within enrollment, and the challenge lasts at most
  five minutes. PoP confirmation and verifier derivation require a live challenge.
- Credential issuance occurs during the PoP challenge and
  `issuedAt < installExpiresAt <= enrollmentExpiresAt`.
- `installExpiresAt <= credentialExpiresAt <= authorizationExpiresAt`, and
  `credentialExpiresAt <= budgetExpiresAt`.

Installation may outlive the challenge used to authorize issuance. Credential
validity may outlive enrollment. Derivation is allowed only before installation
expiry, with expiry itself excluded. The caller must independently authenticate
the issuer and current authority, retain and compare the exact intent, source
role, generation, predecessors, host incarnation, authorization snapshot and
budget, enforce freshness and single use, and reject expired or revoked authority.
A structurally valid proof receipt does not assert proof acceptance.

V2 uses these SHA256 domain prefixes over canonical public evidence:

- Binding: `pagnet/direct-managed-source-binding/v2/`.
- Reservation: `pagnet/closed-direct-managed-source-key/v2/` (digest field empty).
- Prepare receipt: `pagnet/direct-managed-source-prepare/receipt/v2/`.
- PoP transcript: `pagnet/direct-managed-source-host-custody-pop/transcript/v2/`.
- Proof receipt: `pagnet/direct-managed-source-host-custody-pop/proof/v2/`.
- Credential transcript: `pagnet/direct-managed-source-credential/transcript/v2/`.

PoP HKDF info is `pagnet/direct-managed-source-host-custody-pop/kdf/v2/`
followed by the raw 32-byte transcript hash; its salt is the decoded nonce.
HMAC confirmation uses `pagnet/direct-managed-source-host-custody-pop/host-confirm/v2/`
followed by the transcript hash. The public verifier hashes
`pagnet/direct-managed-source-host-custody-pop/verifier/v2/`, transcript hash and
confirmation, in order.

Credential derivation uses the same algorithms as V1, with every suffix changed
to `/v2/`: `credential-secret`, `install-key`, `host-install`, `credential-hash`
and `install-verifier` under `pagnet/direct-managed-source-credential/`.
The secret and installation keys use separate HKDF info strings followed by the
raw transcript hash. Secret hashes and verifier digests bind the raw transcript
hash before the secret or confirmation. Callers compare public verifier digests
in constant time and clear private key material and returned credential secrets.
