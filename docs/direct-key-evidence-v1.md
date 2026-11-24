# Direct key evidence transcript v1

`transport.DirectKeyEvidenceTranscriptV1` commits the public closed evidence for
one role (`S` or `P`) of a V2 descriptor. Struct declaration order defines the
canonical JSON; every field is required, unknown fields and alternate encodings
are rejected, and the transcript is limited to 8192 bytes. It does not alter
existing descriptor or V1 transcript bytes.

`Digest()` returns lowercase hexadecimal SHA-256 of the canonical transcript
bytes, for the descriptor party's `keyEvidenceDigest`.
`DirectKeyEvidenceBindingTranscriptHashV1(role, raw)` requires the exact canonical
role-specific binding subject bytes and returns lowercase hexadecimal SHA-256 of
`pagnet/direct-key-evidence/binding/v1/` followed by those bytes. Existing binding
subject digest domains remain unchanged.

Authority generations retain their UUID encoding. Proposal version, accepted
revision and grant, channel, binding and key generations are canonical positive
uint64 decimal strings; the accepted budget revision must be at least 2.
Public keys use the same canonical unpadded base64url X25519 validation as V2.
Both the original counting contract and the reserved-v2 contract are accepted,
with each contract's pair and grant limit constraints. Effective expiry must be
canonical UTC and must not exceed budget expiry.

This is a pure wire commitment, not authentication or activation. The caller
must resolve the binding and evidence, check the selected principal, endpoint,
host and key against retained evidence, and authenticate current authority,
consent, budget and freshness. The transcript contains no secret-derived database
columns and introduces no daemon or server route.

The S/P JSON and digest fixtures in `transport/testdata/direct_key_evidence_v1`
freeze the canonical byte contract.
