# Closed managed endpoint host custody proof v1

This dormant, pure transport contract proves possession of the dedicated reserved
host X25519 private key. It does not authorize activation or prove execution of a
model process. It has no daemon route, credential, key lookup or network key.

`DirectAuthorizationSnapshotV1` fixes the complete S_i → P V3 consent snapshot.
Its declared Go field order is the canonical JSON field order. Every field is
required, including explicit null target network and membership generation.
Selected sources are unique and sorted by principal UUID, with 1–4 entries.
Versions and grant generation are JSON int64 numbers; authority generations are
canonical UUID strings, matching the server's stored generation identifiers.
Timestamps use canonical UTC RFC3339Nano. The snapshot digest is lowercase hex
SHA256(`pagnet/direct-authorization-snapshot/v1/` || canonical snapshot JSON).

A receipt reference contains the binding intent ID, original Prepare command ID
and lowercase hex SHA256 of the complete canonical successful Prepare ACK, with
no digest prefix. The challenge contains both the exact Prepare command and ACK,
including the complete binding subject, reservation digest, configured server
origin, installation ID and public key. It also contains the complete snapshot
and snapshot digest. Its binding principal/account/tenant identify the invitee P;
the snapshot source S_i is independently selected. Direct intent IDs must match.

The protocol is `managed_endpoint_host_custody_pop_v1`; the suite is
`X25519-HKDF-SHA256-HMAC-SHA256`. Each challenge carries a fresh random UUID,
fresh random 32-byte nonce, fresh server ephemeral X25519 public key, issue time
and expiry. Binary wire fields use lowercase hex. Public keys use canonical
little endian field encodings below 2^255−19. The lifetime is positive and at most
five minutes, within both binding and direct-intent lifetimes. Confirmation is
accepted only at issue time or later and strictly before expiry.

For canonical challenge bytes C:

1. T = SHA256(`pagnet/managed-endpoint-host-custody-pop/transcript/v1/` || C).
2. Z = X25519(host private key, server ephemeral public key), using the standard
   library RFC7748 implementation. Invalid/low-order inputs and zero DH fail.
   The host private key's public key must equal the reserved public key.
3. K = HKDF-SHA256(Z, salt = decoded nonce, info =
   `pagnet/managed-endpoint-host-custody-pop/kdf/v1/` || T, length = 32).
4. Confirmation = HMAC-SHA256(K,
   `pagnet/managed-endpoint-host-custody-pop/host-confirm/v1/` || T).

The proof contains the protocol, suite, challenge ID, lowercase hex T and
lowercase hex confirmation. X25519 is used for DH only. No signatures are used.
The server can derive the same Z with its ephemeral private key and reserved host
public key, then compare the exact challenge ID, transcript hash and confirmation
in constant time. It must consume the challenge atomically to prevent replay.

Decoders accept bounded exact canonical JSON only. They reject unknown, missing
or duplicate fields, trailing data, malformed Unicode, alternate numeric/time
encodings, whitespace and alternate escapes. Authentication of ingress, exact
comparison with independently retained enrollment/consent/origin state, fresh
random generation, replay storage and current authorization checks are caller
duties; these pure helpers do not establish them.

Golden JSON vectors live in `transport/testdata/managed_endpoint_pop_v1`. Tests
also cover the RFC7748 Alice/Bob vector, independent server-side derivation,
purpose separation, every transcript leaf, valid transcript changes, malformed
wire representations, low-order keys and expiry boundaries.
