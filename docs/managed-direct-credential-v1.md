# Managed direct credential v1

`transport/managed_direct_credential.go` implements public canonical wire types
and pure credential derivation only. It does not install, persist, activate,
authorize, or dispatch credentials and defines no daemon or server routes.

The issue binds the complete canonical managed endpoint host-custody PoP
challenge, a receipt containing its challenge ID, transcript hash and plain
SHA256 of the canonical proof, the channel generation, and an accepted budget
reference. The budget retains an agreement ID, accepted revision (at least 2),
terms digest and expiry; it does not define shared budget terms.
`NewManagedDirectCredentialIssue` validates proof/challenge consistency and
computes the receipt. It does not verify the proof or assert server acceptance.

Callers authenticate the issuer and ingress, compare the issue with retained
binding, host incarnation, authorization, grant, channel and budget state, and
verify PoP acceptance independently. The issuer supplies a fresh random 32-byte
nonce and a fresh X25519 server key for each issue. Known reuse of the nested
PoP server key is rejected; pure helpers cannot establish global uniqueness.

Canonical issue fields are emitted in struct order. The nonce uses padded
standard base64; X25519 keys and SHA256 digests use lowercase hex. UUIDs use
canonical lowercase hyphenated form. Times use UTC RFC3339Nano. Strict decoders
reject omitted, duplicate, unknown or reordered fields, trailing input,
noncanonical encodings, malformed Unicode and oversized input. Issue size is
at most 96 KiB, and ACK/failure size is at most 1 KiB. All issue and nested PoP
X25519 public keys must be canonical encodings and must not be low-order points.

Derivation is valid only when `issuedAt <= now < installExpiresAt`. Installation
expires no later than five minutes after issue or the PoP expiry. Credential
expiry may outlive the PoP installation window but cannot exceed the binding,
authorization, grant or budget expiry. Installation must expire no later than
the credential.

For canonical issue bytes `I`, raw SHA256 digest `T`, X25519 shared secret `Z`,
and decoded issue nonce `N`, the exact operations are:

```
D = "pagnet/managed-direct-credential/"
T = SHA256(D || "transcript/v1/" || I)
Kcredential = HKDF-SHA256(Z, salt=N, info=D || "credential-secret/v1/" || T, L=32)
Kinstall = HKDF-SHA256(Z, salt=N, info=D || "install-key/v1/" || T, L=32)
confirmation = HMAC-SHA256(Kinstall, D || "host-install/v1/" || T)
credentialHash = SHA256(D || "credential-hash/v1/" || T || Kcredential)
installVerifier = SHA256(D || "install-verifier/v1/" || T || confirmation)
```

`DeriveManagedDirectCredentialVerifier` checks the server private/public match
and returns only transcript, credential and installation-verifier hashes.
`DeriveManagedDirectCredentialHost` checks the host private/reservation public
match and returns the credential secret and public installation ACK.
`DecodeManagedDirectCredentialACKVerifier` strictly decodes the ACK and derives
its verifier digest; callers must match the retained credential ID and
transcript and compare the expected digest in constant time. A digest alone is
not authentication. Identical issue retries derive identical results; callers
must enforce single use and current authority independently.

The fixed failure is exactly `protocolVersion`, `credentialId`, and
`error: "managed_direct_credential_install_failed"`. It carries no diagnostic or
secret. Public issue, ACK and verifier outputs never contain credential secrets,
private keys, shared secrets or installation keys. Callers own and clear input
private keys and returned credential secrets. Internal buffers are cleared on a
best-effort basis; Go crypto implementation copies cannot be guaranteed wiped.

Golden public artifacts live in
`transport/testdata/managed_direct_credential_v1`. Its `generate.py` independently
reproduces the Go fixture using Python `cryptography` and verifies existing
artifacts before writing. Test keys, nonces and timestamps are fixed; no derived
credential secret or installation key is written to a golden artifact.
