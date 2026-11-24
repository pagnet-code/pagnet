Deterministic closed source credential V1 vectors. Inputs are synthetic repeated
bytes: host private 0x31, source PoP server private 0x42, credential server private
0x53, credential nonce 0x64. No live keys or credential secrets are stored here.

Regenerate with:

    GOWORK=off UPDATE_SOURCE_CREDENTIAL_GOLDEN=1 go test ./transport -run '^TestDirectManagedSourceCredentialGolden$'

`issue.json` retains the complete source PoP challenge and canonical proof digest.
Both issue expiry fields equal the PoP and binding expiry. `ack.json` contains
only public installation confirmation. The remaining files contain lowercase
SHA256 hashes. The golden test independently reconstructs ECDH, HKDF and HMAC
using standard-library primitives; these files are available for server-side
wire comparison without any daemon or server activation.

All credential domains use `pagnet/direct-managed-source-credential/` followed
by `transcript/v1/`, `credential-secret/v1/`, `install-key/v1/`,
`host-install/v1/`, `credential-hash/v1/`, or `install-verifier/v1/`.
Nonce and X25519 public keys use exactly 32 bytes of lowercase hex.
