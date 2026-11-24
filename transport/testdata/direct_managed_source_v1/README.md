These deterministic vectors cover the closed source-role transport only. The
private test inputs are repeated bytes 0x31 (host) and 0x42 (server), never live
keys. Regenerate with:

    GOWORK=off UPDATE_DIRECT_MANAGED_SOURCE_GOLDEN=1 go test ./transport -run TestDirectManagedSourceGolden

`binding.json` is shared with the retained server migration 0188 encoding at
pagnet-server commit 4853ca6. It was independently unmarshaled into the server's
`store.DirectManagedSourceBinding` and marshaled by that server type, comparing
all bytes. Its domain-prefixed SHA256 was independently checked against
`binding_digest.txt`. The Go server encoder produced the same bytes and digest.

The source receipt has exactly `bindingId`, `commandId`, and `receiptDigest`.
Its digest is plain SHA256 of the canonical complete successful source Prepare
ACK. It is separate from target receipts. Future server persistence must retain
this exact ACK digest. The source binding digest uses
`pagnet/direct-managed-source-binding/v1/`; reservation and PoP use the separate
source domains declared in the transport implementation.
