# Direct managed source v2 public vectors

These canonical JSON bytes and public hashes cover the v2 binding, PoP and credential installation transcript. The test independently reconstructs the crypto operations using standard library primitives and literal v2 domain strings. No credential secret or private key is stored here.

The fixture uses deterministic keys solely for tests. They must never be used in production.

Regenerate from the module root:

```sh
UPDATE_DIRECT_MANAGED_SOURCE_V2_GOLDEN=1 GOWORK=off go test ./transport -run '^TestDirectManagedSourceGoldenV2$' -count=1
```
