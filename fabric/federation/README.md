# Explicit encrypted federation transport

This package is the **transport boundary**, not an authority factory or a
completed federation deployment. It provides RFC 9180 authenticated HPKE using
CIRCL's existing X25519/HKDF-SHA256/AES-256-GCM implementation. Transport exchange
keys are distinct from registry signing keys. No custom crypto, cloud tokens,
implicit trusted peers, key conversion, fallback or retry is used.

Composition must supply actual owner-certified peer bindings, explicitly pinned
current roots, exchange-key revisions and a mandatory `TrustGate`. Its callback
holds those current trust fences across each bounded cryptographic operation.
`KeyProvider` selects only the certified local exchange private key before the
registry transaction opens. The current trust fence then rechecks that exact
certificate immediately before synchronous cryptography; external credential
resolution never runs while holding the registry transaction. This package
does not create owner certificates or infer authority from received JSON.

One channel has two independent authenticated HPKE contexts. Channel and receiver
routes are independently chosen opaque 32-byte values. Profile, channel, route,
direction, exact ordinal and initial encapsulation are authenticated. Contexts
are never resumed after transport loss; invocation admission/recovery is a
separate durable destination-node responsibility. A successful write, EOF,
transport ACK or encrypted record does not prove invocation admission or native
completion.

`ConnStream` owns an explicitly supplied connection and its read/write deadlines.
Records use a bounded four-byte length prefix followed by closed-profile JSON.
It checks the length before allocating the body, rejects unknown outer fields,
trailing documents and malformed counters, and synchronously backpressures
writes. Cancellation interrupts only owned I/O. `Duplex` encrypts/decrypts one
record per pull and enforces finite combined plaintext byte credit.

`RelayOpaque` owns two explicitly selected packet streams and routes. It has no
private keys or decryption API. It permits at most one bounded in-flight record
per direction, requires exact sequential opaque routing, enforces finite combined
packet/byte/lifetime budgets, closes both connections when either direction ends,
and joins both forwarding loops. The relay sees routing values, ciphertext
volume and timing; this is not traffic-analysis protection.

Limits: plaintext record at most 64KiB, encoded wire record at most 96KiB, at most
65,536 records per direction, duplex combined plaintext budget at most 128MiB,
and relay combined ciphertext budget at most 256MiB. Operator-selected I/O and
relay lifetimes must be finite. `ForwardChannel` fragments bounded private request bundles into encrypted
records, validates exact length/digest/end before publication, and preserves
original/final envelope bytes. It never buffers native responses; response pull
framing remains the actual node composition responsibility. No endpoint is discovered or selected by this package.

`VerifyForwardBundle` verifies `fabric.SignedForwardProof` using the actual
pinned source root, both exact envelope digests, full principal, immutable system
fields, canonical expiry/deadline and retained engine lineage. Original ancestry,
parent, origin and trigger lineage remain unchanged; the network hop increments
exactly once and the previous extension chain remains a prefix. It invokes the
trusted destination callback inside mandatory current peer trust. The callback
must separately perform destination-global durable replay admission and current
operation policy before execution. Proof authentication does not permit replay. Catalog synchronization is a
separate audience-bound filtered projection; it must not pretend a filtered
subset is a full signed registry-chain import.

Tests currently prove transport/crypto behavior using actual retained registry
roots, explicitly pinned fixture exchange keys and real owned `net.Conn` streams.
A separate positive fixture uses the genuine same retained
`registry.Store.SignForwardExact` signer, encrypted blind relay and destination
verifier. Adversarial re-signed malformed system-field cases are explicitly
cryptographic unit fixtures. Trusted test ingress contexts and exchange pins do
not claim product root-issued peer certificates, a running production relay,
node forwarding authorization, durable remote replay admission, catalog
synchronization or end-to-end federation execution are already integrated.

`internal/fabricfederation` supplies a concrete current-peer gate using genuine
root-signed certificates and bilateral retained pins. Its tests cover the real
root signer, HPKE, revocation, rotation and exact same-transaction admission
checks. This is tested composition infrastructure; the daemon's remote transport,
catalog synchronization and execution routes still require product integration.
