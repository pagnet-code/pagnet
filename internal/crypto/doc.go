// Package crypto is the customer-side E2EE client for Pagnet Private —
// Zero-Knowledge Content Encryption. It is the stateful, storage-backed layer
// on top of the public github.com/pagnet-code/pagnet/e2ee wire contract.
//
// It owns:
//   - the per-network keyring (rotating 256-bit key epochs), stored 0600 at
//     <stateDir>/e2ee/<networkID>/keyring.json;
//   - the stable per-host crypto identity (X25519 HPKE receiver + Ed25519
//     signing key), stored 0600 at <stateDir>/e2ee/host.json;
//   - HPKE (RFC 9180, HPKE-X25519 / HKDF-SHA256 / AES-256-GCM) key transfer,
//     implemented with the audited github.com/cloudflare/circl/hpke;
//   - the Network Key Authority (NKA) role: activation, key-package build,
//     and the decryption challenge/proof that enrolls a new host;
//   - the client-side crypto self-test.
//
// The NKA is a ROLE played by an online customer-side host, not a server
// component: the control plane only relays the opaque HPKE key package and
// challenge. No key material ever leaves the customer side, and none is ever
// logged.
//
// This package is library-level: the daemon calls these functions. It does
// NOT define WSS wire messages (that integration is a follow-up).
package crypto
