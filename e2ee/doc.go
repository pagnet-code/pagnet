// Package e2ee is the public, versioned cryptography contract for Pagnet
// Private — Zero-Knowledge Content Encryption (E2EE).
//
// It defines the wire envelope (EncryptedPayloadV1), the associated-data
// binding (AAD), and the AES-256-GCM Encrypt/Decrypt operations. It is a
// leaf package: it has no dependencies on internal/ packages, so the
// private server (a separate module) and future browser implementations can
// import it and interoperate byte-for-byte.
//
// The cryptography is deliberately lightweight (plan §11.3): standard,
// audited primitives only. Each protected object gets a fresh random 256-bit
// content encryption key (CEK); the payload is encrypted with AES-256-GCM
// under the CEK, and the CEK is wrapped under the network key-epoch key with
// AES-256-GCM (NOT AES-KW — WebCrypto has no AES-KW, and AES-256-GCM is the
// WebCrypto-compatible AEAD required for browser interop).
//
// The canonical JSON encodings of the envelope and the AAD are a
// cross-implementation wire contract, pinned by the committed test vectors
// in VectorsV1.
package e2ee
