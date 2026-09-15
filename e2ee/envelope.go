package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Version and cipher-suite constants for the v1 envelope.
const (
	// EnvelopeVersion is the current EncryptedPayloadV1 version.
	EnvelopeVersion = 1
	// CipherSuiteAES256GCM is the AEAD used for both the payload encryption
	// and the CEK wrap. AES-256-GCM is WebCrypto-compatible (required for
	// browser interop, plan §11.3).
	CipherSuiteAES256GCM = "AES-256-GCM"
	// AADVersion is the current AAD serialization version.
	AADVersion = 1
)

// EncryptedPayloadV1 is the versioned wire envelope for one protected
// object.
//
// The canonical wire encoding is compact JSON with the keys in the EXACT
// order declared below (no whitespace, no HTML escaping, no trailing
// newline). That key order is the cross-implementation contract: the Go
// client, the Go server and the browser must all emit byte-identical
// canonical JSON for the same field values (see VectorsV1).
//
// Field semantics:
//   - Nonce is the base64 12-byte GCM nonce for the payload encryption
//     (the payload is encrypted under the per-object CEK).
//   - Ciphertext is the base64 GCM ciphertext+tag of the payload, encrypted
//     under the CEK with the canonical AAD as associated data.
//   - WrappedContentKey is the base64 CEK wrapped under the network
//     key-epoch key. It is a self-contained GCM record:
//     nonce (12 bytes) || ciphertext+tag of the 32-byte CEK. The CEK wrap
//     uses no associated data; the epoch key itself binds it to the epoch
//     (each epoch has a distinct random key).
type EncryptedPayloadV1 struct {
	Version           int    `json:"version"`
	CipherSuite       string `json:"cipher_suite"`
	KeyEpochID        string `json:"key_epoch_id"`
	Nonce             string `json:"nonce"`
	Ciphertext        string `json:"ciphertext"`
	WrappedContentKey string `json:"wrapped_content_key"`
	AADVersion        int    `json:"aad_version"`
}

// CanonicalJSON returns the canonical wire encoding of the envelope: compact
// JSON, keys in the fixed declaration order, no HTML escaping, no trailing
// newline. This is the cross-implementation wire contract.
func (e EncryptedPayloadV1) CanonicalJSON() ([]byte, error) {
	return canonicalJSON(e)
}

// Validate checks the envelope's fixed fields and base64 encodings. It does
// NOT verify authentication (that is Decrypt's job with the epoch key).
func (e EncryptedPayloadV1) Validate() error {
	if e.Version != EnvelopeVersion {
		return fmt.Errorf("e2ee: unsupported envelope version %d (want %d)", e.Version, EnvelopeVersion)
	}
	if e.CipherSuite != CipherSuiteAES256GCM {
		return fmt.Errorf("e2ee: unsupported cipher suite %q (want %q)", e.CipherSuite, CipherSuiteAES256GCM)
	}
	if e.AADVersion != AADVersion {
		return fmt.Errorf("e2ee: unsupported aad_version %d (want %d)", e.AADVersion, AADVersion)
	}
	if e.KeyEpochID == "" {
		return errors.New("e2ee: empty key_epoch_id")
	}
	if n, err := base64.StdEncoding.DecodeString(e.Nonce); err != nil {
		return fmt.Errorf("e2ee: nonce is not valid base64: %w", err)
	} else if len(n) != gcmNonceSize {
		return fmt.Errorf("e2ee: nonce is %d bytes, want %d", len(n), gcmNonceSize)
	}
	if _, err := base64.StdEncoding.DecodeString(e.Ciphertext); err != nil {
		return fmt.Errorf("e2ee: ciphertext is not valid base64: %w", err)
	}
	if w, err := base64.StdEncoding.DecodeString(e.WrappedContentKey); err != nil {
		return fmt.Errorf("e2ee: wrapped_content_key is not valid base64: %w", err)
	} else if len(w) < gcmNonceSize+gcmTagSize {
		return fmt.Errorf("e2ee: wrapped_content_key is %d bytes, want at least %d", len(w), gcmNonceSize+gcmTagSize)
	}
	return nil
}

// canonicalJSON encodes v as compact JSON with no HTML escaping and no
// trailing newline. Struct fields emit in declaration order, which is the
// canonical key order for the wire contract.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
