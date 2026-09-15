package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HostIdentity is the stable per-host crypto identity (plan §11.5). It is
// generated locally and survives daemon restarts — it is per HOST, not per
// ephemeral Runner. It holds:
//   - an X25519 keypair, the HPKE receiver identity (key transfer);
//   - an Ed25519 keypair, for signing crypto metadata (provenance).
//
// The private keys are stored 0600 at <stateDir>/e2ee/host.json and never
// logged.
type HostIdentity struct {
	// X25519Pub / X25519Priv are the 32-byte HPKE receiver keys.
	X25519Pub  []byte `json:"x25519_pub"`
	X25519Priv []byte `json:"x25519_priv"`
	// Ed25519Pub / Ed25519Priv are the signing keys (32-byte public,
	// 64-byte private).
	Ed25519Pub  []byte `json:"ed25519_pub"`
	Ed25519Priv []byte `json:"ed25519_priv"`
}

// String is a safe, key-free representation for logging.
func (h *HostIdentity) String() string {
	return "HostIdentity{x25519+ed25519}"
}

// NewHostIdentity generates a fresh host crypto identity locally.
func NewHostIdentity() (*HostIdentity, error) {
	// X25519 (HPKE receiver) via the audited circl KEM scheme.
	x25519Pub, x25519Priv, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("crypto: generate x25519: %w", err)
	}
	x25519PubBytes, err := x25519Pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal x25519 public: %w", err)
	}
	x25519PrivBytes, err := x25519Priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal x25519 private: %w", err)
	}
	// Ed25519 (signing) via the standard library.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ed25519: %w", err)
	}
	return &HostIdentity{
		X25519Pub:   x25519PubBytes,
		X25519Priv:  x25519PrivBytes,
		Ed25519Pub:  edPub,
		Ed25519Priv: edPriv,
	}, nil
}

// HPKEPublicKey returns the X25519 public key as a circl kem.PublicKey.
func (h *HostIdentity) HPKEPublicKey() (kem.PublicKey, error) {
	return hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(h.X25519Pub)
}

// HPKEPrivateKey returns the X25519 private key as a circl kem.PrivateKey.
func (h *HostIdentity) HPKEPrivateKey() (kem.PrivateKey, error) {
	return hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(h.X25519Priv)
}

// Ed25519Signer returns the Ed25519 private key (for signing).
func (h *HostIdentity) Ed25519Signer() ed25519.PrivateKey {
	return ed25519.PrivateKey(h.Ed25519Priv)
}

// Ed25519Verifier returns the Ed25519 public key (for verification).
func (h *HostIdentity) Ed25519Verifier() ed25519.PublicKey {
	return ed25519.PublicKey(h.Ed25519Pub)
}

// HostPath returns the host-identity file path.
func HostPath(stateDir string) string {
	return filepath.Join(stateDir, "e2ee", "host.json")
}

// Save writes the host identity to disk as a 0600 file, atomically (see
// writeFileAtomic): a crash mid-write must not tear the identity, whose
// regeneration would orphan pending key packages.
func (h *HostIdentity) Save(stateDir string) error {
	path := HostPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("crypto: mkdir host dir: %w", err)
	}
	b, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("crypto: marshal host identity: %w", err)
	}
	if err := writeFileAtomic(path, b); err != nil {
		return fmt.Errorf("crypto: write host identity: %w", err)
	}
	return nil
}

// EnsureHostIdentity loads the host identity from disk, generating and saving
// a fresh one if it does not exist yet. This is the daemon's entry point for
// the stable per-host identity: call it once per host (it is idempotent and
// survives daemon restarts — it is per HOST, not per ephemeral Runner).
func EnsureHostIdentity(stateDir string) (*HostIdentity, error) {
	if h, err := LoadHostIdentity(stateDir); err == nil {
		return h, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	h, err := NewHostIdentity()
	if err != nil {
		return nil, err
	}
	if err := h.Save(stateDir); err != nil {
		return nil, err
	}
	return h, nil
}

// LoadHostIdentity reads the host identity from disk.
func LoadHostIdentity(stateDir string) (*HostIdentity, error) {
	b, err := os.ReadFile(HostPath(stateDir))
	if err != nil {
		return nil, fmt.Errorf("crypto: read host identity: %w", err)
	}
	var h HostIdentity
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("crypto: parse host identity: %w", err)
	}
	if len(h.X25519Pub) != 32 || len(h.X25519Priv) != 32 {
		return nil, fmt.Errorf("crypto: host identity has malformed x25519 keys")
	}
	if len(h.Ed25519Pub) != ed25519.PublicKeySize || len(h.Ed25519Priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("crypto: host identity has malformed ed25519 keys")
	}
	return &h, nil
}
