package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// snapshotSigningPublicKey uses the stable persisted host identity. Validate the
// complete signer before offering its public key on this admission.
func (d *Daemon) snapshotSigningPublicKey() (string, error) {
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		return "", err
	}
	private := identity.Ed25519Signer()
	public := identity.Ed25519Verifier()
	if len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize {
		return "", errors.New("snapshot signing identity has malformed ed25519 keys")
	}
	derived := ed25519.NewKeyFromSeed(private.Seed())
	if !bytes.Equal(private, derived) || !bytes.Equal(public, derived.Public().(ed25519.PublicKey)) {
		return "", errors.New("snapshot signing identity has mismatched ed25519 keys")
	}
	return base64.StdEncoding.EncodeToString(public), nil
}
