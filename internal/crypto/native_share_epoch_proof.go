package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// ProveNativeShareEpoch opens only the caller-verified single epoch package.
// It returns a signature, never epoch material or a Keyring. Owned key and signer
// buffers are cleared best-effort on all paths.
func ProveNativeShareEpoch(p transport.NativeShareEpochPackage, expected transport.NativeShareEpochMetadata, source ed25519.PublicKey, holderPrivate []byte, challenge transport.NativeShareEpochProofChallenge, now time.Time) ([]byte, error) {
	if challenge.Metadata != expected || challenge.Validate(now) != nil {
		return nil, errNativeShareEpoch
	}
	transcript, err := challenge.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	key, err := OpenNativeShareEpoch(p, expected, source, holderPrivate, now)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	signer, err := epochPossessionSigner(key.Key, string(expected.NetworkID), string(expected.EpochID))
	if err != nil {
		return nil, err
	}
	defer clearNativeShareEpoch(signer)
	if hex.EncodeToString(signer.Public().(ed25519.PublicKey)) != expected.EpochPossessionVerifier {
		return nil, errNativeShareEpoch
	}
	return ed25519.Sign(signer, transcript), nil
}
