package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// EpochPossessionSigner derives a separate signing key locally. Its public
// verifier cannot decrypt content, and its seed is never persisted or relayed.
func EpochPossessionSigner(kr *Keyring, epochID string) (ed25519.PrivateKey, error) {
	if kr == nil || kr.NetworkID == "" || epochID == "" {
		return nil, errors.New("crypto: invalid possession scope")
	}
	epoch, ok := kr.EpochByID(epochID)
	if !ok || (epoch.State != EpochActive && epoch.State != EpochRotated) || len(epoch.Key) != 32 {
		return nil, errors.New("crypto: requested possession epoch unavailable")
	}
	info, _ := json.Marshal(struct {
		Domain    string `json:"domain"`
		NetworkID string `json:"networkId"`
		EpochID   string `json:"epochId"`
	}{"pagnet.network-epoch-possession.seed.v1", kr.NetworkID, epochID})
	seed, err := hkdf.Key(sha256.New, epoch.Key, nil, string(info), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}
