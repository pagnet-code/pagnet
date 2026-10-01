package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestEpochPossessionDerivationScopeAndKey(t *testing.T) {
	kr := &Keyring{NetworkID: "network", Epochs: []KeyEpoch{{ID: "epoch", State: EpochActive, CreatedAt: time.Now(), Key: bytes.Repeat([]byte{7}, 32)}}}
	signer, err := EpochPossessionSigner(kr, "epoch")
	if err != nil {
		t.Fatal(err)
	}
	again, err := EpochPossessionSigner(kr, "epoch")
	if err != nil || !bytes.Equal(signer, again) {
		t.Fatal("unstable derivation")
	}
	kr.Epochs[0].State = EpochRotated
	retained, err := EpochPossessionSigner(kr, "epoch")
	if err != nil || !bytes.Equal(signer, retained) {
		t.Fatal("retained admitted epoch lost its original verifier")
	}
	proof := ed25519.Sign(signer, []byte("fresh nonce binding"))
	for _, name := range []string{"network", "epoch", "key", "revoked"} {
		t.Run(name, func(t *testing.T) {
			other := *kr
			other.Epochs = append([]KeyEpoch(nil), kr.Epochs...)
			id := "epoch"
			switch name {
			case "network":
				other.NetworkID = "different"
			case "epoch":
				other.Epochs[0].ID = "different"
				id = "different"
			case "key":
				other.Epochs[0].Key = bytes.Repeat([]byte{8}, 32)
			case "revoked":
				other.Epochs[0].State = EpochRevoked
			}
			different, err := EpochPossessionSigner(&other, id)
			if name == "revoked" {
				if err == nil {
					t.Fatal("revoked key usable")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ed25519.Verify(different.Public().(ed25519.PublicKey), []byte("fresh nonce binding"), proof) {
				t.Fatal("scope/key change retained readiness")
			}
		})
	}
}
