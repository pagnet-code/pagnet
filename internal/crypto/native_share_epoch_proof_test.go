package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeShareEpochProofSignatureOnly(t *testing.T) {
	fresh, metadata, source, holder, now := nativeShareEpochFixture(t)
	p, err := SealNativeShareEpoch(fresh, metadata, source, now)
	if err != nil {
		t.Fatal(err)
	}
	c := transport.NativeShareEpochProofChallenge{Version: 1, BindingID: "10000000-0000-4000-8000-000000000008", StageDigest: strings.Repeat("ab", 32), Metadata: metadata, CommandID: "10000000-0000-4000-8000-000000000009", ChallengeID: "10000000-0000-4000-8000-000000000010", Nonce: bytes.Repeat([]byte{3}, 32), ExpiresAt: now.Add(time.Second).Format(time.RFC3339Nano)}
	verifier, _ := hex.DecodeString(metadata.EpochPossessionVerifier)
	private := holder.Bytes()
	before := append([]byte(nil), private...)
	for i := 0; i < 2; i++ {
		signature, err := ProveNativeShareEpoch(p, metadata, source.Public().(ed25519.PublicKey), private, c, now)
		if err != nil {
			t.Fatal(err)
		}
		transcript, err := c.CanonicalBytes()
		if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(verifier, transcript, signature) {
			t.Fatal("invalid epoch proof", err)
		}
	}
	if !bytes.Equal(before, private) {
		t.Fatal("modified caller holder private key")
	}
	for _, name := range []string{"source", "holder", "metadata", "expiry", "verifier"} {
		t.Run(name, func(t *testing.T) {
			changed, expected, trust, key, clock := c, metadata, source.Public().(ed25519.PublicKey), private, now
			switch name {
			case "source":
				trust = make(ed25519.PublicKey, ed25519.PublicKeySize)
			case "holder":
				key = make([]byte, 32)
			case "metadata":
				expected.GrantGeneration++
			case "expiry":
				clock = now.Add(time.Second)
			case "verifier":
				expected.EpochPossessionVerifier = strings.Repeat("00", 32)
				changed.Metadata = expected
			}
			signature, err := ProveNativeShareEpoch(p, expected, trust, key, changed, clock)
			if err == nil || len(signature) != 0 {
				t.Fatal("rejected proof returned a signature")
			}
		})
	}
}
