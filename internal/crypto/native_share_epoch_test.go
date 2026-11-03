package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeShareEpochFixture(t *testing.T) (*FreshNativeShareEpoch, transport.NativeShareEpochMetadata, ed25519.PrivateKey, *ecdh.PrivateKey, time.Time) {
	t.Helper()
	fresh, err := NewFreshNativeShareEpoch()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Destroy)
	_, source, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := transport.NativeShareEpochMetadata{
		Version: 1, OperationID: "10000000-0000-4000-8000-000000000001",
		TenantID: "10000000-0000-4000-8000-000000000002", NetworkID: "10000000-0000-4000-8000-000000000003",
		PreviousEpochID: "10000000-0000-4000-8000-000000000004", EpochID: fresh.ID(),
		ProposalRevision: 1, GrantGeneration: 2, BindingDigest: strings.Repeat("ab", 32),
		HolderID: "10000000-0000-4000-8000-000000000006", HolderX25519: hex.EncodeToString(holder.PublicKey().Bytes()),
		CommandID: "10000000-0000-4000-8000-000000000007", CommandConnectionID: "command-connection", AuthorityConnectionID: "authority-connection",
		Deadline: "2027-01-02T03:04:05Z",
	}
	return fresh, m, source, holder, time.Date(2027, 1, 2, 3, 4, 4, 0, time.UTC)
}

func nativeShareEpochAssertCleared(t *testing.T, key []byte) {
	t.Helper()
	if len(key) != 32 || !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("owned epoch buffer was not cleared")
	}
}

func TestNativeShareEpochFreshRoundTripAndOneShot(t *testing.T) {
	fresh, metadata, source, holder, now := nativeShareEpochFixture(t)
	other, err := NewFreshNativeShareEpoch()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	if fresh.ID() == "" || fresh.ID() == other.ID() || bytes.Equal(fresh.secret.key, other.secret.key) {
		t.Fatal("constructor did not create distinct fresh epochs")
	}
	original := append([]byte(nil), fresh.secret.key...)
	defer clearNativeShareEpoch(original)
	owned := fresh.secret.key
	copyOfFresh := *fresh
	p, err := SealNativeShareEpoch(&copyOfFresh, metadata, source, now)
	if err != nil {
		t.Fatal(err)
	}
	nativeShareEpochAssertCleared(t, owned)
	if fresh.secret.key != nil {
		t.Fatal("fresh epoch retained consumed buffer")
	}
	for _, consumed := range []*FreshNativeShareEpoch{fresh, &copyOfFresh} {
		if _, err := SealNativeShareEpoch(consumed, metadata, source, now); err == nil {
			t.Fatal("accepted a second seal through a copied fresh epoch")
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pub := source.Public().(ed25519.PublicKey)
	decoded, err := transport.DecodeNativeShareEpochPackage(raw, metadata, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenNativeShareEpoch(decoded, metadata, pub, holder.Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	if opened.EpochID != metadata.EpochID || !bytes.Equal(opened.Key, original) {
		t.Fatal("opened epoch did not match fresh material")
	}
	// Inspect the actual HPKE plaintext, so a serialized keyring or extra keys
	// cannot pass merely because the public open helper extracts one epoch.
	aad, err := metadata.AAD()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := e2ee.HPKEUnwrap(holder.Bytes(), p.Wrapped.Enc, []byte(transport.NativeShareEpochInfo), aad, p.Wrapped.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clearNativeShareEpoch(plain)
	if len(plain) != 32 || !bytes.Equal(plain, original) {
		t.Fatal("HPKE payload was not exactly the fresh 32-byte epoch key")
	}
	openedBuffer := opened.Key
	opened.Destroy()
	nativeShareEpochAssertCleared(t, openedBuffer)
	if opened.Key != nil {
		t.Fatal("destroyed opened key retained its buffer")
	}
}

func TestNativeShareEpochSealFailureConsumesAndClears(t *testing.T) {
	for name, mutate := range map[string]func(*transport.NativeShareEpochMetadata, *ed25519.PrivateKey, *time.Time){
		"wrong epoch": func(m *transport.NativeShareEpochMetadata, _ *ed25519.PrivateKey, _ *time.Time) {
			m.EpochID = m.PreviousEpochID
		},
		"invalid source":   func(_ *transport.NativeShareEpochMetadata, source *ed25519.PrivateKey, _ *time.Time) { *source = nil },
		"invalid metadata": func(m *transport.NativeShareEpochMetadata, _ *ed25519.PrivateKey, _ *time.Time) { m.Version = 2 },
		"zero time":        func(_ *transport.NativeShareEpochMetadata, _ *ed25519.PrivateKey, now *time.Time) { *now = time.Time{} },
		"deadline": func(_ *transport.NativeShareEpochMetadata, _ *ed25519.PrivateKey, now *time.Time) {
			*now = now.Add(time.Second)
		},
		"HPKE failure": func(m *transport.NativeShareEpochMetadata, _ *ed25519.PrivateKey, _ *time.Time) {
			m.HolderX25519 = strings.Repeat("00", 32)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fresh, metadata, source, _, now := nativeShareEpochFixture(t)
			owned := fresh.secret.key
			copyOfFresh := *fresh
			mutate(&metadata, &source, &now)
			if _, err := SealNativeShareEpoch(fresh, metadata, source, now); err == nil {
				t.Fatal("accepted invalid seal")
			}
			nativeShareEpochAssertCleared(t, owned)
			if fresh.secret.key != nil {
				t.Fatal("failed seal retained owned buffer")
			}
			if _, err := SealNativeShareEpoch(&copyOfFresh, metadata, source, now); err == nil {
				t.Fatal("failed seal did not consume copied fresh epoch")
			}
		})
	}
}

func TestNativeShareEpochDestroyAndZeroValues(t *testing.T) {
	fresh, metadata, source, _, now := nativeShareEpochFixture(t)
	owned := fresh.secret.key
	copyOfFresh := *fresh
	fresh.Destroy()
	fresh.Destroy()
	nativeShareEpochAssertCleared(t, owned)
	if _, err := SealNativeShareEpoch(&copyOfFresh, metadata, source, now); err == nil {
		t.Fatal("accepted destroyed fresh epoch copy")
	}
	for _, empty := range []*FreshNativeShareEpoch{nil, {}} {
		if empty.ID() != "" {
			t.Fatal("zero fresh epoch had an ID")
		}
		empty.Destroy()
		if _, err := SealNativeShareEpoch(empty, metadata, source, now); err == nil {
			t.Fatal("accepted zero fresh epoch")
		}
	}
	var key *NativeShareEpochKey
	key.Destroy()
	key = &NativeShareEpochKey{}
	key.Destroy()
}

func TestNativeShareEpochOpenRejectsWrongHolderAndTampering(t *testing.T) {
	fresh, metadata, source, holder, now := nativeShareEpochFixture(t)
	p, err := SealNativeShareEpoch(fresh, metadata, source, now)
	if err != nil {
		t.Fatal(err)
	}
	pub := source.Public().(ed25519.PublicKey)
	wrongHolder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, private := range map[string][]byte{"different holder": wrongHolder.Bytes(), "missing key": nil, "short key": make([]byte, 31)} {
		t.Run(name, func(t *testing.T) {
			if key, err := OpenNativeShareEpoch(p, metadata, pub, private, now); err == nil || key != nil {
				t.Fatal("opened package with wrong holder key")
			}
		})
	}
	for name, mutate := range map[string]func(*transport.NativeShareEpochPackage){
		"ciphertext": func(p *transport.NativeShareEpochPackage) {
			p.Wrapped.Ciphertext = append([]byte(nil), p.Wrapped.Ciphertext...)
			p.Wrapped.Ciphertext[0] ^= 1
		},
		"enc": func(p *transport.NativeShareEpochPackage) {
			p.Wrapped.Enc = append([]byte(nil), p.Wrapped.Enc...)
			p.Wrapped.Enc[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			// Re-sign to reach HPKE authentication after transport verification.
			raw, err := changed.SignatureBytes()
			if err != nil {
				t.Fatal(err)
			}
			changed.Signature = ed25519.Sign(source, raw)
			if key, err := OpenNativeShareEpoch(changed, metadata, pub, holder.Bytes(), now); err == nil || key != nil {
				t.Fatal("opened authenticated package with corrupt HPKE data")
			}
		})
	}
	changed := metadata
	changed.NetworkID = "20000000-0000-4000-8000-000000000001"
	if key, err := OpenNativeShareEpoch(p, changed, pub, holder.Bytes(), now); err == nil || key != nil {
		t.Fatal("opened package under wrong expected context")
	}
	_, wrongSource, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := OpenNativeShareEpoch(p, metadata, wrongSource.Public().(ed25519.PublicKey), holder.Bytes(), now); err == nil || key != nil {
		t.Fatal("opened package under wrong authority")
	}
}
