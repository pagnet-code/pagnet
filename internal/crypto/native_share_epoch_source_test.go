package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func nativeShareEpochSourceFixture(t *testing.T) (transport.NativeShareEpochSourceContext, *ecdh.PrivateKey) {
	t.Helper()
	holder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return transport.NativeShareEpochSourceContext{
		Subject: transport.NativeShareBindingSubject{
			ServerURL: "https://source.example", TenantID: "20000000-0000-4000-8000-000000000009",
			AccountID: "20000000-0000-4000-8000-000000000001", HostID: "20000000-0000-4000-8000-000000000002",
			NativeAdmissionID: "20000000-0000-4000-8000-000000000003", RunnerID: "20000000-0000-4000-8000-000000000004",
			RunnerEpoch: "2027-01-02T03:00:00Z", BootID: "source-boot", ProfileFingerprint: strings.Repeat("ab", 32),
		},
		ConnectedAt: "2027-01-02T03:00:00Z", HostCredentialID: "source-credential", OwnershipScope: "source-scope",
		ConnectionID: "source-connection", AuthorityConnectionID: "source-authority",
		HolderID: "20000000-0000-4000-8000-000000000005", HolderX25519: hex.EncodeToString(holder.PublicKey().Bytes()),
		ProposalID: "20000000-0000-4000-8000-000000000006", GrantID: "20000000-0000-4000-8000-000000000007", BindingID: "20000000-0000-4000-8000-000000000008",
	}, holder
}

func TestNativeShareEpochSourceDualRoundTrip(t *testing.T) {
	fresh, recipient, signer, holder, now := nativeShareEpochFixture(t)
	context, sourceHolder := nativeShareEpochSourceFixture(t)
	context.SigningKey = hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	if context.Subject.TenantID == recipient.TenantID {
		t.Fatal("fixture must exercise cross-tenant source delivery")
	}
	owned := fresh.secret.key
	original := append([]byte(nil), owned...)
	defer clearNativeShareEpoch(original)
	copyOfFresh := *fresh
	selected, source, err := SealNativeShareEpochWithSource(fresh, recipient, context, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	nativeShareEpochAssertCleared(t, owned)
	if fresh.secret.key != nil {
		t.Fatal("retained fresh key")
	}
	if _, err := fresh.PossessionVerifier(recipient.NetworkID); err == nil {
		t.Fatal("retained verifier access")
	}
	if _, _, err := SealNativeShareEpochWithSource(&copyOfFresh, recipient, context, signer, now); err == nil {
		t.Fatal("resealed consumed epoch")
	}
	if _, err := SealNativeShareEpoch(&copyOfFresh, recipient, signer, now); err == nil {
		t.Fatal("old API resealed consumed epoch")
	}
	pub := signer.Public().(ed25519.PublicKey)
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := transport.DecodeNativeShareEpochSourceEnvelope(raw, source.Metadata, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	selectedKey, err := OpenNativeShareEpoch(selected, recipient, pub, holder.Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer selectedKey.Destroy()
	sourceKey, err := OpenNativeShareEpochSource(decoded, source.Metadata, pub, sourceHolder.Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceKey.Destroy()
	if sourceKey.EpochID != recipient.EpochID || !bytes.Equal(sourceKey.Key, original) || !bytes.Equal(sourceKey.Key, selectedKey.Key) {
		t.Fatal("dual envelopes differ from single fresh epoch")
	}
	digest, err := transport.NativeShareEpochPackageDigest(selected)
	if err != nil || digest != source.Metadata.RecipientPackageDigest {
		t.Fatal("wrong selected package digest", err)
	}
	verifier, err := nativeShareEpochPossessionVerifier(sourceKey.Key, recipient.NetworkID, recipient.EpochID)
	if err != nil || hex.EncodeToString(verifier) != recipient.EpochPossessionVerifier {
		t.Fatal("source verifier differs", err)
	}
	// Inspect both actual plaintexts: neither can carry a keyring or history.
	recipientAAD, _ := recipient.AAD()
	sourceAAD, _ := source.Metadata.AAD()
	for _, envelope := range []struct{ holder, enc, ct, info, aad []byte }{
		{holder.Bytes(), selected.Wrapped.Enc, selected.Wrapped.Ciphertext, []byte(transport.NativeShareEpochInfo), recipientAAD},
		{sourceHolder.Bytes(), source.Wrapped.Enc, source.Wrapped.Ciphertext, []byte(transport.NativeShareEpochSourceInfo), sourceAAD},
	} {
		plaintext, err := e2ee.HPKEUnwrap(envelope.holder, envelope.enc, envelope.info, envelope.aad, envelope.ct)
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) != 32 || !bytes.Equal(plaintext, original) {
			t.Fatal("payload contains more than one fresh key")
		}
		clearNativeShareEpoch(plaintext)
	}
	wrongHolder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{holder.Bytes(), wrongHolder.Bytes(), nil} {
		if key, err := OpenNativeShareEpochSource(source, source.Metadata, pub, private, now); err == nil || key != nil {
			t.Fatal("wrong holder opened source envelope")
		}
	}
	if key, err := OpenNativeShareEpoch(selected, recipient, pub, sourceHolder.Bytes(), now); err == nil || key != nil {
		t.Fatal("source holder opened selected package")
	}
	if _, err := e2ee.HPKEUnwrap(sourceHolder.Bytes(), source.Wrapped.Enc, []byte(transport.NativeShareEpochInfo), sourceAAD, source.Wrapped.Ciphertext); err == nil {
		t.Fatal("source envelope accepted recipient HPKE domain")
	}
	substitution := source.Metadata
	substitution.Recipient.HolderX25519 = hex.EncodeToString(wrongHolder.PublicKey().Bytes())
	if key, err := OpenNativeShareEpochSource(source, substitution, pub, sourceHolder.Bytes(), now); err == nil || key != nil {
		t.Fatal("accepted recipient substitution")
	}
	buffer := sourceKey.Key
	sourceKey.Destroy()
	nativeShareEpochAssertCleared(t, buffer)
}

func TestNativeShareEpochSourceSealFailureConsumes(t *testing.T) {
	type mutate func(*transport.NativeShareEpochMetadata, *transport.NativeShareEpochSourceContext, *ed25519.PrivateKey, *time.Time)
	for name, change := range map[string]mutate{
		"source context": func(_ *transport.NativeShareEpochMetadata, s *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			s.Subject.BootID = ""
		},
		"signing pin": func(_ *transport.NativeShareEpochMetadata, s *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			s.SigningKey = strings.Repeat("ab", 32)
		},
		"bad private key": func(_ *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, k *ed25519.PrivateKey, _ *time.Time) {
			*k = nil
		},
		"inconsistent private key": func(_ *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, k *ed25519.PrivateKey, _ *time.Time) {
			(*k)[63] ^= 1
		},
		"recipient metadata": func(m *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			m.Version = 2
		},
		"wrong epoch": func(m *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			m.EpochID = m.PreviousEpochID
		},
		"wrong verifier": func(m *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			m.EpochPossessionVerifier = strings.Repeat("ab", 32)
		},
		"zero time": func(_ *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, n *time.Time) {
			*n = time.Time{}
		},
		"expired": func(_ *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, n *time.Time) {
			*n = n.Add(time.Second)
		},
		"recipient HPKE failure": func(m *transport.NativeShareEpochMetadata, _ *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			m.HolderX25519 = strings.Repeat("00", 32)
		},
		"source HPKE failure after recipient seal": func(_ *transport.NativeShareEpochMetadata, s *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			s.HolderX25519 = strings.Repeat("00", 32)
		},
		"same holder key": func(m *transport.NativeShareEpochMetadata, s *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			s.HolderX25519 = m.HolderX25519
		},
		"same holder id": func(m *transport.NativeShareEpochMetadata, s *transport.NativeShareEpochSourceContext, _ *ed25519.PrivateKey, _ *time.Time) {
			s.HolderID = m.HolderID
		},
	} {
		t.Run(name, func(t *testing.T) {
			fresh, recipient, signer, _, now := nativeShareEpochFixture(t)
			context, _ := nativeShareEpochSourceFixture(t)
			context.SigningKey = hex.EncodeToString(signer.Public().(ed25519.PublicKey))
			owned := fresh.secret.key
			copyOfFresh := *fresh
			change(&recipient, &context, &signer, &now)
			p, s, err := SealNativeShareEpochWithSource(fresh, recipient, context, signer, now)
			if err == nil || !reflect.DeepEqual(p, transport.NativeShareEpochPackage{}) || !reflect.DeepEqual(s, transport.NativeShareEpochSourceEnvelope{}) {
				t.Fatal("failure returned an envelope", err)
			}
			nativeShareEpochAssertCleared(t, owned)
			if fresh.secret.key != nil {
				t.Fatal("failed seal retained key")
			}
			if _, err := fresh.PossessionVerifier(recipient.NetworkID); err == nil {
				t.Fatal("failed seal retained verifier")
			}
			if _, _, err := SealNativeShareEpochWithSource(&copyOfFresh, recipient, context, signer, now); err == nil {
				t.Fatal("failed seal did not consume copy")
			}
		})
	}
}

func TestNativeShareEpochSourceConcurrentConsumption(t *testing.T) {
	fresh, recipient, signer, _, now := nativeShareEpochFixture(t)
	context, _ := nativeShareEpochSourceFixture(t)
	context.SigningKey = hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	owned := fresh.secret.key
	var wg sync.WaitGroup
	successes := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _, err := SealNativeShareEpochWithSource(fresh, recipient, context, signer, now)
				successes <- err == nil
			} else {
				_, err := SealNativeShareEpoch(fresh, recipient, signer, now)
				successes <- err == nil
			}
		}(i)
	}
	wg.Wait()
	close(successes)
	count := 0
	for success := range successes {
		if success {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("got %d successful seals", count)
	}
	nativeShareEpochAssertCleared(t, owned)
}

func TestNativeShareEpochSourceZeroFresh(t *testing.T) {
	for _, fresh := range []*FreshNativeShareEpoch{nil, {}} {
		p, s, err := SealNativeShareEpochWithSource(fresh, transport.NativeShareEpochMetadata{}, transport.NativeShareEpochSourceContext{}, nil, time.Time{})
		if err == nil || !reflect.DeepEqual(p, transport.NativeShareEpochPackage{}) || !reflect.DeepEqual(s, transport.NativeShareEpochSourceEnvelope{}) {
			t.Fatal("zero fresh accepted")
		}
	}
}

func TestNativeShareEpochSourceAuthenticatedWrongVerifier(t *testing.T) {
	fresh, recipient, signer, _, now := nativeShareEpochFixture(t)
	context, holder := nativeShareEpochSourceFixture(t)
	context.SigningKey = hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	p, source, err := SealNativeShareEpochWithSource(fresh, recipient, context, signer, now)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().(ed25519.PublicKey)
	opened, err := OpenNativeShareEpochSource(source, source.Metadata, pub, holder.Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	source.Metadata.Recipient.EpochPossessionVerifier = strings.Repeat("ab", 32)
	// Authenticate a deliberately inconsistent verifier. Open must derive it again.
	aad, _ := source.Metadata.AAD()
	source.Wrapped.Enc, source.Wrapped.Ciphertext, err = e2ee.HPKEWrap(holder.PublicKey().Bytes(), []byte(transport.NativeShareEpochSourceInfo), aad, opened.Key)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := source.SignatureBytes()
	source.Signature = ed25519.Sign(signer, signed)
	if err := source.Verify(source.Metadata, pub, now); err != nil {
		t.Fatal(err)
	}
	if key, err := OpenNativeShareEpochSource(source, source.Metadata, pub, holder.Bytes(), now); err == nil || key != nil {
		t.Fatal("accepted authenticated wrong verifier")
	}
	// The selected package has only its original, independent recipient context.
	if p.Metadata != recipient {
		t.Fatal("source metadata changed selected package")
	}
}
