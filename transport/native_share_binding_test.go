package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

func nativeShareBindingFixture() NativeShareBindingPreparePayload {
	return NativeShareBindingPreparePayload{
		CommandID: "10000000-0000-4000-8000-000000000001",
		Binding: NativeShareBinding{
			Version: 1, BindingID: "10000000-0000-4000-8000-000000000002",
			ProposalID: "10000000-0000-4000-8000-000000000003", GrantID: "10000000-0000-4000-8000-000000000004",
			NetworkID: "10000000-0000-4000-8000-000000000005", ProposalGeneration: 1, GrantGeneration: 2,
			OwningTenantID: "10000000-0000-4000-8000-000000000016", OwnerUserID: "10000000-0000-4000-8000-000000000017",
			PrincipalID: "10000000-0000-4000-8000-000000000006", InstanceID: "10000000-0000-4000-8000-000000000007",
			HostID: "10000000-0000-4000-8000-000000000008", NativeAdmissionID: "10000000-0000-4000-8000-000000000009",
			RunnerID: "10000000-0000-4000-8000-000000000010", RunnerIncarnationID: "10000000-0000-4000-8000-000000000011",
			RunnerGeneration: 3, ProfileFingerprint: strings.Repeat("ab", 32), ContextID: "10000000-0000-4000-8000-000000000012",
			ExpiresAt: "2027-01-02T03:04:05Z",
		},
	}
}

func nativeSharePrepared(t *testing.T) (NativeShareBindingPreparedPayload, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := NativeShareBindingPreparedPayload{Prepare: nativeShareBindingFixture(), HolderID: "10000000-0000-4000-8000-000000000013", HolderX25519: strings.Repeat("cd", 32)}
	p.BindingDigest, err = p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(private, raw)
	return p, pub, private
}

func TestNativeShareBindingDeterministic(t *testing.T) {
	p, pub, _ := nativeSharePrepared(t)
	raw, err := p.Prepare.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	var decoded NativeShareBindingPreparePayload
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	again, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("canonical transcript changed after round trip")
	}
	if err := p.Verify(decoded, pub); err != nil {
		t.Fatal(err)
	}
	digest, _ := p.Digest()
	if digest != p.BindingDigest || !bytes.Contains(raw, []byte(`"grantGeneration":"2"`)) {
		t.Fatal("unstable digest or generation encoding")
	}
	p.Signature[0] ^= 1
	if p.Verify(decoded, pub) == nil {
		t.Fatal("accepted tampered signature")
	}
}

func TestNativeShareBindingEveryFieldRequiredAndBound(t *testing.T) {
	p, pub, _ := nativeSharePrepared(t)
	typ := reflect.TypeOf(p.Prepare.Binding)
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			changed := p
			field := reflect.ValueOf(&changed.Prepare.Binding).Elem().Field(i)
			field.SetZero()
			if _, err := changed.Prepare.CanonicalBytes(); err == nil {
				t.Fatal("accepted omitted binding field")
			}
			changed = p
			field = reflect.ValueOf(&changed.Prepare.Binding).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				switch typ.Field(i).Name {
				case "ProfileFingerprint":
					field.SetString(strings.Repeat("ef", 32))
				case "ExpiresAt":
					field.SetString("2027-01-02T03:04:06Z")
				default:
					field.SetString("20000000-0000-4000-8000-000000000001")
				}
			case reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.Int:
				field.SetInt(2)
			}
			if changed.Verify(p.Prepare, pub) == nil {
				t.Fatal("accepted changed binding")
			}
			if typ.Field(i).Name != "Version" {
				digest, err := changed.Digest()
				if err != nil || digest == p.BindingDigest {
					t.Fatal("valid field change did not change digest", err)
				}
			}
		})
	}
	for _, mutate := range []func(*NativeShareBindingPreparedPayload){
		func(p *NativeShareBindingPreparedPayload) {
			p.Prepare.CommandID = "20000000-0000-4000-8000-000000000001"
		},
		func(p *NativeShareBindingPreparedPayload) { p.HolderID = "20000000-0000-4000-8000-000000000002" },
		func(p *NativeShareBindingPreparedPayload) { p.HolderX25519 = strings.Repeat("ef", 32) },
	} {
		changed := p
		mutate(&changed)
		digest, err := changed.Digest()
		if err != nil || digest == p.BindingDigest || changed.Verify(p.Prepare, pub) == nil {
			t.Fatal("prepare command or holder mutation was not bound", err)
		}
	}
	for _, name := range []string{"CommandID", "HolderID", "HolderX25519", "BindingDigest"} {
		t.Run(name, func(t *testing.T) {
			changed := p
			if name == "CommandID" {
				changed.Prepare.CommandID = ""
			} else {
				reflect.ValueOf(&changed).Elem().FieldByName(name).SetZero()
			}
			if changed.Verify(p.Prepare, pub) == nil {
				t.Fatal("accepted omitted receipt field")
			}
		})
	}
}

func TestNativeShareBindingChallengeAndReplay(t *testing.T) {
	prepared, pub, private := nativeSharePrepared(t)
	holder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prepared.HolderX25519 = hex.EncodeToString(holder.PublicKey().Bytes())
	prepared.BindingDigest, _ = prepared.Digest()
	request := NativeShareBindingProvePayload{Version: 1, CommandID: "10000000-0000-4000-8000-000000000014", BindingDigest: prepared.BindingDigest, ChallengeID: "10000000-0000-4000-8000-000000000015"}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	aad, err := request.ChallengeAAD()
	if err != nil {
		t.Fatal(err)
	}
	request.Challenge.Enc, request.Challenge.Ciphertext, err = e2ee.HPKEWrap(holder.PublicKey().Bytes(), []byte(NativeShareBindingChallengeInfo), aad, challenge)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := e2ee.HPKEUnwrap(holder.Bytes(), request.Challenge.Enc, []byte(NativeShareBindingChallengeInfo), aad, request.Challenge.Ciphertext)
	if err != nil || !bytes.Equal(plain, challenge) {
		t.Fatal("challenge unwrap failed", err)
	}
	reply := NativeShareBindingProvedPayload{Version: 1, CommandID: request.CommandID, BindingDigest: request.BindingDigest, ChallengeID: request.ChallengeID, Challenge: plain}
	raw, err := reply.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	reply.Signature = ed25519.Sign(private, raw)
	if err := reply.Verify(request, challenge, pub); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CommandID", "BindingDigest", "ChallengeID"} {
		t.Run(name, func(t *testing.T) {
			changed := request
			switch name {
			case "CommandID":
				changed.CommandID = domain.ID("20000000-0000-4000-8000-000000000001")
			case "BindingDigest":
				other := prepared
				other.Prepare.Binding.InstanceID = "20000000-0000-4000-8000-000000000002"
				changed.BindingDigest, _ = other.Digest()
			case "ChallengeID":
				changed.ChallengeID = "20000000-0000-4000-8000-000000000003"
			}
			if reply.Verify(changed, challenge, pub) == nil {
				t.Fatal("accepted replay")
			}
			changedAAD, _ := changed.ChallengeAAD()
			if _, err := e2ee.HPKEUnwrap(holder.Bytes(), changed.Challenge.Enc, []byte(NativeShareBindingChallengeInfo), changedAAD, changed.Challenge.Ciphertext); err == nil {
				t.Fatal("accepted challenge under changed AAD")
			}
			reflect.ValueOf(&changed).Elem().FieldByName(name).SetZero()
			if _, err := changed.CanonicalBytes(); err == nil {
				t.Fatal("accepted omitted prove field")
			}
		})
	}
	challenge[0] ^= 1
	if reply.Verify(request, challenge, pub) == nil {
		t.Fatal("accepted wrong decrypted challenge")
	}
	request.Challenge.Ciphertext = nil
	if _, err := request.CanonicalBytes(); err == nil {
		t.Fatal("accepted missing HPKE ciphertext")
	}
}
