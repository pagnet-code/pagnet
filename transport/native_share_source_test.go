package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
)

func nativeShareSourceFixture() NativeShareSourceChallengeContext {
	return NativeShareSourceChallengeContext{Version: 1, EnrollmentID: "10000000-0000-4000-8000-000000000001", CommandID: "10000000-0000-4000-8000-000000000002", EnrollmentDigest: strings.Repeat("ab", 32), DescriptorFingerprint: strings.Repeat("cd", 32), ChallengeID: "10000000-0000-4000-8000-000000000003", ExpiresAt: "2027-01-02T03:04:05Z"}
}

func TestNativeShareSourceVectors(t *testing.T) {
	c := nativeShareSourceFixture()
	aad, err := c.ChallengeAAD()
	if err != nil {
		t.Fatal(err)
	}
	want := `pagnet/native-share-source/challenge-aad/v1/{"version":1,"enrollmentId":"10000000-0000-4000-8000-000000000001","commandId":"10000000-0000-4000-8000-000000000002","enrollmentDigest":"` + strings.Repeat("ab", 32) + `","descriptorFingerprint":"` + strings.Repeat("cd", 32) + `","challengeId":"10000000-0000-4000-8000-000000000003","expiresAt":"2027-01-02T03:04:05Z"}`
	if string(aad) != want {
		t.Fatalf("AAD mismatch: %s", aad)
	}
	hash := sha256.Sum256(aad)
	if hex.EncodeToString(hash[:]) != "0026fa421980680e55d375d43db3f8899624f5d45a9e77be09af023b70eaee39" {
		t.Fatal("AAD vector mismatch")
	}
	p := NativeShareSourceProvedPayload{NativeShareSourceChallengeContext: c, Challenge: bytes.Repeat([]byte{1}, 32)}
	signed, err := p.SignatureBytes()
	if err != nil || bytes.Contains(signed, []byte("signature")) {
		t.Fatal("unsigned proof contains signature", err)
	}
	challengeHash, err := p.ChallengeHash()
	expected := sha256.Sum256(append(append([]byte("pagnet/native-share-source/challenge-hash/v1/"), aad...), p.Challenge...))
	if err != nil || challengeHash != hex.EncodeToString(expected[:]) {
		t.Fatal("challenge hash mismatch", err)
	}
	if challengeHash != "62624de5a75dff9ab3738104325a590cb7a3b645e57ce0029ff64580e0964e02" {
		t.Fatal("challenge hash vector mismatch")
	}
}

func TestNativeShareSourceChallengeProof(t *testing.T) {
	c := nativeShareSourceFixture()
	request := NativeShareSourceProvePayload{NativeShareSourceChallengeContext: c}
	holder, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aad, _ := request.ChallengeAAD()
	challenge := bytes.Repeat([]byte{1}, 32)
	request.Challenge.Enc, request.Challenge.Ciphertext, err = e2ee.HPKEWrap(holder.PublicKey().Bytes(), []byte(NativeShareSourceChallengeInfo), aad, challenge)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := e2ee.HPKEUnwrap(holder.Bytes(), request.Challenge.Enc, []byte(NativeShareSourceChallengeInfo), aad, request.Challenge.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	reply := NativeShareSourceProvedPayload{NativeShareSourceChallengeContext: c, Challenge: plain}
	signed, _ := reply.SignatureBytes()
	reply.Signature = ed25519.Sign(private, signed)
	hash, _ := reply.ChallengeHash()
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	if err := reply.Verify(request, hash, c.DescriptorFingerprint, pub, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := reply.CanonicalBytes()
	receipt, _ := reply.ReceiptDigest()
	expected := sha256.Sum256(append([]byte("pagnet/native-share-source/proof-receipt/v1/"), raw...))
	if receipt != hex.EncodeToString(expected[:]) {
		t.Fatal("receipt digest mismatch")
	}
	if reply.Verify(request, strings.Repeat("00", 32), c.DescriptorFingerprint, pub, now) == nil {
		t.Fatal("accepted wrong retained hash")
	}
	if reply.Verify(request, hash, strings.Repeat("ef", 32), pub, now) == nil {
		t.Fatal("accepted wrong retained descriptor fingerprint")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	for _, when := range []time.Time{{}, expiresAt, expiresAt.Add(time.Nanosecond)} {
		if reply.Verify(request, hash, c.DescriptorFingerprint, pub, when) == nil {
			t.Fatal("accepted expired proof or zero trusted time")
		}
	}
	typ := reflect.TypeOf(c)
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			changed := request
			f := reflect.ValueOf(&changed.NativeShareSourceChallengeContext).Elem().Field(i)
			f.SetZero()
			if _, err := changed.CanonicalBytes(); err == nil {
				t.Fatal("accepted omitted field")
			}
			changed = request
			f = reflect.ValueOf(&changed.NativeShareSourceChallengeContext).Elem().Field(i)
			switch typ.Field(i).Name {
			case "Version":
				f.SetInt(2)
			case "ExpiresAt":
				f.SetString("2027-01-02T03:04:06Z")
			case "EnrollmentDigest", "DescriptorFingerprint":
				f.SetString(strings.Repeat("ef", 32))
			default:
				f.SetString("20000000-0000-4000-8000-000000000001")
			}
			if reply.Verify(changed, hash, c.DescriptorFingerprint, pub, now) == nil {
				t.Fatal("accepted substituted context")
			}
			changedAAD, err := changed.ChallengeAAD()
			if err == nil {
				if _, err := e2ee.HPKEUnwrap(holder.Bytes(), changed.Challenge.Enc, []byte(NativeShareSourceChallengeInfo), changedAAD, changed.Challenge.Ciphertext); err == nil {
					t.Fatal("accepted changed AAD")
				}
			}
		})
	}
	reply.Signature[0] ^= 1
	if reply.Verify(request, hash, c.DescriptorFingerprint, pub, now) == nil {
		t.Fatal("accepted bad signature")
	}
}

func TestNativeShareSourceStrictDecode(t *testing.T) {
	request := NativeShareSourceProvePayload{NativeShareSourceChallengeContext: nativeShareSourceFixture(), Challenge: CryptoHPKEWrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 48)}}
	raw, _ := request.CanonicalBytes()
	if _, err := DecodeNativeShareSourceProvePayload(raw); err != nil {
		t.Fatal(err)
	}
	proved := NativeShareSourceProvedPayload{NativeShareSourceChallengeContext: request.NativeShareSourceChallengeContext, Challenge: make([]byte, 32), Signature: make([]byte, 64)}
	reply, _ := proved.CanonicalBytes()
	if _, err := DecodeNativeShareSourceProvedPayload(reply); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{raw, reply} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for name, value := range fields {
			for _, replacement := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage(`{}`)} {
				delete(fields, name)
				if replacement != nil {
					fields[name] = replacement
				}
				bad, _ := json.Marshal(fields)
				if _, proved := fields["signature"]; proved || bytes.Equal(raw, reply) {
					if _, err := DecodeNativeShareSourceProvedPayload(bad); err == nil {
						t.Fatal("accepted malformed proved field", name)
					}
				} else if _, err := DecodeNativeShareSourceProvePayload(bad); err == nil {
					t.Fatal("accepted malformed prove field", name)
				}
			}
			fields[name] = value
		}
	}
	for _, bad := range []string{
		string(reply) + `{}`, string(reply[:len(reply)-1]) + `,"signature":""}`,
		strings.Replace(string(reply), `"signature":`, `"Signature":`, 1),
		strings.Replace(string(reply), `"challenge":"`, `"challenge":"\n`, 1),
		string(reply) + strings.Repeat(" ", 4096),
	} {
		if _, err := DecodeNativeShareSourceProvedPayload([]byte(bad)); err == nil {
			t.Fatal("accepted malformed proved payload")
		}
	}
	for _, bad := range []string{
		string(raw) + `{}`, `null`, `[]`, string(raw[:len(raw)-1]) + `,"version":1}`, strings.Replace(string(raw), `"version"`, `"Version"`, 1), strings.Replace(string(raw), `"version":1`, `"version":null`, 1), strings.Replace(string(raw), `"version":1`, `"version":"1"`, 1), strings.Replace(string(raw), `"version":1`, `"unknown":1`, 1), strings.Replace(string(raw), `"enc":`, `"Enc":`, 1), strings.Replace(string(raw), `"enc":`, `"enc":null,"enc":`, 1), strings.Replace(string(raw), `2027-01-02T03:04:05Z`, `2027-01-02T03:04:05+00:00`, 1), strings.Replace(string(raw), strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1), string(raw) + strings.Repeat(" ", 4096),
	} {
		if _, err := DecodeNativeShareSourceProvePayload([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed payload %s", bad)
		}
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	for field := range fields {
		mutated := make(map[string]json.RawMessage)
		for key, value := range fields {
			mutated[key] = value
		}
		delete(mutated, field)
		bad, _ := json.Marshal(mutated)
		if _, err := DecodeNativeShareSourceProvePayload(bad); err == nil {
			t.Fatal("accepted omitted field", field)
		}
	}
	for _, n := range []int{0, 31, 33} {
		request.Challenge.Enc = make([]byte, n)
		if _, err := request.CanonicalBytes(); err == nil {
			t.Fatal("accepted enc length", n)
		}
	}
	request.Challenge.Enc = make([]byte, 32)
	for _, n := range []int{0, 47, 49} {
		request.Challenge.Ciphertext = make([]byte, n)
		if _, err := request.CanonicalBytes(); err == nil {
			t.Fatal("accepted ciphertext length", n)
		}
	}
}
