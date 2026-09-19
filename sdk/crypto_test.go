package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestAADCanonicalMatchesCommittedVector(t *testing.T) {
	// The SDK builds AADs with ProtocolVersion = transport.ProtocolVersion
	// (2). The committed e2ee vectors use the v1 AAD; verify the canonical
	// serialization is stable by round-tripping the vector's AAD.
	v := e2ee.VectorsV1[0]
	got := v.AAD.CanonicalBytes()
	if string(got) != v.AADCanonical {
		t.Fatalf("AAD.CanonicalBytes() = %s, want committed %s", got, v.AADCanonical)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	var epochKey [32]byte
	for i := range epochKey {
		epochKey[i] = byte(i)
	}
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        "tenant-1",
		NetworkID:       "net-1",
		ObjectType:      e2ee.ObjectTypeMessage,
		ObjectID:        "obj-1",
		Sender:          "sender-1",
		Recipient:       "recipient-1",
		CreatedAt:       "2026-09-19T00:00:00Z",
		KeyEpochID:      "epoch-1",
	}
	plaintext := []byte("round trip secret")
	env, err := e2ee.Encrypt(plaintext, epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e2ee.Decrypt(env, epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("decrypt = %q, want %q", out, plaintext)
	}
	// The ciphertext must not contain the plaintext (zero-knowledge).
	envJSON, _ := json.Marshal(env)
	if bytes.Contains(envJSON, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}
}

func TestDecryptFailsOnAADTamper(t *testing.T) {
	var epochKey [32]byte
	aad := e2ee.AAD{
		ProtocolVersion: transport.ProtocolVersion,
		TenantID:        "tenant-1",
		NetworkID:       "net-1",
		ObjectType:      e2ee.ObjectTypeMessage,
		ObjectID:        "obj-1",
		Sender:          "sender-1",
		Recipient:       "recipient-1",
		CreatedAt:       "2026-09-19T00:00:00Z",
		KeyEpochID:      "epoch-1",
	}
	env, err := e2ee.Encrypt([]byte("secret"), epochKey, aad)
	if err != nil {
		t.Fatal(err)
	}
	tampered := aad
	tampered.Recipient = "attacker"
	if _, err := e2ee.Decrypt(env, epochKey, tampered); err == nil {
		t.Fatal("decrypt with a tampered AAD must fail (GCM authentication)")
	}
}

func TestChallengeMACMatchesHMACConstruction(t *testing.T) {
	plaintext := []byte("challenge-plaintext")
	nonce := []byte("nonce-nonce-nonce1")
	got := challengeMAC(plaintext, nonce)
	mac := hmac.New(sha256.New, plaintext)
	mac.Write(nonce)
	mac.Write([]byte(proofContext))
	want := mac.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("challengeMAC = %x, want HMAC-SHA256(plaintext, nonce||proofContext) = %x", got, want)
	}
}

func TestHPKEWrapUnwrapRoundTrip(t *testing.T) {
	pub, priv, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := pub.MarshalBinary()
	privBytes, _ := priv.MarshalBinary()
	secret := bytes.Repeat([]byte{0xAB}, 32)
	enc, ct, err := e2ee.HPKEWrap(pubBytes, []byte(enrollmentInfo), nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e2ee.HPKEUnwrap(privBytes, enc, []byte(enrollmentInfo), nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, secret) {
		t.Fatal("HPKE unwrap did not recover the secret")
	}
	// A different recipient key cannot unwrap.
	otherPub, otherPriv, _ := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	otherPrivBytes, _ := otherPriv.MarshalBinary()
	_ = otherPub
	if _, err := e2ee.HPKEUnwrap(otherPrivBytes, enc, []byte(enrollmentInfo), nil, ct); err == nil {
		t.Fatal("a different recipient key must not unwrap the wrap")
	}
}

func TestNewObjectIDIsUUIDv7(t *testing.T) {
	id := newObjectID()
	u, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("newObjectID() %q is not a UUID: %v", id, err)
	}
	if u.Version() != 7 {
		t.Fatalf("newObjectID() version = %d, want 7", u.Version())
	}
}

func TestUUIDV7TimeExtraction(t *testing.T) {
	before := time.Now()
	id := newObjectID()
	after := time.Now()
	ts, ok := uuidV7Time(id)
	if !ok {
		t.Fatalf("uuidV7Time(%q) not recognized as UUIDv7", id)
	}
	if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
		t.Fatalf("uuidV7Time = %v, want within [%v, %v]", ts, before, after)
	}
	// A non-v7 UUID is not recognized.
	if _, ok := uuidV7Time(uuid.NewString()); ok {
		t.Fatal("uuidV7Time should reject a non-v7 UUID")
	}
	// A garbage string is not recognized.
	if _, ok := uuidV7Time("not-a-uuid"); ok {
		t.Fatal("uuidV7Time should reject a non-UUID string")
	}
}
