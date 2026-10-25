package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
)

type ownerMailboxVector struct {
	Description     string                 `json:"description"`
	Descriptor      OwnerMailboxDescriptor `json:"descriptor"`
	BrowserPrivate  string                 `json:"browserPrivateHex"`
	HostSigningSeed string                 `json:"hostSigningSeedHex"`
	HPKERandomness  string                 `json:"hpkeRandomnessHex"`
	Keys            string                 `json:"directionalKeysHex"`
	B               string                 `json:"BHex"`
	T               string                 `json:"THex"`
	Info            string                 `json:"infoHex"`
	AAD             string                 `json:"AADHex"`
	Enc             string                 `json:"encHex"`
	CT              string                 `json:"ctHex"`
	Signature       string                 `json:"signatureHex"`
	Sequence        uint64                 `json:"frameSequence"`
	Plaintext       string                 `json:"framePlaintextHex"`
	Nonce           string                 `json:"frameNonceHex"`
	C2HAAD          string                 `json:"c2hFrameAADHex"`
	H2CAAD          string                 `json:"h2cFrameAADHex"`
	C2HCT           string                 `json:"c2hFrameCiphertextHex"`
	H2CCT           string                 `json:"h2cFrameCiphertextHex"`
}

func ownerMailboxTestDescriptor(t *testing.T) (OwnerMailboxDescriptor, []byte, ed25519.PrivateKey) {
	t.Helper()
	browserPrivate := bytes.Repeat([]byte{0x11}, 32)
	browser, err := ecdh.X25519().NewPrivateKey(browserPrivate)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32))
	return OwnerMailboxDescriptor{
		TenantID: "00000000-0000-4000-8000-000000000001", OwnerUserID: "00000000-0000-4000-8000-000000000002",
		InstallationID: "00000000-0000-4000-8000-000000000003", ServiceID: "00000000-0000-4000-8000-000000000004",
		HostID: "00000000-0000-4000-8000-000000000005", SessionID: "00000000-0000-4000-8000-000000000006",
		RunnerID: "00000000-0000-4000-8000-000000000007", HostCredentialID: "00000000-0000-4000-8000-000000000008",
		RunnerEpoch: time.Date(2026, 10, 22, 12, 34, 56, 123456000, time.UTC), Generation: 9007199254740993,
		BrowserX25519Pub: browser.PublicKey().Bytes(), HostX25519Pub: host.PublicKey().Bytes(), HostEd25519Pub: signer.Public().(ed25519.PublicKey),
		IssuedAtUnixSeconds: 1792672496, ExpiresAtUnixSeconds: 1792673396,
	}, browserPrivate, signer
}

// Fixed entropy is confined to this synthetic vector generator. Production uses
// HPKEWrap and crypto/rand; these public synthetic keys must never be deployed.
func ownerMailboxSyntheticVector(t *testing.T) ownerMailboxVector {
	t.Helper()
	d, priv, signer := ownerMailboxTestDescriptor(t)
	b, err := EncodeOwnerMailboxDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 64)
	for i := range material {
		material[i] = byte(i)
	}
	randomness := bytes.Repeat([]byte{0x44}, 32)
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(d.BrowserX25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := hpkeSuite.NewSender(pk, []byte(OwnerMailboxHPKEInfo))
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(bytes.NewReader(randomness))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(material, b)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := OwnerMailboxBootstrapTranscript(d, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	const seq = 7
	plaintext := []byte("synthetic owner mailbox frame")
	c2hAAD, _ := OwnerMailboxFrameAAD(d, OwnerMailboxClientToHost, seq)
	h2cAAD, _ := OwnerMailboxFrameAAD(d, OwnerMailboxHostToClient, seq)
	c2h, err := SealOwnerMailboxFrame(d, material[:32], OwnerMailboxClientToHost, seq, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	h2c, err := SealOwnerMailboxFrame(d, material[32:], OwnerMailboxHostToClient, seq, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ownerMailboxVector{
		Description: "Synthetic public test keys only. Binary fields use hex; descriptor public keys use JSON base64.", Descriptor: d,
		BrowserPrivate: hex.EncodeToString(priv), HostSigningSeed: hex.EncodeToString(signer.Seed()), HPKERandomness: hex.EncodeToString(randomness), Keys: hex.EncodeToString(material),
		B: hex.EncodeToString(b), T: hex.EncodeToString(transcript), Info: hex.EncodeToString([]byte(OwnerMailboxHPKEInfo)), AAD: hex.EncodeToString(b),
		Enc: hex.EncodeToString(enc), CT: hex.EncodeToString(ct), Signature: hex.EncodeToString(ed25519.Sign(signer, transcript)),
		Sequence: seq, Plaintext: hex.EncodeToString(plaintext), Nonce: "000000000000000000000007", C2HAAD: hex.EncodeToString(c2hAAD), H2CAAD: hex.EncodeToString(h2cAAD), C2HCT: hex.EncodeToString(c2h), H2CCT: hex.EncodeToString(h2c),
	}
}

func ownerMailboxUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOwnerMailboxVector(t *testing.T) {
	data, err := os.ReadFile("testdata/owner_mailbox_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v ownerMailboxVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(ownerMailboxSyntheticVector(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(data), want) {
		t.Fatal("synthetic vector differs from fixture")
	}
	keys, err := VerifyOwnerMailboxBootstrap(v.Descriptor, OwnerMailboxBootstrap{Enc: ownerMailboxUnhex(t, v.Enc), Ciphertext: ownerMailboxUnhex(t, v.CT), Signature: ownerMailboxUnhex(t, v.Signature)}, ownerMailboxUnhex(t, v.BrowserPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(keys.ClientToHost[:], keys.HostToClient[:]...), ownerMailboxUnhex(t, v.Keys)) {
		t.Fatal("unwrapped keys differ")
	}
	for _, frame := range []struct {
		direction byte
		key       []byte
		ct        string
	}{{0, keys.ClientToHost[:], v.C2HCT}, {1, keys.HostToClient[:], v.H2CCT}} {
		plaintext, err := OpenOwnerMailboxFrame(v.Descriptor, frame.key, frame.direction, v.Sequence, ownerMailboxUnhex(t, frame.ct))
		if err != nil || !bytes.Equal(plaintext, ownerMailboxUnhex(t, v.Plaintext)) {
			t.Fatalf("frame %d: %x %v", frame.direction, plaintext, err)
		}
	}
}

func TestOwnerMailboxBootstrap(t *testing.T) {
	d, priv, signer := ownerMailboxTestDescriptor(t)
	bootstrap, keys, err := CreateOwnerMailboxBootstrap(d, signer)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := VerifyOwnerMailboxBootstrap(d, bootstrap, priv)
	if err != nil || opened != keys {
		t.Fatalf("round trip: %v", err)
	}
	if keys.ClientToHost == keys.HostToClient {
		t.Fatal("directional keys equal")
	}
	another, moreKeys, err := CreateOwnerMailboxBootstrap(d, signer)
	if err != nil || moreKeys == keys || bytes.Equal(another.Enc, bootstrap.Enc) {
		t.Fatal("bootstrap must be fresh", err)
	}
	for name, mutate := range map[string]func(*OwnerMailboxDescriptor){
		"tenant": func(d *OwnerMailboxDescriptor) { d.TenantID = d.SessionID }, "owner": func(d *OwnerMailboxDescriptor) { d.OwnerUserID = d.SessionID },
		"installation": func(d *OwnerMailboxDescriptor) { d.InstallationID = d.SessionID }, "service": func(d *OwnerMailboxDescriptor) { d.ServiceID = d.SessionID },
		"host": func(d *OwnerMailboxDescriptor) { d.HostID = d.SessionID }, "session": func(d *OwnerMailboxDescriptor) { d.SessionID = d.HostID },
		"runner": func(d *OwnerMailboxDescriptor) { d.RunnerID = d.SessionID }, "credential": func(d *OwnerMailboxDescriptor) { d.HostCredentialID = d.SessionID },
		"epoch": func(d *OwnerMailboxDescriptor) { d.RunnerEpoch = d.RunnerEpoch.Add(time.Nanosecond) }, "generation": func(d *OwnerMailboxDescriptor) { d.Generation++ },
		"browser key": func(d *OwnerMailboxDescriptor) { d.BrowserX25519Pub = bytes.Repeat([]byte{5}, 32) },
		"host x key":  func(d *OwnerMailboxDescriptor) { d.HostX25519Pub = bytes.Repeat([]byte{5}, 32) },
		"host ed key": func(d *OwnerMailboxDescriptor) { d.HostEd25519Pub = bytes.Repeat([]byte{5}, 32) },
		"lifetime":    func(d *OwnerMailboxDescriptor) { d.IssuedAtUnixSeconds++; d.ExpiresAtUnixSeconds++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d
			mutate(&changed)
			if _, err := VerifyOwnerMailboxBootstrap(changed, bootstrap, priv); err == nil {
				t.Fatal("accepted changed descriptor")
			}
		})
	}
	for name, field := range map[string][]byte{"signature": bootstrap.Signature, "enc": bootstrap.Enc, "ciphertext": bootstrap.Ciphertext} {
		t.Run(name, func(t *testing.T) {
			field[0] ^= 1
			defer func() { field[0] ^= 1 }()
			if _, err := VerifyOwnerMailboxBootstrap(d, bootstrap, priv); err == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
	if _, err := VerifyOwnerMailboxBootstrap(d, bootstrap, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("accepted wrong browser key")
	}
	if _, _, err := CreateOwnerMailboxBootstrap(d, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))); err == nil {
		t.Fatal("accepted wrong signer")
	}
	if _, _, err := CreateOwnerMailboxBootstrap(d, nil); err == nil {
		t.Fatal("accepted missing signer")
	}
}

func TestOwnerMailboxDescriptorValidation(t *testing.T) {
	d, _, _ := ownerMailboxTestDescriptor(t)
	for name, mutate := range map[string]func(*OwnerMailboxDescriptor){
		"uppercase":       func(d *OwnerMailboxDescriptor) { d.TenantID = "AAAAAAAA-0000-4000-8000-000000000001" },
		"alternate uuid":  func(d *OwnerMailboxDescriptor) { d.TenantID = strings.ReplaceAll(d.TenantID, "-", "") },
		"unicode":         func(d *OwnerMailboxDescriptor) { d.TenantID = "\xff" },
		"zero generation": func(d *OwnerMailboxDescriptor) { d.Generation = 0 }, "large generation": func(d *OwnerMailboxDescriptor) { d.Generation = math.MaxInt64 + 1 },
		"short key": func(d *OwnerMailboxDescriptor) { d.BrowserX25519Pub = make([]byte, 31) }, "long key": func(d *OwnerMailboxDescriptor) { d.HostX25519Pub = make([]byte, 33) },
		"short signing key": func(d *OwnerMailboxDescriptor) { d.HostEd25519Pub = nil }, "zero epoch": func(d *OwnerMailboxDescriptor) { d.RunnerEpoch = time.Time{} },
		"long lifetime": func(d *OwnerMailboxDescriptor) { d.ExpiresAtUnixSeconds++ }, "overflow": func(d *OwnerMailboxDescriptor) {
			d.IssuedAtUnixSeconds = math.MaxUint64 - 899
			d.ExpiresAtUnixSeconds = 0
		},
		"browser unsafe": func(d *OwnerMailboxDescriptor) {
			d.IssuedAtUnixSeconds = 1 << 53
			d.ExpiresAtUnixSeconds = d.IssuedAtUnixSeconds + 900
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			mutate(&bad)
			if _, err := EncodeOwnerMailboxDescriptor(bad); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
	b, _ := EncodeOwnerMailboxDescriptor(d)
	if !bytes.Contains(b, []byte("2026-10-22T12:34:56.123456000Z")) {
		t.Fatal("epoch lost precision")
	}
	d.RunnerEpoch = d.RunnerEpoch.In(time.FixedZone("offset", 3600))
	normalized, err := EncodeOwnerMailboxDescriptor(d)
	if err != nil || !bytes.Equal(b, normalized) {
		t.Fatal("UTC normalization differs", err)
	}
}

func TestOwnerMailboxFrames(t *testing.T) {
	d, _, _ := ownerMailboxTestDescriptor(t)
	key := bytes.Repeat([]byte{7}, 32)
	for _, seq := range []uint64{0, 1, OwnerMailboxSequenceLimit - 1} {
		for _, size := range []int{0, OwnerMailboxMaxPlaintext} {
			plaintext := make([]byte, size)
			ct, err := SealOwnerMailboxFrame(d, key, 0, seq, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			got, err := OpenOwnerMailboxFrame(d, key, 0, seq, ct)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatal("frame round trip", err)
			}
		}
	}
	ct, err := SealOwnerMailboxFrame(d, key, 0, 7, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		name      string
		key       []byte
		direction byte
		seq       uint64
		ct        []byte
	}{
		{"direction", key, 1, 7, ct}, {"sequence", key, 0, 8, ct}, {"key", bytes.Repeat([]byte{8}, 32), 0, 7, ct},
		{"invalid direction", key, 2, 7, ct}, {"limit", key, 0, OwnerMailboxSequenceLimit, ct}, {"overflow", key, 0, math.MaxUint64, ct},
		{"short key", key[:31], 0, 7, ct}, {"short ct", key, 0, 7, ct[:15]}, {"large ct", key, 0, 7, make([]byte, OwnerMailboxMaxPlaintext+17)},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := OpenOwnerMailboxFrame(d, bad.key, bad.direction, bad.seq, bad.ct); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	ct[0] ^= 1
	if _, err := OpenOwnerMailboxFrame(d, key, 0, 7, ct); err == nil {
		t.Fatal("accepted ciphertext tampering")
	}
	for _, seq := range []uint64{OwnerMailboxSequenceLimit, math.MaxUint64} {
		if _, err := SealOwnerMailboxFrame(d, key, 0, seq, nil); err == nil {
			t.Fatal("accepted sequence outside bound")
		}
	}
	if _, err := SealOwnerMailboxFrame(d, key, 0, 0, make([]byte, OwnerMailboxMaxPlaintext+1)); err == nil {
		t.Fatal("accepted oversized plaintext")
	}
	if _, err := SealOwnerMailboxFrame(d, key, 2, 0, nil); err == nil {
		t.Fatal("accepted invalid direction")
	}
	if _, err := SealOwnerMailboxFrame(d, key[:31], 0, 0, nil); err == nil {
		t.Fatal("accepted short key")
	}
	_, nonce, err := ownerMailboxFrameCipher(key, OwnerMailboxSequenceLimit-1)
	if err != nil || hex.EncodeToString(nonce) != "0000000000000000000fffff" {
		t.Fatal("nonce encoding", err)
	}
}

func TestOwnerMailboxGenerationJSON(t *testing.T) {
	d, _, _ := ownerMailboxTestDescriptor(t)
	for _, generation := range []uint64{1, 9007199254740993, math.MaxInt64} {
		d.Generation = generation
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		canonical := strconv.FormatUint(generation, 10)
		if !bytes.Contains(data, []byte(`"generation":"`+canonical+`"`)) {
			t.Fatal("generation must be a decimal JSON string")
		}
		var decoded OwnerMailboxDescriptor
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		before, err := EncodeOwnerMailboxDescriptor(d)
		if err != nil {
			t.Fatal(err)
		}
		after, err := EncodeOwnerMailboxDescriptor(decoded)
		if err != nil || decoded.Generation != generation || !bytes.Equal(before, after) {
			t.Fatal("generation round trip changed descriptor", err)
		}
	}
	for _, value := range []string{`1`, `9007199254740993`, `null`, `""`, `"0"`, `"01"`, `"+1"`, `"-1"`, `"1.0"`, `"1e1"`, `" 1"`, `"9223372036854775808"`, `"18446744073709551616"`} {
		t.Run(value, func(t *testing.T) {
			var decoded OwnerMailboxDescriptor
			if err := json.Unmarshal([]byte(`{"generation":`+value+`}`), &decoded); err == nil {
				t.Fatal("accepted noncanonical generation")
			}
		})
	}
	var decoded OwnerMailboxDescriptor
	if err := json.Unmarshal([]byte(`{}`), &decoded); err == nil {
		t.Fatal("accepted missing generation")
	}
}
