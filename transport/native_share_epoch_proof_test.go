package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nativeShareEpochProofFixture(t *testing.T) (NativeShareEpochProof, ed25519.PublicKey, ed25519.PublicKey, time.Time) {
	t.Helper()
	pkg, epochKey, epochPrivate, now := nativeShareEpochFixture(t)
	hostKey, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := NativeShareEpochProofChallenge{Version: 1, BindingID: "20000000-0000-4000-8000-000000000001", StageDigest: strings.Repeat("ef", 32), Metadata: pkg.Metadata, CommandID: "20000000-0000-4000-8000-000000000002", ChallengeID: "20000000-0000-4000-8000-000000000003", Nonce: make([]byte, 32), ExpiresAt: pkg.Metadata.Deadline}
	challenge, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	p := NativeShareEpochProof{Challenge: c, EpochSignature: ed25519.Sign(epochPrivate, challenge)}
	host, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.HostSignature = ed25519.Sign(hostPrivate, host)
	return p, epochKey, hostKey, now
}

func TestNativeShareEpochProofRoundTrip(t *testing.T) {
	p, epochKey, hostKey, now := nativeShareEpochProofFixture(t)
	if err := p.Verify(p.Challenge, epochKey, hostKey, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	got, err := DecodeNativeShareEpochProof(raw)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("proof round trip failed", err)
	}
	raw, _ = json.Marshal(p.Challenge)
	challenge, err := DecodeNativeShareEpochProofChallenge(raw)
	if err != nil || !reflect.DeepEqual(challenge, p.Challenge) {
		t.Fatal("challenge round trip failed", err)
	}
	canonical, _ := challenge.CanonicalBytes()
	host, _ := p.SignatureBytes()
	if !bytes.HasPrefix(canonical, []byte("pagnet/native-share-epoch/proof-challenge/v1/")) || !bytes.HasPrefix(host, []byte("pagnet/native-share-epoch/proof-host/v1/")) {
		t.Fatal("missing domain separation")
	}
}

func TestNativeShareEpochProofTampering(t *testing.T) {
	p, epochKey, hostKey, now := nativeShareEpochProofFixture(t)
	for name, mutate := range map[string]func(*NativeShareEpochProof){
		"epoch signature":         func(p *NativeShareEpochProof) { p.EpochSignature = bytes.Repeat([]byte{1}, 64) },
		"host signature":          func(p *NativeShareEpochProof) { p.HostSignature = bytes.Repeat([]byte{1}, 64) },
		"nonce":                   func(p *NativeShareEpochProof) { p.Challenge.Nonce = bytes.Repeat([]byte{1}, 32) },
		"stage digest":            func(p *NativeShareEpochProof) { p.Challenge.StageDigest = strings.Repeat("ab", 32) },
		"metadata":                func(p *NativeShareEpochProof) { p.Challenge.Metadata.GrantGeneration++ },
		"missing epoch signature": func(p *NativeShareEpochProof) { p.EpochSignature = nil },
		"missing host signature":  func(p *NativeShareEpochProof) { p.HostSignature = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if changed.Verify(changed.Challenge, epochKey, hostKey, now) == nil {
				t.Fatal("accepted tampered proof")
			}
			original, _ := p.Challenge.CanonicalBytes()
			modified, _ := changed.Challenge.CanonicalBytes()
			if !bytes.Equal(original, modified) && p.Verify(changed.Challenge, epochKey, hostKey, now) == nil {
				t.Fatal("accepted mismatched expected challenge")
			}
		})
	}
	if p.Verify(p.Challenge, nil, hostKey, now) == nil || p.Verify(p.Challenge, epochKey, nil, now) == nil || p.Verify(p.Challenge, hostKey, epochKey, now) == nil {
		t.Fatal("accepted invalid keys")
	}
}

func TestNativeShareEpochProofChallengeValidation(t *testing.T) {
	p, _, _, now := nativeShareEpochProofFixture(t)
	for name, mutate := range map[string]func(*NativeShareEpochProofChallenge){
		"version":              func(c *NativeShareEpochProofChallenge) { c.Version = 2 },
		"binding":              func(c *NativeShareEpochProofChallenge) { c.BindingID = "invalid" },
		"command":              func(c *NativeShareEpochProofChallenge) { c.CommandID = c.Metadata.CommandID },
		"challenge":            func(c *NativeShareEpochProofChallenge) { c.ChallengeID = "00000000-0000-0000-0000-000000000000" },
		"digest":               func(c *NativeShareEpochProofChallenge) { c.StageDigest = strings.Repeat("AB", 32) },
		"nonce":                func(c *NativeShareEpochProofChallenge) { c.Nonce = c.Nonce[:31] },
		"metadata":             func(c *NativeShareEpochProofChallenge) { c.Metadata.GrantGeneration = 0 },
		"expiry format":        func(c *NativeShareEpochProofChallenge) { c.ExpiresAt = "2027-01-02T03:04:05+00:00" },
		"expiry past deadline": func(c *NativeShareEpochProofChallenge) { c.ExpiresAt = "2027-01-02T03:04:06Z" },
	} {
		t.Run(name, func(t *testing.T) {
			c := p.Challenge
			mutate(&c)
			if _, err := c.CanonicalBytes(); err == nil {
				t.Fatal("accepted malformed challenge")
			}
		})
	}
	for _, at := range []time.Time{{}, now.Add(time.Second), now.Add(2 * time.Second), now.Add(-5 * time.Minute)} {
		if p.Challenge.Validate(at) == nil {
			t.Fatal("accepted zero time, expired challenge or excessive lifetime")
		}
	}
	if err := p.Challenge.Validate(now.Add(-4*time.Minute - 59*time.Second)); err != nil {
		t.Fatal("rejected exact five minute lifetime", err)
	}
}

func TestNativeShareEpochProofStrictDecode(t *testing.T) {
	p, _, _, _ := nativeShareEpochProofFixture(t)
	for _, proof := range []bool{false, true} {
		var raw []byte
		decode := func(raw []byte) error { _, err := DecodeNativeShareEpochProofChallenge(raw); return err }
		if proof {
			raw, _ = json.Marshal(p)
			decode = func(raw []byte) error { _, err := DecodeNativeShareEpochProof(raw); return err }
		} else {
			raw, _ = json.Marshal(p.Challenge)
		}
		var walk func([]byte, func([]byte) []byte)
		walk = func(object []byte, wrap func([]byte) []byte) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(object, &fields); err != nil {
				t.Fatal(err)
			}
			for name, value := range fields {
				for _, mutation := range []string{"null", "missing", "case", "duplicate", "unknown"} {
					changed := make(map[string]json.RawMessage)
					for k, v := range fields {
						changed[k] = v
					}
					switch mutation {
					case "null":
						changed[name] = json.RawMessage("null")
					case "missing":
						delete(changed, name)
					case "case":
						delete(changed, name)
						changed[strings.ToUpper(name[:1])+name[1:]] = value
					case "unknown":
						changed["unknown"] = json.RawMessage("true")
					}
					input, _ := json.Marshal(changed)
					if mutation == "duplicate" {
						input = append(append([]byte(`{"`+name+`":`), value...), append([]byte(","), input[1:]...)...)
					}
					if decode(wrap(input)) == nil {
						t.Fatalf("accepted %s %s (proof=%v)", name, mutation, proof)
					}
				}
				if len(value) > 0 && value[0] == '{' {
					walk(value, func(child []byte) []byte {
						changed := make(map[string]json.RawMessage)
						for k, v := range fields {
							changed[k] = v
						}
						changed[name] = child
						input, _ := json.Marshal(changed)
						return wrap(input)
					})
				}
			}
		}
		walk(raw, func(input []byte) []byte { return input })
		for _, input := range [][]byte{append(append([]byte(nil), raw...), []byte(" {}")...), append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), 16<<10)...), raw[:len(raw)-1], bytes.Replace(raw, []byte(`"nonce":"`), []byte(`"nonce":"\n`), 1), bytes.Replace(raw, []byte(`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`), []byte(`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=`), 1)} {
			if decode(input) == nil {
				t.Fatal("accepted malformed or noncanonical encoding")
			}
		}
	}
}

func TestNativeShareEpochProofRejectsMismatchedEpochVerifier(t *testing.T) {
	p, epochKey, _, now := nativeShareEpochProofFixture(t)
	attackerKey, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.HostSignature = ed25519.Sign(hostPrivate, baseline)
	if err := p.Verify(p.Challenge, epochKey, hostKey, now); err != nil {
		t.Fatal(err)
	}
	challenge, err := p.Challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.EpochSignature = ed25519.Sign(attackerPrivate, challenge)
	host, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.HostSignature = ed25519.Sign(hostPrivate, host)
	if p.Verify(p.Challenge, attackerKey, hostKey, now) == nil {
		t.Fatal("accepted epoch signer differing from retained possession verifier")
	}
}
