package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func directFixture(t *testing.T) (directDescriptor, []byte, []byte, []byte, time.Time) {
	t.Helper()
	s, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	d := directDescriptor{directDomain, pairSuite, "parent", "9007199254740993", "network", directParty{"tenant-s", "principal-s", "endpoint-s", directB64(s.PublicKey().Bytes())}, directParty{"tenant-p", "principal-p", "endpoint-p", directB64(p.PublicKey().Bytes())}, epoch.String(), now.Add(time.Hour).Format(time.RFC3339Nano), directLimits{4096, 2, 10, 65536, 2}}
	raw, _ := json.Marshal(d)
	return d, raw, s.Bytes(), p.Bytes(), now
}
func directMaterials(t *testing.T) (*directMaterial, *directMaterial, []byte, time.Time) {
	t.Helper()
	d, raw, s, p, now := directFixture(t)
	sm, wire, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := directAccept(wire, d, p, now)
	if err != nil {
		t.Fatal(err)
	}
	return sm, pm, wire, now
}
func TestDirectRoundTripAndSeparation(t *testing.T) {
	s, p, pkg, now := directMaterials(t)
	if s.key != p.key || s.hash != p.hash {
		t.Fatal("material mismatch")
	}
	readiness, _ := s.readinessKey()
	askKey, _ := s.derive("ASK")
	replyKey, _ := s.derive("REPLY")
	if bytes.Equal(readiness, askKey) || bytes.Equal(askKey, replyKey) || bytes.Equal(readiness, replyKey) {
		t.Fatal("key domains overlap")
	}
	ask, err := s.seal("ASK", "ask-1", "root", nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := p.open("ASK", "ask-1", "root", nil, ask, now)
	if err != nil || string(plaintext) != "question" {
		t.Fatalf("ASK: %s %v", plaintext, err)
	}
	reply, err := p.seal("REPLY", "reply-1", "root", ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = s.open("REPLY", "reply-1", "root", ask, reply, now)
	if err != nil || string(plaintext) != "answer" {
		t.Fatalf("REPLY: %s %v", plaintext, err)
	}
	// A stateless parser can reopen an identical delivery. Admission/deduplication
	// is intentionally outside this cryptographic layer.
	if _, err = p.open("ASK", "ask-1", "root", nil, ask, now); err != nil {
		t.Fatal(err)
	}
	if _, err = p.open("ASK", "ask-2", "root", nil, ask, now); err == nil {
		t.Fatal("replay under another ID accepted")
	}
	serializedMaterial, err := json.Marshal(s)
	if err != nil || string(serializedMaterial) != "{}" {
		t.Fatal("local material is serializable")
	}
	// Publication is an explicit allowlist and contains no epoch or traffic key.
	var publication map[string]json.RawMessage
	if err = json.Unmarshal(pkg, &publication); err != nil {
		t.Fatal(err)
	}
	if len(publication) != 3 || publication["descriptor"] == nil || publication["enc"] == nil || publication["ciphertext"] == nil {
		t.Fatal("publication fields")
	}
	for _, secret := range [][]byte{s.key[:], readiness, askKey, replyKey} {
		if bytes.Contains(pkg, []byte(directB64(secret))) {
			t.Fatal("secret exposed to N")
		}
	}
	if bytes.Contains(pkg, []byte("networkPublicKey")) {
		t.Fatal("N key field")
	}
}
func TestDirectDescriptorStrictness(t *testing.T) {
	d, raw, _, _, now := directFixture(t)
	cases := map[string][]byte{
		"duplicate":         []byte(strings.Replace(string(raw), `"domain":`, `"domain":"ignored","domain":`, 1)),
		"unknown":           append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"extra":1}`)...),
		"whitespace":        append([]byte(" "), raw...),
		"generation-number": []byte(strings.Replace(string(raw), `"9007199254740993"`, `9007199254740993`, 1)),
	}
	for name, mutate := range map[string]func(*directDescriptor){
		"generation-zero":         func(d *directDescriptor) { d.Generation = "0" },
		"generation-leading-zero": func(d *directDescriptor) { d.Generation = "01" },
		"generation-overflow":     func(d *directDescriptor) { d.Generation = "18446744073709551616" },
		"public-padding":          func(d *directDescriptor) { d.S.PublicKey += "=" },
		"public-ambiguous":        func(d *directDescriptor) { d.S.PublicKey = d.S.PublicKey[:42] + "B" },
		"domain":                  func(d *directDescriptor) { d.Domain = "pagnet/sdk-pair" },
		"expired":                 func(d *directDescriptor) { d.ExpiresAt = now.Format(time.RFC3339Nano) },
		"same-principal":          func(d *directDescriptor) { d.P.PrincipalID = d.S.PrincipalID },
		"same-key":                func(d *directDescriptor) { d.P.PublicKey = d.S.PublicKey },
		"limits":                  func(d *directDescriptor) { d.Limits.MaxInFlight = 0 },
	} {
		mutated := d
		mutate(&mutated)
		encoded, _ := json.Marshal(mutated)
		t.Run(name, func(t *testing.T) {
			if _, err := directValidate(encoded, mutated, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := directValidate(raw, d, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	other := d
	other.NetworkID = "other"
	if _, err := directValidate(raw, other, now); err == nil {
		t.Fatal("untrusted descriptor accepted")
	}
	for _, mutate := range []func(*directDescriptor){func(d *directDescriptor) { d.ParentGrantID = "other" }, func(d *directDescriptor) { d.Generation = "2" }, func(d *directDescriptor) { d.S.EndpointID = "other" }, func(d *directDescriptor) { d.P.PublicKey = d.S.PublicKey }, func(d *directDescriptor) { d.EpochID = "other" }} {
		other = d
		mutate(&other)
		if directChannelID(other) == directChannelID(d) {
			t.Fatal("channel identity collision")
		}
	}
}
func TestDirectPackageAuthentication(t *testing.T) {
	d, raw, s, p, now := directFixture(t)
	_, wire, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, wrong, _, _ := directFixture(t)
	if _, _, err = directPrepare(raw, d, wrong, now); err == nil {
		t.Fatal("wrong sender private accepted")
	}
	if _, err = directAccept(wire, d, wrong, now); err == nil {
		t.Fatal("wrong recipient private accepted")
	}
	for _, field := range []string{"enc", "ciphertext", "epoch", "sender", "recipient", "network"} {
		t.Run(field, func(t *testing.T) {
			var pkg directPackage
			json.Unmarshal(wire, &pkg)
			expected := d
			switch field {
			case "enc":
				b, _ := directBinary(pkg.Enc, 32)
				b[0] ^= 1
				pkg.Enc = directB64(b)
			case "ciphertext":
				b, _ := directBinary(pkg.Ciphertext, 48)
				b[0] ^= 1
				pkg.Ciphertext = directB64(b)
			case "epoch":
				id, _ := uuid.NewV7()
				expected.EpochID = id.String()
			case "sender":
				expected.S.PublicKey = directB64(wrong)
			case "recipient":
				expected.P.PublicKey = directB64(wrong)
			case "network":
				expected.NetworkID = "other"
			}
			if field == "epoch" || field == "sender" || field == "recipient" || field == "network" {
				pkg.Descriptor, _ = json.Marshal(expected)
			}
			mutated, _ := json.Marshal(pkg)
			if _, err := directAccept(mutated, expected, p, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestDirectMessageContextAndTamper(t *testing.T) {
	s, p, _, now := directMaterials(t)
	ask, err := s.seal("ASK", "ask", "root", nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := p.seal("REPLY", "reply", "root", ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kind", "channel", "descriptor", "id", "root", "from", "to", "ask-id", "ask-hash", "nonce", "ciphertext", "padding", "duplicate", "unknown"} {
		t.Run(name, func(t *testing.T) {
			var w directWire
			json.Unmarshal(reply, &w)
			switch name {
			case "kind":
				w.Header.Kind = "ASK"
			case "channel":
				w.Header.ChannelID = "other"
			case "descriptor":
				w.Header.DescriptorHash = "other"
			case "id":
				w.Header.MessageID = "other"
			case "root":
				w.Header.RootID = "other"
			case "from":
				w.Header.From = s.descriptor.S
			case "to":
				w.Header.To = s.descriptor.P
			case "ask-id":
				w.Header.AskID = "other"
			case "ask-hash":
				w.Header.AskWireHash = "other"
			case "nonce":
				b, _ := directBinary(w.Nonce, 12)
				b[0] ^= 1
				w.Nonce = directB64(b)
			case "ciphertext":
				b, _ := directBinary(w.Ciphertext, -1)
				b[0] ^= 1
				w.Ciphertext = directB64(b)
			case "padding":
				w.Nonce += "="
			}
			mutated, _ := json.Marshal(w)
			if name == "duplicate" {
				mutated = []byte(strings.Replace(string(mutated), `"kind":`, `"kind":"REPLY","kind":`, 1))
			}
			if name == "unknown" {
				mutated = append(mutated[:len(mutated)-1], []byte(`,"extra":1}`)...)
			}
			if _, err := s.open("REPLY", "reply", "root", ask, mutated, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	secondAsk, err := s.seal("ASK", "ask", "root", nil, []byte("different question"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.open("REPLY", "reply", "root", secondAsk, reply, now); err == nil {
		t.Fatal("reply replayed against different ASK wire")
	}
	for name, run := range map[string]func() error{
		"wrong sender role":     func() error { _, e := p.seal("ASK", "ask", "root", nil, nil, now); return e },
		"wrong recipient role":  func() error { _, e := s.open("ASK", "ask", "root", nil, ask, now); return e },
		"wrong reply role":      func() error { _, e := s.seal("REPLY", "reply", "root", ask, nil, now); return e },
		"wrong reply recipient": func() error { _, e := p.open("REPLY", "reply", "root", ask, reply, now); return e },
		"expired":               func() error { _, e := p.open("ASK", "ask", "root", nil, ask, now.Add(2*time.Hour)); return e },
		"root replay":           func() error { _, e := p.open("ASK", "ask", "other", nil, ask, now); return e },
		"corrupt ask": func() error {
			bad := append([]byte(nil), ask...)
			bad[len(bad)-3] ^= 1
			_, e := p.seal("REPLY", "reply", "root", bad, nil, now)
			return e
		},
		"oversize": func() error { _, e := s.seal("ASK", "ask", "root", nil, make([]byte, 4096), now); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if run() == nil {
				t.Fatal("accepted")
			}
		})
	}
	other := *p
	other.key[0] ^= 1
	if _, err = other.open("ASK", "ask", "root", nil, ask, now); err == nil {
		t.Fatal("wrong key accepted")
	}
	other = *p
	id, _ := uuid.NewV7()
	other.descriptor.EpochID = id.String()
	if _, err = other.open("ASK", "ask", "root", nil, ask, now); err == nil {
		t.Fatal("wrong epoch accepted")
	}
}
func TestDirectReadinessProof(t *testing.T) {
	s, p, _, now := directMaterials(t)
	for _, m := range []*directMaterial{s, p} {
		t.Run(m.role, func(t *testing.T) {
			d := m.descriptor
			party := d.S
			if m.role == "P" {
				party = d.P
			}
			transcript := directProofTranscript{directDomain + "/proof", "challenge", m.role, party.PrincipalID, party.EndpointID, "credential", directChannelID(d), d.ParentGrantID, d.Generation, directB64(m.hash[:]), d.EpochID, directB64(make([]byte, 32))}
			raw, _ := json.Marshal(transcript)
			challenge := directChallenge{"challenge", raw, now.Add(time.Minute)}
			proof, err := m.readinessProof(challenge, "credential", now)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := m.readinessKey()
			mac := hmac.New(sha256.New, key)
			mac.Write(raw)
			if !hmac.Equal(proof, mac.Sum(nil)) {
				t.Fatal("MAC mismatch")
			}
			for _, field := range []string{"role", "principal", "endpoint", "credential", "channel", "parent", "generation", "descriptor", "epoch", "nonce", "id", "domain"} {
				t.Run(field, func(t *testing.T) {
					mutated := transcript
					switch field {
					case "role":
						mutated.Role = "N"
					case "principal":
						mutated.PrincipalID = "other"
					case "endpoint":
						mutated.EndpointID = "other"
					case "credential":
						mutated.CredentialID = "other"
					case "channel":
						mutated.ChannelID = "other"
					case "parent":
						mutated.ParentGrantID = "other"
					case "generation":
						mutated.Generation = "2"
					case "descriptor":
						mutated.DescriptorHash = "other"
					case "epoch":
						mutated.EpochID = "other"
					case "nonce":
						mutated.Nonce += "="
					case "id":
						mutated.ChallengeID = "other"
					case "domain":
						mutated.Domain = "pagnet/sdk-pair/proof/v1"
					}
					c := challenge
					c.Transcript, _ = json.Marshal(mutated)
					if _, err := m.readinessProof(c, "credential", now); err == nil {
						t.Fatal("accepted")
					}
				})
			}
			if _, err = m.readinessProof(challenge, "wrong", now); err == nil {
				t.Fatal("wrong credential metadata accepted")
			}
			if _, err = m.readinessProof(challenge, "credential", now.Add(time.Minute)); err == nil {
				t.Fatal("expired challenge accepted")
			}
		})
	}
}
