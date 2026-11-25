package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

const (
	directTestAskID         = "11111111-1111-4111-8111-111111111111"
	directTestSecondAskID   = "22222222-2222-4222-8222-222222222222"
	directTestReplyID       = "33333333-3333-4333-8333-333333333333"
	directTestSecondReplyID = "44444444-4444-4444-8444-444444444444"
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
	limits := directLimits{MaxMessageWireBytes: 4096, MaxMessagesPerMinute: 2, MaxMessagesPerDay: 10, MaxWireBytesPerDay: 65536, MaxInFlight: 2, MaxTurnsPerThread: 4}
	expiry := now.Add(time.Hour).Format(time.RFC3339Nano)
	d := directDescriptor{Domain: directDomain, Suite: pairSuite, ParentGrantID: uuid.NewString(), GrantGeneration: "9007199254740993", ChannelGeneration: "2", DirectIntentID: uuid.NewString(), NetworkID: uuid.NewString(), AuthorizationDigest: strings.Repeat("a", 64), S: directParty{TenantID: uuid.NewString(), PrincipalID: uuid.NewString(), EndpointID: uuid.NewString(), PublicKey: directB64(s.PublicKey().Bytes()), CredentialID: uuid.NewString(), KeyEvidenceDigest: strings.Repeat("b", 64)}, P: directParty{TenantID: uuid.NewString(), PrincipalID: uuid.NewString(), EndpointID: uuid.NewString(), PublicKey: directB64(p.PublicKey().Bytes()), CredentialID: uuid.NewString(), KeyEvidenceDigest: strings.Repeat("c", 64)}, EpochID: epoch.String(), ExpiresAt: expiry, Budget: transport.DirectChannelBudgetV2{AgreementID: uuid.NewString(), AcceptedRevision: "2", TermsDigest: strings.Repeat("d", 64), ExpiresAt: expiry, CountingVersion: transport.DirectChannelCountingVersionV2, GrantLimits: limits}, Limits: limits}
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
	ask, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := p.open("ASK", directTestAskID, directTestAskID, nil, ask, now)
	if err != nil || string(plaintext) != "question" {
		t.Fatalf("ASK: %s %v", plaintext, err)
	}
	reply, err := p.seal("REPLY", directTestReplyID, directTestAskID, ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = s.open("REPLY", directTestReplyID, directTestAskID, ask, reply, now)
	if err != nil || string(plaintext) != "answer" {
		t.Fatalf("REPLY: %s %v", plaintext, err)
	}
	// A stateless parser can reopen an identical delivery. Admission/deduplication
	// is intentionally outside this cryptographic layer.
	if _, err = p.open("ASK", directTestAskID, directTestAskID, nil, ask, now); err != nil {
		t.Fatal(err)
	}
	if _, err = p.open("ASK", directTestSecondAskID, directTestAskID, nil, ask, now); err == nil {
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
		"generation-zero":         func(d *directDescriptor) { d.GrantGeneration = "0" },
		"generation-leading-zero": func(d *directDescriptor) { d.GrantGeneration = "01" },
		"generation-overflow":     func(d *directDescriptor) { d.GrantGeneration = "18446744073709551616" },
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
	otherD, _, _, _, _ := directFixture(t)
	for _, mutate := range []func(*directDescriptor){
		func(d *directDescriptor) { d.ParentGrantID = uuid.NewString() },
		func(d *directDescriptor) { d.GrantGeneration = "2" },
		func(d *directDescriptor) { d.ChannelGeneration = "3" },
		func(d *directDescriptor) { d.DirectIntentID = uuid.NewString() },
		func(d *directDescriptor) { d.S.EndpointID = uuid.NewString() },
		func(d *directDescriptor) { d.P.PublicKey = otherD.P.PublicKey },
		func(d *directDescriptor) { id, _ := uuid.NewV7(); d.EpochID = id.String() },
	} {
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
	wrongD, _, wrong, _, _ := directFixture(t)
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
				expected.S.PublicKey = wrongD.S.PublicKey
			case "recipient":
				expected.P.PublicKey = wrongD.S.PublicKey
			case "network":
				expected.NetworkID = uuid.NewString()
			}
			if field == "epoch" || field == "sender" || field == "recipient" || field == "network" {
				pkg.Descriptor = expected
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
	ask, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("question"), now)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := p.seal("REPLY", directTestReplyID, directTestAskID, ask, []byte("answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kind", "channel", "descriptor", "id", "root", "role", "epoch", "ask-id", "ask-hash", "nonce", "ciphertext", "padding", "duplicate", "unknown"} {
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
			case "role":
				w.Header.SenderRole = "S"
			case "epoch":
				w.Header.EpochID = "other"
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
			if _, err := s.open("REPLY", directTestReplyID, directTestAskID, ask, mutated, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	secondAsk, err := s.seal("ASK", directTestAskID, directTestAskID, nil, []byte("different question"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.open("REPLY", directTestReplyID, directTestAskID, secondAsk, reply, now); err == nil {
		t.Fatal("reply replayed against different ASK wire")
	}
	for name, run := range map[string]func() error{
		"wrong sender role": func() error {
			_, e := p.seal("ASK", directTestAskID, directTestAskID, nil, nil, now)
			return e
		},
		"wrong recipient role": func() error {
			_, e := s.open("ASK", directTestAskID, directTestAskID, nil, ask, now)
			return e
		},
		"wrong reply role": func() error {
			_, e := s.seal("REPLY", directTestReplyID, directTestAskID, ask, nil, now)
			return e
		},
		"wrong reply recipient": func() error {
			_, e := p.open("REPLY", directTestReplyID, directTestAskID, ask, reply, now)
			return e
		},
		"expired": func() error {
			_, e := p.open("ASK", directTestAskID, directTestAskID, nil, ask, now.Add(2*time.Hour))
			return e
		},
		"root replay": func() error {
			_, e := p.open("ASK", directTestAskID, "other", nil, ask, now)
			return e
		},
		"corrupt ask": func() error {
			bad := append([]byte(nil), ask...)
			bad[len(bad)-3] ^= 1
			_, e := p.seal("REPLY", directTestReplyID, directTestAskID, bad, nil, now)
			return e
		},
		"oversize": func() error {
			_, e := s.seal("ASK", directTestAskID, directTestAskID, nil, make([]byte, 4096), now)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if run() == nil {
				t.Fatal("accepted")
			}
		})
	}
	other := *p
	other.key[0] ^= 1
	if _, err = other.open("ASK", directTestAskID, directTestAskID, nil, ask, now); err == nil {
		t.Fatal("wrong key accepted")
	}
	other = *p
	id, _ := uuid.NewV7()
	other.descriptor.EpochID = id.String()
	if _, err = other.open("ASK", directTestAskID, directTestAskID, nil, ask, now); err == nil {
		t.Fatal("wrong epoch accepted")
	}
}
func directReadinessChallenge(m *directMaterial, now time.Time) transport.DirectChannelReadinessChallengeV2 {
	d := m.descriptor
	party := d.S
	if m.role == "P" {
		party = d.P
	}
	return transport.DirectChannelReadinessChallengeV2{Domain: directDomain + "/proof", ChallengeID: uuid.NewString(), Role: m.role, PrincipalID: party.PrincipalID, EndpointID: party.EndpointID, CredentialID: party.CredentialID, ChannelID: directChannelID(d), ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration, ChannelGeneration: d.ChannelGeneration, DirectIntentID: d.DirectIntentID, DescriptorHash: directB64(m.hash[:]), PublicationHash: directB64(m.publicationHash[:]), EpochID: d.EpochID, Nonce: directB64(make([]byte, 32)), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
}
func TestDirectReadinessProof(t *testing.T) {
	s, p, publication, now := directMaterials(t)
	pub, err := transport.DecodeDirectChannelPublicationV2(publication)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*directMaterial{s, p} {
		t.Run(m.role, func(t *testing.T) {
			challenge := directReadinessChallenge(m, now)
			raw, err := challenge.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := m.readinessProof(raw, challenge.CredentialID, now)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := transport.DecodeDirectChannelReadinessProofV2(proof)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := m.readinessKey()
			mac := hmac.New(sha256.New, key)
			mac.Write(raw)
			if decoded.Confirmation != directB64(mac.Sum(nil)) {
				t.Fatal("MAC mismatch")
			}
			if err := transport.VerifyDirectChannelReadinessProofV2(pub, challenge, decoded, key, now); err != nil {
				t.Fatal(err)
			}
			retry, err := m.readinessProof(raw, challenge.CredentialID, now)
			if err != nil || !bytes.Equal(proof, retry) {
				t.Fatal("same challenge retry changed proof")
			}
			for name, mutate := range map[string]func(*transport.DirectChannelReadinessChallengeV2){
				"role": func(c *transport.DirectChannelReadinessChallengeV2) {
					if c.Role == "S" {
						c.Role = "P"
					} else {
						c.Role = "S"
					}
				},
				"principal":  func(c *transport.DirectChannelReadinessChallengeV2) { c.PrincipalID = uuid.NewString() },
				"endpoint":   func(c *transport.DirectChannelReadinessChallengeV2) { c.EndpointID = uuid.NewString() },
				"credential": func(c *transport.DirectChannelReadinessChallengeV2) { c.CredentialID = uuid.NewString() },
				"channel": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.ChannelID = directB64(bytes.Repeat([]byte{1}, 32))
				},
				"parent":             func(c *transport.DirectChannelReadinessChallengeV2) { c.ParentGrantID = uuid.NewString() },
				"grant-generation":   func(c *transport.DirectChannelReadinessChallengeV2) { c.GrantGeneration = "2" },
				"channel-generation": func(c *transport.DirectChannelReadinessChallengeV2) { c.ChannelGeneration = "3" },
				"intent":             func(c *transport.DirectChannelReadinessChallengeV2) { c.DirectIntentID = uuid.NewString() },
				"descriptor": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.DescriptorHash = directB64(bytes.Repeat([]byte{1}, 32))
				},
				"publication": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.PublicationHash = directB64(bytes.Repeat([]byte{1}, 32))
				},
				"epoch":  func(c *transport.DirectChannelReadinessChallengeV2) { id, _ := uuid.NewV7(); c.EpochID = id.String() },
				"nonce":  func(c *transport.DirectChannelReadinessChallengeV2) { c.Nonce += "=" },
				"domain": func(c *transport.DirectChannelReadinessChallengeV2) { c.Domain = "pagnet/direct_ask_reply_v1/proof" },
				"future": func(c *transport.DirectChannelReadinessChallengeV2) {
					c.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano)
				},
				"expired": func(c *transport.DirectChannelReadinessChallengeV2) { c.ExpiresAt = now.Format(time.RFC3339Nano) },
			} {
				t.Run(name, func(t *testing.T) {
					changed := challenge
					mutate(&changed)
					raw, _ := json.Marshal(changed)
					if _, err := m.readinessProof(raw, challenge.CredentialID, now); err == nil {
						t.Fatal("accepted")
					}
				})
			}
			if _, err = m.readinessProof(raw, uuid.NewString(), now); err == nil {
				t.Fatal("wrong credential metadata accepted")
			}
			if _, err = m.readinessProof(raw, challenge.CredentialID, now.Add(time.Minute)); err == nil {
				t.Fatal("expired challenge accepted")
			}
			// A changed nonce is a distinct challenge and must not validate the old proof.
			changed := challenge
			changed.Nonce = directB64(bytes.Repeat([]byte{1}, 32))
			if transport.VerifyDirectChannelReadinessProofV2(pub, changed, decoded, key, now) == nil {
				t.Fatal("proof replayed against changed nonce")
			}
		})
	}
}

// Keep a genuine legacy descriptor shape to ensure V2 never treats V1 as a
// descriptor with omitted zero-valued V2 bindings.
func directLegacyDescriptor(t *testing.T, d directDescriptor) []byte {
	t.Helper()
	type party struct {
		TenantID    string `json:"tenantId"`
		PrincipalID string `json:"principalId"`
		EndpointID  string `json:"endpointId"`
		PublicKey   string `json:"publicKey"`
	}
	legacyParty := func(p directParty) party { return party{p.TenantID, p.PrincipalID, p.EndpointID, p.PublicKey} }
	legacy := struct {
		Domain        string `json:"domain"`
		Suite         string `json:"suite"`
		ParentGrantID string `json:"parentGrantId"`
		Generation    string `json:"generation"`
		NetworkID     string `json:"networkId"`
		S             party  `json:"s"`
		P             party  `json:"p"`
		EpochID       string `json:"epochId"`
		ExpiresAt     string `json:"expiresAt"`
		Limits        struct {
			MaxMessageWireBytes int `json:"maxMessageWireBytes"`
			MaxAsksPerMinute    int `json:"maxAsksPerMinute"`
			MaxAsksPerDay       int `json:"maxAsksPerDay"`
			MaxWireBytesPerDay  int `json:"maxWireBytesPerDay"`
			MaxInFlight         int `json:"maxInFlight"`
		} `json:"limits"`
	}{Domain: "pagnet/direct_ask_reply_v1", Suite: d.Suite, ParentGrantID: d.ParentGrantID, Generation: d.GrantGeneration, NetworkID: d.NetworkID, S: legacyParty(d.S), P: legacyParty(d.P), EpochID: d.EpochID, ExpiresAt: d.ExpiresAt}
	legacy.Limits.MaxMessageWireBytes = d.Limits.MaxMessageWireBytes
	legacy.Limits.MaxAsksPerMinute = d.Limits.MaxMessagesPerMinute
	legacy.Limits.MaxAsksPerDay = d.Limits.MaxMessagesPerDay
	legacy.Limits.MaxWireBytesPerDay = d.Limits.MaxWireBytesPerDay
	legacy.Limits.MaxInFlight = d.Limits.MaxInFlight
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDirectV1FailsClosed(t *testing.T) {
	d, raw, s, p, now := directFixture(t)
	legacy := directLegacyDescriptor(t, d)
	if _, _, err := directPrepare(legacy, d, s, now); err == nil {
		t.Fatal("prepared V1")
	}
	if _, err := transport.DecodeDirectChannelDescriptorV2(legacy); err == nil {
		t.Fatal("decoded V1 descriptor")
	}
	_, publication, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Descriptor json.RawMessage `json:"descriptor"`
		Enc        string          `json:"enc"`
		Ciphertext string          `json:"ciphertext"`
	}
	if err := json.Unmarshal(publication, &old); err != nil {
		t.Fatal(err)
	}
	old.Descriptor = legacy
	publication, _ = json.Marshal(old)
	if _, err := directAccept(publication, d, p, now); err == nil {
		t.Fatal("accepted V1 publication")
	}
	if _, err := transport.DecodeDirectChannelPublicationV2(publication); err == nil {
		t.Fatal("decoded V1 publication")
	}
}

func TestDirectV2DescriptorBinding(t *testing.T) {
	d, raw, s, p, now := directFixture(t)
	_, publication, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	other, _, otherS, otherP, _ := directFixture(t)
	for name, mutate := range map[string]func(*directDescriptor){
		"source-key":         func(d *directDescriptor) { d.S.PublicKey = other.S.PublicKey },
		"target-key":         func(d *directDescriptor) { d.P.PublicKey = other.P.PublicKey },
		"swapped-roles":      func(d *directDescriptor) { d.S, d.P = d.P, d.S },
		"source-endpoint":    func(d *directDescriptor) { d.S.EndpointID = uuid.NewString() },
		"target-endpoint":    func(d *directDescriptor) { d.P.EndpointID = uuid.NewString() },
		"source-credential":  func(d *directDescriptor) { d.S.CredentialID = uuid.NewString() },
		"target-credential":  func(d *directDescriptor) { d.P.CredentialID = uuid.NewString() },
		"source-evidence":    func(d *directDescriptor) { d.S.KeyEvidenceDigest = strings.Repeat("e", 64) },
		"target-evidence":    func(d *directDescriptor) { d.P.KeyEvidenceDigest = strings.Repeat("e", 64) },
		"grant-generation":   func(d *directDescriptor) { d.GrantGeneration = "2" },
		"channel-generation": func(d *directDescriptor) { d.ChannelGeneration = "3" },
		"direct-intent":      func(d *directDescriptor) { d.DirectIntentID = uuid.NewString() },
		"authorization":      func(d *directDescriptor) { d.AuthorizationDigest = strings.Repeat("e", 64) },
		"budget-id":          func(d *directDescriptor) { d.Budget.AgreementID = uuid.NewString() },
		"budget-revision":    func(d *directDescriptor) { d.Budget.AcceptedRevision = "3" },
		"budget-digest":      func(d *directDescriptor) { d.Budget.TermsDigest = strings.Repeat("e", 64) },
		"budget-expiry":      func(d *directDescriptor) { d.Budget.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano) },
		"budget-counting":    func(d *directDescriptor) { d.Budget.CountingVersion = "ask_only_v1" },
		"grant-limits":       func(d *directDescriptor) { d.Budget.GrantLimits.MaxTurnsPerThread++ },
		"channel-limits":     func(d *directDescriptor) { d.Limits.MaxMessagesPerDay-- },
	} {
		t.Run(name, func(t *testing.T) {
			changed := d
			mutate(&changed)
			changedRaw, _ := json.Marshal(changed)
			// Even structurally valid replacements must match the authenticated selection.
			if _, _, err := directPrepare(changedRaw, d, s, now); err == nil {
				t.Fatal("prepared unpinned descriptor")
			}
			pkg, err := transport.DecodeDirectChannelPublicationV2(publication)
			if err != nil {
				t.Fatal(err)
			}
			pkg.Descriptor = changed
			wire, _ := json.Marshal(pkg)
			private := p
			if name == "target-key" {
				private = otherP
			}
			if name == "swapped-roles" {
				private = s
			}
			if _, err := directAccept(wire, changed, private, now); err == nil {
				t.Fatal("accepted rewritten HPKE context")
			}
		})
	}
	// A correctly authenticated sibling endpoint publication is still rejected
	// when the caller pins the originally selected endpoint.
	sibling := d
	sibling.S.PublicKey = other.S.PublicKey
	sibling.S.EndpointID = other.S.EndpointID
	sibling.S.CredentialID = other.S.CredentialID
	siblingRaw, _ := sibling.CanonicalBytes()
	_, wire, err := directPrepare(siblingRaw, sibling, otherS, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directAccept(wire, d, p, now); err == nil {
		t.Fatal("source sibling substitution accepted")
	}
}

func TestDirectV2CryptoDomainsAndFreshRoot(t *testing.T) {
	d, raw, s, p, now := directFixture(t)
	m, publication, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPublication, err := directPrepare(raw, d, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.key == second.key || bytes.Equal(publication, secondPublication) || bytes.Equal(m.key[:], s) || bytes.Equal(m.key[:], p) {
		t.Fatal("root is not fresh pairwise material")
	}
	pkg, err := transport.DecodeDirectChannelPublicationV2(publication)
	if err != nil {
		t.Fatal(err)
	}
	sender, _ := directBinary(d.S.PublicKey, 32)
	enc, _ := directBinary(pkg.Enc, 32)
	ct, _ := directBinary(pkg.Ciphertext, 48)
	hash := sha256.Sum256(raw)
	root, err := e2ee.HPKEUnwrapAuth(p, sender, enc, []byte("pagnet/direct_ask_reply_v2/epoch-wrap"), hash[:], ct)
	if err != nil || !bytes.Equal(root, m.key[:]) {
		t.Fatalf("V2 HPKE contract: %v", err)
	}
	if _, err := e2ee.HPKEUnwrapAuth(p, sender, enc, []byte("pagnet/direct_ask_reply_v1/epoch-wrap"), hash[:], ct); err == nil {
		t.Fatal("V1 HPKE domain accepted")
	}
	if _, err := e2ee.HPKEUnwrapAuth(p, sender, enc, []byte("pagnet/direct_ask_reply_v2/epoch-wrap"), []byte(directB64(hash[:])), ct); err == nil {
		t.Fatal("text descriptor hash AAD accepted")
	}
	for _, purpose := range []string{"readiness", "ASK", "REPLY"} {
		expected, err := hkdf.Key(sha256.New, root, hash[:], "pagnet/direct_ask_reply_v2/"+purpose, 32)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := m.derive(purpose)
		if err != nil || !bytes.Equal(expected, actual) {
			t.Fatalf("V2 HKDF %s: %v", purpose, err)
		}
	}
}

func TestDirectCompactContinuationAndCap(t *testing.T) {
	s, p, _, now := directMaterials(t)
	const root = "11111111-1111-4111-8111-111111111111"
	const replyID = "22222222-2222-4222-8222-222222222222"
	const nextID = "33333333-3333-4333-8333-333333333333"
	const lastID = "44444444-4444-4444-8444-444444444444"
	ask, err := s.seal("ASK", root, root, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ask) > 1024 {
		t.Fatalf("empty ASK is %d bytes", len(ask))
	}
	reply, err := p.seal("REPLY", replyID, root, ask, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) > 1024 {
		t.Fatalf("empty REPLY is %d bytes", len(reply))
	}
	next, err := s.sealContinuationAsk(nextID, ask, reply, []byte("next question"), now)
	if err != nil {
		t.Fatal(err)
	}
	w, err := transport.DecodeDirectChannelMessageV2(next)
	if err != nil {
		t.Fatal(err)
	}
	parentHash := sha256.Sum256(reply)
	if w.Header.RootID != root || w.Header.ParentMessageID != replyID || w.Header.ParentWireHash != directB64(parentHash[:]) {
		t.Fatal("continuation links")
	}
	plain, err := p.open("ASK", nextID, root, nil, next, now)
	if err != nil || string(plain) != "next question" {
		t.Fatalf("continuation open: %v", err)
	}
	final, err := p.seal("REPLY", lastID, root, next, []byte("last answer"), now)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = s.open("REPLY", lastID, root, next, final, now)
	if err != nil || string(plain) != "last answer" {
		t.Fatalf("continuation reply: %v", err)
	}
	if _, err := s.seal("ASK", nextID, root, nil, nil, now); err == nil {
		t.Fatal("initial ASK inherited a root")
	}
	for _, which := range []string{"ask", "reply"} {
		badAsk, badReply := append([]byte(nil), ask...), append([]byte(nil), reply...)
		if which == "ask" {
			badAsk[len(badAsk)-3] ^= 1
		} else {
			badReply[len(badReply)-3] ^= 1
		}
		if _, err := s.sealContinuationAsk(nextID, badAsk, badReply, nil, now); err == nil {
			t.Fatalf("tampered parent %s", which)
		}
	}
	// A structurally valid changed parent hash must fail GCM authentication.
	w.Header.ParentWireHash = directB64(bytes.Repeat([]byte{1}, 32))
	changed, _ := w.CanonicalBytes()
	if _, err := p.open("ASK", nextID, root, nil, changed, now); err == nil {
		t.Fatal("parent hash missing from AAD")
	}
	// Exercise the complete-wire boundary with the original authenticated descriptor.
	// Base64 expands in steps, so choose the descriptor cap to match a real wire.
	d, _, source, peer, now := directFixture(t)
	d.Limits.MaxMessageWireBytes = 1024
	d.Budget.GrantLimits.MaxMessageWireBytes = 1024
	raw, _ := d.CanonicalBytes()
	s, publication, err := directPrepare(raw, d, source, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err = directAccept(publication, d, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	var exact []byte
	for n := 0; n < 1024; n++ {
		candidate, err := s.seal("ASK", root, root, nil, make([]byte, n), now)
		if err != nil {
			break
		}
		if len(candidate) == 1024 {
			exact = candidate
			break
		}
	}
	if exact == nil {
		t.Fatal("could not construct exact 1024-byte wire")
	}
	if _, err := p.open("ASK", root, root, nil, exact, now); err != nil {
		t.Fatal(err)
	}
	var boundary directWire
	json.Unmarshal(exact, &boundary)
	ct, _ := directBinary(boundary.Ciphertext, -1)
	if _, err := s.seal("ASK", root, root, nil, make([]byte, len(ct)-16+1), now); err == nil {
		t.Fatal("over-cap wire accepted")
	}
}
