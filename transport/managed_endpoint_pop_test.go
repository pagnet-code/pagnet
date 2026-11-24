package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func managedPoPFixture(t *testing.T) (ManagedEndpointPoPChallenge, []byte, []byte) {
	t.Helper()
	id := func(n byte) domain.ID {
		return domain.ID("10000000-0000-4000-8000-0000000000" + hex.EncodeToString([]byte{n}))
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	command, ack := managedPrepareFixture(t)
	// Replace every randomized fixture value with stable IDs for golden vectors.
	subject := &command.Subject
	subject.ID = id(1)
	subject.DirectIntentID = id(2)
	subject.TenantID = id(20)
	subject.AccountID = id(21)
	subject.PrincipalID = id(24)
	subject.EndpointID = id(6)
	subject.InstanceID = id(7)
	subject.OriginID = id(8)
	subject.OwnershipID = id(9)
	subject.NativeAdmissionID = id(10)
	subject.ConnectionIncarnationID = id(10)
	subject.HostID = id(11)
	subject.HostCredentialID = id(12)
	subject.RunnerID = id(13)
	subject.CreatedAt = now
	subject.ExpiresAt = now.Add(5 * time.Minute)
	subject.RunnerConnectedAt = now.Add(-time.Minute)
	command.CommandID = id(14)
	host := bytes.Repeat([]byte{0x31}, 32)
	server := bytes.Repeat([]byte{0x42}, 32)
	hostKey, _ := ecdh.X25519().NewPrivateKey(host)
	serverKey, _ := ecdh.X25519().NewPrivateKey(server)
	ack.CommandID = command.CommandID
	ack.Reservation.Subject = *subject
	ack.Reservation.InstallationID = id(15)
	ack.Reservation.X25519 = hex.EncodeToString(hostKey.PublicKey().Bytes())
	ack.Reservation.EnrollmentDigest, _ = ack.Reservation.Digest()
	receipt, err := NewManagedEndpointPrepareReceiptReference(ack)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := DirectAuthorizationSnapshotV1{ProtocolVersion: DirectAuthorizationSnapshotProtocol, DirectIntentID: id(2), EpochID: id(16), ProposalID: id(17), ProposalVersion: 3, GrantID: id(18), GrantGeneration: 1, NetworkID: id(19), InviterTenantID: id(3), InviterAccountID: id(4), InviteeTenantID: id(20), InviteeAccountID: id(21), SourcePrincipalID: id(5), SelectedSources: []DirectAuthorizationSourceV1{{id(5), string(id(22)), string(id(23))}}, Target: DirectAuthorizationTargetV1{PrincipalID: id(24), AuthorityGeneration: string(id(25))}, ConsentVersion: 3, CommunicationProfile: "direct_ask_reply_v1", Permissions: []string{"direct_ask", "direct_reply"}, HistoryPolicy: "future_only", HolderScope: "selected_direct_channel_endpoints", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), GrantExpiresAt: now.Add(time.Hour)}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return ManagedEndpointPoPChallenge{ManagedEndpointPoPProtocol, ManagedEndpointPoPSuite, id(26), strings.Repeat("ab", 32), hex.EncodeToString(serverKey.PublicKey().Bytes()), now, now.Add(time.Minute), command, ack, receipt, snapshot, digest}, host, server
}

func TestManagedEndpointPoPGolden(t *testing.T) {
	challenge, host, server := managedPoPFixture(t)
	raw, err := challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ConfirmManagedEndpointHostCustody(challenge, host, challenge.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, _ := proof.CanonicalBytes()
	snapshot, _ := challenge.Authorization.CanonicalBytes()
	for name, got := range map[string][]byte{"challenge.json": raw, "proof.json": proofRaw, "authorization.json": snapshot} {
		path := filepath.Join("testdata", "managed_endpoint_pop_v1", name)
		if os.Getenv("UPDATE_MANAGED_POP_GOLDEN") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("golden %s: %v", name, err)
		}
	}
	decoded, err := DecodeManagedEndpointPoPChallenge(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeManagedEndpointPoPProof(proofRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDirectAuthorizationSnapshotV1(snapshot); err != nil {
		t.Fatal(err)
	}
	// Independently derive on the server side with the standard library primitives.
	serverKey, _ := ecdh.X25519().NewPrivateKey(server)
	hostKey, _ := ecdh.X25519().NewPrivateKey(host)
	shared, err := serverKey.ECDH(hostKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := decoded.transcriptHash(challenge.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(challenge.Nonce)
	key, err := hkdf.Key(sha256.New, shared, nonce, managedEndpointPoPKDF+string(transcript), 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(managedEndpointPoPConfirm))
	mac.Write(transcript)
	if hex.EncodeToString(mac.Sum(nil)) != proof.HostConfirmation {
		t.Fatal("server confirmation mismatch")
	}
	for _, purpose := range []string{"pagnet/sdk-pair/readiness/v1", managedEndpointPoPConfirm} {
		other, _ := hkdf.Key(sha256.New, shared, nonce, purpose+string(transcript), 32)
		otherMAC := hmac.New(sha256.New, other)
		otherMAC.Write([]byte(managedEndpointPoPConfirm))
		otherMAC.Write(transcript)
		if hmac.Equal(mac.Sum(nil), otherMAC.Sum(nil)) {
			t.Fatal("purpose separation")
		}
	}
	otherMAC := hmac.New(sha256.New, key)
	otherMAC.Write([]byte(managedEndpointPoPKDF))
	otherMAC.Write(transcript)
	if hmac.Equal(mac.Sum(nil), otherMAC.Sum(nil)) {
		t.Fatal("confirmation domain separation")
	}
}

func TestManagedEndpointPoPEveryFieldBound(t *testing.T) {
	p, host, _ := managedPoPFixture(t)
	raw, _ := p.CanonicalBytes()
	original, _ := ConfirmManagedEndpointHostCustody(p, host, p.IssuedAt)
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	count := 0
	var visit func(any, []any)
	visit = func(node any, path []any) {
		switch v := node.(type) {
		case map[string]any:
			for k, child := range v {
				visit(child, append(append([]any{}, path...), k))
			}
		case []any:
			for i, child := range v {
				visit(child, append(append([]any{}, path...), i))
			}
		default:
			count++
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			var container any = changed
			for _, part := range path[:len(path)-1] {
				switch key := part.(type) {
				case string:
					container = container.(map[string]any)[key]
				case int:
					container = container.([]any)[key]
				}
			}
			var replacement any = "tampered"
			switch value := v.(type) {
			case string:
				replacement = value + "x"
			case float64:
				replacement = value + 1
			}
			switch key := path[len(path)-1].(type) {
			case string:
				container.(map[string]any)[key] = replacement
			case int:
				container.([]any)[key] = replacement
			}
			altered, _ := json.Marshal(changed)
			var challenge ManagedEndpointPoPChallenge
			json.Unmarshal(altered, &challenge)
			proof, err := ConfirmManagedEndpointHostCustody(challenge, host, p.IssuedAt)
			if err == nil && proof.HostConfirmation == original.HostConfirmation {
				t.Fatalf("unbound field %v", path)
			}
		}
	}
	visit(root, nil)
	if count != 99 {
		t.Fatalf("unexpected field coverage %d", count)
	}
	t.Logf("checked %d bound leaves", count)
}

func TestManagedEndpointPoPRejects(t *testing.T) {
	p, host, _ := managedPoPFixture(t)
	for name, mutate := range map[string]func(*ManagedEndpointPoPChallenge){
		"zero": func(p *ManagedEndpointPoPChallenge) { p.ServerEphemeralX25519 = strings.Repeat("00", 32) },
		"one":  func(p *ManagedEndpointPoPChallenge) { p.ServerEphemeralX25519 = "01" + strings.Repeat("00", 31) },
		"low-order": func(p *ManagedEndpointPoPChallenge) {
			p.ServerEphemeralX25519 = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
		},
		"low-order-2": func(p *ManagedEndpointPoPChallenge) {
			p.ServerEphemeralX25519 = "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"
		},
		"p-minus-one":     func(p *ManagedEndpointPoPChallenge) { p.ServerEphemeralX25519 = "ec" + strings.Repeat("ff", 30) + "7f" },
		"p":               func(p *ManagedEndpointPoPChallenge) { p.ServerEphemeralX25519 = "ed" + strings.Repeat("ff", 30) + "7f" },
		"high-bit":        func(p *ManagedEndpointPoPChallenge) { p.ServerEphemeralX25519 = strings.Repeat("ff", 32) },
		"nonce-case":      func(p *ManagedEndpointPoPChallenge) { p.Nonce = strings.ToUpper(p.Nonce) },
		"receipt":         func(p *ManagedEndpointPoPChallenge) { p.Receipt.ReceiptDigest = strings.Repeat("ab", 32) },
		"snapshot-digest": func(p *ManagedEndpointPoPChallenge) { p.AuthorizationDigest = strings.Repeat("ab", 32) },
		"long-expiry":     func(p *ManagedEndpointPoPChallenge) { p.ExpiresAt = p.IssuedAt.Add(6 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			if _, err := ConfirmManagedEndpointHostCustody(q, host, p.IssuedAt); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, now := range []time.Time{p.IssuedAt.Add(-time.Nanosecond), p.ExpiresAt, p.ExpiresAt.Add(time.Second)} {
		if _, err := ConfirmManagedEndpointHostCustody(p, host, now); err == nil {
			t.Fatal("accepted invalid time")
		}
	}
	if _, err := ConfirmManagedEndpointHostCustody(p, bytes.Repeat([]byte{7}, 32), p.IssuedAt); err == nil {
		t.Fatal("accepted different key")
	}
	if _, err := managedEndpointPoPConfirmation(make([]byte, 32), p.Nonce, make([]byte, 32)); err == nil {
		t.Fatal("zero DH")
	}
}

func TestManagedEndpointPoPStrictJSON(t *testing.T) {
	p, host, _ := managedPoPFixture(t)
	challenge, _ := p.CanonicalBytes()
	snapshot, _ := p.Authorization.CanonicalBytes()
	proof, _ := ConfirmManagedEndpointHostCustody(p, host, p.IssuedAt)
	proofRaw, _ := proof.CanonicalBytes()
	for _, tc := range []struct {
		name   string
		raw    []byte
		decode func([]byte) bool
	}{
		{"challenge", challenge, func(b []byte) bool { _, e := DecodeManagedEndpointPoPChallenge(b); return e == nil }},
		{"snapshot", snapshot, func(b []byte) bool { _, e := DecodeDirectAuthorizationSnapshotV1(b); return e == nil }},
		{"proof", proofRaw, func(b []byte) bool { _, e := DecodeManagedEndpointPoPProof(b); return e == nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]json.RawMessage
			json.Unmarshal(tc.raw, &obj)
			var first string
			for k := range obj {
				first = k
				break
			}
			key, _ := json.Marshal(first)
			for _, bad := range [][]byte{
				append(append([]byte{}, tc.raw...), []byte("{}")...),
				append([]byte(" "), tc.raw...),
				append([]byte("{\"unknown\":null,"), tc.raw[1:]...),
				append(append(append(append([]byte("{"), key...), ':'), append(obj[first], ',')...), tc.raw[1:]...),
				bytes.Replace(tc.raw, []byte("v1"), []byte("v\\ud800"), 1),
				append([]byte("{\"bad\":\"\xff\","), tc.raw[1:]...),
				bytes.Repeat([]byte(" "), 65537),
			} {
				if tc.decode(bad) {
					t.Fatalf("accepted %q", bad)
				}
			}
			delete(obj, first)
			missing, _ := json.Marshal(obj)
			if tc.decode(missing) {
				t.Fatal("missing field")
			}
		})
	}
}

func TestDirectAuthorizationSnapshotInvariants(t *testing.T) {
	p, _, _ := managedPoPFixture(t)
	for name, mutate := range map[string]func(*DirectAuthorizationSnapshotV1){
		"duplicate-source": func(s *DirectAuthorizationSnapshotV1) {
			s.SelectedSources = append(s.SelectedSources, s.SelectedSources[0])
		},
		"no-sources":              func(s *DirectAuthorizationSnapshotV1) { s.SelectedSources = nil },
		"missing-selected-source": func(s *DirectAuthorizationSnapshotV1) { s.SourcePrincipalID = s.Target.PrincipalID },
		"unpaired-target":         func(s *DirectAuthorizationSnapshotV1) { s.Target.NetworkID = &s.NetworkID },
		"consent":                 func(s *DirectAuthorizationSnapshotV1) { s.ConsentVersion = 2 },
		"permissions":             func(s *DirectAuthorizationSnapshotV1) { s.Permissions = []string{"direct_reply", "direct_ask"} },
		"grant-expiry":            func(s *DirectAuthorizationSnapshotV1) { s.GrantExpiresAt = s.CreatedAt },
		"empty-time-range":        func(s *DirectAuthorizationSnapshotV1) { s.ExpiresAt = s.CreatedAt },
	} {
		t.Run(name, func(t *testing.T) {
			s := p.Authorization
			mutate(&s)
			if _, err := s.CanonicalBytes(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	s := p.Authorization
	generation := s.Target.AuthorityGeneration
	s.Target.NetworkID = &s.NetworkID
	s.Target.MembershipAuthorityGeneration = &generation
	raw, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDirectAuthorizationSnapshotV1(raw); err != nil {
		t.Fatal(err)
	}
}

func TestManagedEndpointPoPValidTranscriptChanges(t *testing.T) {
	p, host, _ := managedPoPFixture(t)
	original, _ := ConfirmManagedEndpointHostCustody(p, host, p.IssuedAt)
	for name, mutate := range map[string]func(*ManagedEndpointPoPChallenge){
		"nonce":     func(p *ManagedEndpointPoPChallenge) { p.Nonce = strings.Repeat("cd", 32) },
		"challenge": func(p *ManagedEndpointPoPChallenge) { p.ChallengeID = p.Authorization.ProposalID },
		"snapshot": func(p *ManagedEndpointPoPChallenge) {
			p.Authorization.GrantGeneration++
			p.AuthorizationDigest, _ = p.Authorization.Digest()
		},
		"host-incarnation": func(p *ManagedEndpointPoPChallenge) {
			p.Prepare.Subject.BootID = "other-boot"
			p.ACK.Reservation.Subject = p.Prepare.Subject
			p.ACK.Reservation.EnrollmentDigest, _ = p.ACK.Reservation.Digest()
			p.Receipt, _ = NewManagedEndpointPrepareReceiptReference(p.ACK)
		},
		"expiry": func(p *ManagedEndpointPoPChallenge) { p.ExpiresAt = p.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			changed, err := ConfirmManagedEndpointHostCustody(q, host, p.IssuedAt)
			if err != nil {
				t.Fatal(err)
			}
			if changed.HostConfirmation == original.HostConfirmation {
				t.Fatal("unchanged confirmation")
			}
		})
	}
	raw, _ := p.Receipt.CanonicalBytes()
	if _, err := DecodeManagedEndpointPrepareReceiptReference(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManagedEndpointPrepareReceiptReference(bytes.Replace(raw, []byte("receiptDigest"), []byte("other"), 1)); err == nil {
		t.Fatal("receipt unknown field")
	}
}

// RFC7748 section 6.1 Alice/Bob vector also fixes the underlying DH primitive.
func TestManagedEndpointPoPRFC7748(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	private, err := ecdh.X25519().NewPrivateKey(decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.X25519().NewPublicKey(decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(shared) != "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" {
		t.Fatal("RFC7748 vector mismatch")
	}
}
