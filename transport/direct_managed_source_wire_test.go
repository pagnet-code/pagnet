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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func directManagedSourceFixture(t *testing.T) (DirectManagedSourcePoPChallenge, []byte, []byte) {
	t.Helper()
	id := func(n byte) domain.ID {
		return domain.ID("20000000-0000-4000-8000-0000000000" + hex.EncodeToString([]byte{n}))
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	subject := DirectManagedSourceBindingV1{
		ID: id(1), DirectIntentID: id(2), ProtocolVersion: DirectManagedSourceBindingProtocol,
		TenantID: id(3), AccountID: id(4), OwnershipScope: "personal", PrincipalID: id(5),
		EndpointID: id(6), InstanceID: id(7), OriginID: id(8), NativeGeneration: "native-generation", NativeSessionID: "native-session",
		OwnershipID: id(9), OwnershipGeneration: "ownership-generation", NativeAdmissionID: id(10), ConnectionIncarnationID: id(10),
		HostID: id(11), HostCredentialID: id(12), RunnerID: id(13), RunnerConnectedAt: now.Add(-time.Minute), BootID: "source-boot",
		BindingGeneration: 1, State: "pending_closed", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Role: "S", ProposalID: id(17), ProposalVersion: 3, GrantID: id(18), GrantGeneration: 1, NetworkID: id(19),
		SourcePrincipalID: id(5), TargetPrincipalID: id(24), SourceAuthorityGeneration: string(id(22)),
		SourceMembershipAuthorityGeneration: string(id(23)), TargetAuthorityGeneration: string(id(25)),
		BudgetID: id(27), BudgetAcceptedRevision: 2, BudgetTermsDigest: strings.Repeat("cd", 32),
	}
	host, server := bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x42}, 32)
	hostKey, _ := ecdh.X25519().NewPrivateKey(host)
	serverKey, _ := ecdh.X25519().NewPrivateKey(server)
	command := DirectManagedSourcePrepareCommand{DirectManagedSourcePrepareProtocol, id(14), subject}
	reservation := DirectManagedSourceKeyReservation{Subject: subject, ServerURL: "https://server.example", InstallationID: id(15), KeyGeneration: 1, X25519: hex.EncodeToString(hostKey.PublicKey().Bytes())}
	var err error
	reservation.EnrollmentDigest, err = reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ack := DirectManagedSourcePrepareACK{DirectManagedSourcePrepareProtocol, command.CommandID, reservation}
	receipt, err := NewDirectManagedSourcePrepareReceiptReference(ack)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return DirectManagedSourcePoPChallenge{DirectManagedSourcePoPProtocol, DirectManagedSourcePoPSuite, id(26), strings.Repeat("ab", 32), hex.EncodeToString(serverKey.PublicKey().Bytes()), now, now.Add(time.Minute), command, ack, receipt, digest}, host, server
}

func TestDirectManagedSourceGolden(t *testing.T) {
	p, host, server := directManagedSourceFixture(t)
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := p.Prepare.Subject.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ConfirmDirectManagedSourceHostCustody(p, host, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, err := proof.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	transcript, digest, err := DeriveDirectManagedSourcePoPVerifier(p, server, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, got, err := DecodeDirectManagedSourcePoPProofVerifier(proofRaw)
	if err != nil || decoded != proof || transcript != proof.TranscriptHash || got != digest {
		t.Fatal("host/server verifier mismatch", err)
	}
	for name, got := range map[string][]byte{"binding.json": binding, "challenge.json": raw, "proof.json": proofRaw, "verifier_digest.txt": []byte(digest), "binding_digest.txt": []byte(p.SourceBindingDigest)} {
		path := filepath.Join("testdata", "direct_managed_source_v1", name)
		if os.Getenv("UPDATE_DIRECT_MANAGED_SOURCE_GOLDEN") == "1" {
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
	// Reconstruct the transcript and server response using only public standard-library primitives.
	sum := sha256.Sum256(append([]byte("pagnet/direct-managed-source-host-custody-pop/transcript/v1/"), raw...))
	if hex.EncodeToString(sum[:]) != transcript {
		t.Fatal("transcript domain mismatch")
	}
	serverKey, _ := ecdh.X25519().NewPrivateKey(server)
	hostKey, _ := ecdh.X25519().NewPrivateKey(host)
	shared, err := serverKey.ECDH(hostKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(p.Nonce)
	key, err := hkdf.Key(sha256.New, shared, nonce, "pagnet/direct-managed-source-host-custody-pop/kdf/v1/"+string(sum[:]), 32)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pagnet/direct-managed-source-host-custody-pop/host-confirm/v1/"))
	mac.Write(sum[:])
	if hex.EncodeToString(mac.Sum(nil)) != proof.HostConfirmation {
		t.Fatal("independent confirmation mismatch")
	}
	verifier := sha256.New()
	verifier.Write([]byte("pagnet/direct-managed-source-host-custody-pop/verifier/v1/"))
	verifier.Write(sum[:])
	verifier.Write(mac.Sum(nil))
	if hex.EncodeToString(verifier.Sum(nil)) != digest {
		t.Fatal("independent verifier mismatch")
	}
	ackRaw, _ := p.ACK.CanonicalBytes()
	receiptSum := sha256.Sum256(ackRaw)
	if p.Receipt.ReceiptDigest != hex.EncodeToString(receiptSum[:]) {
		t.Fatal("receipt must hash complete canonical ACK without prefix")
	}
	wantReceipt := `{"bindingId":"` + string(p.Prepare.Subject.ID) + `","commandId":"` + string(p.Prepare.CommandID) + `","receiptDigest":"` + p.Receipt.ReceiptDigest + `"}`
	receiptRaw, _ := p.Receipt.CanonicalBytes()
	if string(receiptRaw) != wantReceipt {
		t.Fatal("source receipt shape changed")
	}
}

func TestDirectManagedSourceBindingInvariants(t *testing.T) {
	p, _, _ := directManagedSourceFixture(t)
	for name, mutate := range map[string]func(*DirectManagedSourceBindingV1){
		"role":                  func(s *DirectManagedSourceBindingV1) { s.Role = "P" },
		"principal":             func(s *DirectManagedSourceBindingV1) { s.PrincipalID = s.TargetPrincipalID },
		"proposal-version":      func(s *DirectManagedSourceBindingV1) { s.ProposalVersion = 0 },
		"grant-generation":      func(s *DirectManagedSourceBindingV1) { s.GrantGeneration = 0 },
		"budget-revision":       func(s *DirectManagedSourceBindingV1) { s.BudgetAcceptedRevision = 0 },
		"budget-digest":         func(s *DirectManagedSourceBindingV1) { s.BudgetTermsDigest = strings.ToUpper(s.BudgetTermsDigest) },
		"budget-id":             func(s *DirectManagedSourceBindingV1) { s.BudgetID = "" },
		"source-generation":     func(s *DirectManagedSourceBindingV1) { s.SourceAuthorityGeneration = "generation" },
		"membership-generation": func(s *DirectManagedSourceBindingV1) { s.SourceMembershipAuthorityGeneration = "" },
		"target-generation":     func(s *DirectManagedSourceBindingV1) { s.TargetAuthorityGeneration = "" },
		"protocol":              func(s *DirectManagedSourceBindingV1) { s.ProtocolVersion = ManagedEndpointBindingProtocol },
		"scope":                 func(s *DirectManagedSourceBindingV1) { s.OwnershipScope = "network" },
		"state":                 func(s *DirectManagedSourceBindingV1) { s.State = "active" },
		"binding-generation":    func(s *DirectManagedSourceBindingV1) { s.BindingGeneration = 2 },
		"connection":            func(s *DirectManagedSourceBindingV1) { s.ConnectionIncarnationID = s.HostID },
		"native-generation":     func(s *DirectManagedSourceBindingV1) { s.NativeGeneration = "" },
		"time":                  func(s *DirectManagedSourceBindingV1) { s.RunnerConnectedAt = time.Time{} },
		"expiry":                func(s *DirectManagedSourceBindingV1) { s.ExpiresAt = s.CreatedAt },
		"lifetime":              func(s *DirectManagedSourceBindingV1) { s.ExpiresAt = s.CreatedAt.Add(5*time.Minute + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			s := p.Prepare.Subject
			mutate(&s)
			if _, err := s.CanonicalBytes(); err == nil {
				t.Fatal("accepted invalid source subject")
			}
		})
	}
	revision := p.Prepare.Subject
	revision.ProposalVersion = 2
	if _, err := revision.CanonicalBytes(); err != nil {
		t.Fatal("positive proposal revision rejected", err)
	}
	original, _ := p.Prepare.Subject.CanonicalBytes()
	s := p.Prepare.Subject
	s.CreatedAt = s.CreatedAt.In(time.FixedZone("offset", 3600))
	s.ExpiresAt = s.ExpiresAt.In(time.FixedZone("offset", 3600))
	s.RunnerConnectedAt = s.RunnerConnectedAt.In(time.FixedZone("offset", 3600))
	normalized, _ := s.CanonicalBytes()
	if !bytes.Equal(original, normalized) {
		t.Fatal("UTC normalization changed subject")
	}
}

func TestDirectManagedSourcePrepareBindsEverySubjectField(t *testing.T) {
	p, _, _ := directManagedSourceFixture(t)
	raw, err := p.ACK.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDirectManagedSourcePrepareACK(raw, p.Prepare); err != nil {
		t.Fatal(err)
	}
	// Every retained subject field must compare equal even when an alternate subject remains valid.
	subject := reflect.ValueOf(p.Prepare.Subject)
	for i := 0; i < subject.NumField(); i++ {
		t.Run(subject.Type().Field(i).Name, func(t *testing.T) {
			expected := p.Prepare
			field := reflect.ValueOf(&expected.Subject).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				field.SetString(field.String() + "x")
			case reflect.Int64:
				field.SetInt(field.Int() + 1)
			case reflect.Struct:
				field.Set(reflect.ValueOf(field.Interface().(time.Time).Add(time.Nanosecond)))
			}
			if _, err := DecodeDirectManagedSourcePrepareACK(raw, expected); err == nil {
				t.Fatal("accepted cross-subject ACK")
			}
		})
	}

	for name, mutate := range map[string]func(*DirectManagedSourceBindingV1){
		"binding-id": func(s *DirectManagedSourceBindingV1) { s.ID = s.ProposalID },
		"source-identity": func(s *DirectManagedSourceBindingV1) {
			s.SourcePrincipalID = s.TargetPrincipalID
			s.PrincipalID = s.TargetPrincipalID
		},
		"authority": func(s *DirectManagedSourceBindingV1) { s.SourceAuthorityGeneration = s.TargetAuthorityGeneration },
		"membership": func(s *DirectManagedSourceBindingV1) {
			s.SourceMembershipAuthorityGeneration = s.TargetAuthorityGeneration
		},
		"budget":   func(s *DirectManagedSourceBindingV1) { s.BudgetID = s.ProposalID; s.BudgetAcceptedRevision++ },
		"proposal": func(s *DirectManagedSourceBindingV1) { s.ProposalVersion++ },
		"grant":    func(s *DirectManagedSourceBindingV1) { s.GrantGeneration++ },
		"boot":     func(s *DirectManagedSourceBindingV1) { s.BootID = "new-boot" },
	} {
		t.Run("valid-cross-binding-"+name, func(t *testing.T) {
			expected := p.Prepare
			mutate(&expected.Subject)
			if _, err := expected.CanonicalBytes(); err != nil {
				t.Fatal("invalid alternate subject", err)
			}
			if _, err := DecodeDirectManagedSourcePrepareACK(raw, expected); err == nil {
				t.Fatal("accepted ACK for different valid subject")
			}
			ack := p.ACK
			ack.Reservation.Subject = expected.Subject
			ack.Reservation.EnrollmentDigest, err = ack.Reservation.Digest()
			if err != nil {
				t.Fatal(err)
			}
			otherRaw, err := ack.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeDirectManagedSourcePrepareACK(otherRaw, p.Prepare); err == nil {
				t.Fatal("accepted recomputed ACK for different subject")
			}
		})
	}
	expected := p.Prepare
	expected.CommandID = p.Prepare.Subject.ProposalID
	if _, err := DecodeDirectManagedSourcePrepareACK(raw, expected); err == nil {
		t.Fatal("accepted cross-command ACK")
	}
	reservation := p.ACK.Reservation
	reservation.Subject.BootID = "new-boot"
	if err := reservation.VerifySubject(p.Prepare.Subject); err == nil {
		t.Fatal("accepted changed reservation subject")
	}
}

func TestDirectManagedSourceStrictJSON(t *testing.T) {
	p, host, _ := directManagedSourceFixture(t)
	proof, _ := ConfirmDirectManagedSourceHostCustody(p, host, p.IssuedAt)
	popFailure := DirectManagedSourcePoPFailureACK{DirectManagedSourcePoPProtocol, p.ChallengeID, DirectManagedSourcePoPFailure}
	prepareFailure := DirectManagedSourcePrepareFailureACK{DirectManagedSourcePrepareProtocol, p.Prepare.CommandID, DirectManagedSourcePrepareFailure}
	cases := []struct {
		name   string
		value  interface{ CanonicalBytes() ([]byte, error) }
		decode func([]byte) error
	}{
		{"binding", p.Prepare.Subject, func(b []byte) error { _, e := DecodeDirectManagedSourceBindingV1(b); return e }},
		{"reservation", p.ACK.Reservation, func(b []byte) error { _, e := DecodeDirectManagedSourceKeyReservation(b); return e }},
		{"prepare", p.Prepare, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareCommand(b); return e }},
		{"ack", p.ACK, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareACK(b, p.Prepare); return e }},
		{"receipt", p.Receipt, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareReceiptReference(b); return e }},
		{"challenge", p, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPChallenge(b); return e }},
		{"proof", proof, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPProof(b); return e }},
		{"proof-verifier", proof, func(b []byte) error { _, _, e := DecodeDirectManagedSourcePoPProofVerifier(b); return e }},
		{"prepare-failure", prepareFailure, func(b []byte) error {
			_, e := DecodeDirectManagedSourcePrepareFailureACK(b, p.Prepare.CommandID)
			return e
		}},
		{"pop-failure", popFailure, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPFailureACK(b, p.ChallengeID); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.decode(raw); err != nil {
				t.Fatal("canonical round trip", err)
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			var first string
			for key := range fields {
				first = key
				break
			}
			key, _ := json.Marshal(first)
			duplicate := append([]byte("{"), key...)
			duplicate = append(duplicate, ':')
			duplicate = append(duplicate, fields[first]...)
			duplicate = append(duplicate, ',')
			duplicate = append(duplicate, raw[1:]...)
			for name, bad := range map[string][]byte{
				"whitespace": append([]byte(" "), raw...), "trailing": append(append([]byte{}, raw...), []byte("{}")...),
				"unknown": append([]byte(`{"unknown":null,`), raw[1:]...), "duplicate": duplicate,
				"case-field":    bytes.Replace(raw, key, []byte(`"`+strings.ToUpper(first)+`"`), 1),
				"escaped-field": bytes.Replace(raw, key, []byte(`"\u`+hex.EncodeToString([]byte{0, first[0]})+first[1:]+`"`), 1),
				"null":          bytes.Replace(raw, fields[first], []byte("null"), 1), "oversize": bytes.Repeat([]byte(" "), 65537),
				"utf8": append([]byte("{\"bad\":\"\xff\","), raw[1:]...),
			} {
				t.Run(name, func(t *testing.T) {
					if tc.decode(bad) == nil {
						t.Fatal("accepted noncanonical JSON")
					}
				})
			}
			delete(fields, first)
			missing, _ := json.Marshal(fields)
			if tc.decode(missing) == nil {
				t.Fatal("accepted missing field")
			}
		})
	}
	raw, _ := p.CanonicalBytes()
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","role":"S"`), 1),
		bytes.Replace(raw, []byte(`"bootId":"source-boot"`), []byte(`"bootId":"\ud800"`), 1),
		bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","authorization":{}`), 1),
	} {
		if _, err := DecodeDirectManagedSourcePoPChallenge(bad); err == nil {
			t.Fatal("accepted ambiguous nested source evidence")
		}
	}
}

func TestDirectManagedSourcePoPRejects(t *testing.T) {
	p, host, server := directManagedSourceFixture(t)
	for name, key := range map[string]string{
		"zero": strings.Repeat("00", 32), "one": "01" + strings.Repeat("00", 31),
		"low-order":   "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"low-order-2": "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"p-minus-one": "ec" + strings.Repeat("ff", 30) + "7f", "p": "ed" + strings.Repeat("ff", 30) + "7f", "high-bit": strings.Repeat("ff", 32),
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.ServerEphemeralX25519 = key
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted invalid server public key")
			}
			if _, err := ConfirmDirectManagedSourceHostCustody(q, host, p.IssuedAt); err == nil {
				t.Fatal("confirmed invalid server key")
			}
			r := p.ACK.Reservation
			r.X25519 = key
			if _, err := r.Digest(); err == nil {
				t.Fatal("accepted invalid host public key")
			}
		})
	}
	for name, mutate := range map[string]func(*DirectManagedSourcePoPChallenge){
		"nonce-case":      func(q *DirectManagedSourcePoPChallenge) { q.Nonce = strings.ToUpper(q.Nonce) },
		"receipt":         func(q *DirectManagedSourcePoPChallenge) { q.Receipt.ReceiptDigest = strings.Repeat("ab", 32) },
		"receipt-binding": func(q *DirectManagedSourcePoPChallenge) { q.Receipt.BindingID = q.Prepare.Subject.ProposalID },
		"receipt-command": func(q *DirectManagedSourcePoPChallenge) { q.Receipt.CommandID = q.Prepare.Subject.ProposalID },
		"binding-digest":  func(q *DirectManagedSourcePoPChallenge) { q.SourceBindingDigest = strings.Repeat("ab", 32) },
		"cross-binding":   func(q *DirectManagedSourcePoPChallenge) { q.Prepare.Subject.BootID = "other-boot" },
		"long-expiry":     func(q *DirectManagedSourcePoPChallenge) { q.ExpiresAt = q.IssuedAt.Add(6 * time.Minute) },
		"outside-binding": func(q *DirectManagedSourcePoPChallenge) {
			q.IssuedAt = q.Prepare.Subject.CreatedAt.Add(-time.Nanosecond)
		},
		"after-binding": func(q *DirectManagedSourcePoPChallenge) {
			q.IssuedAt = q.Prepare.Subject.ExpiresAt.Add(-time.Second)
			q.ExpiresAt = q.Prepare.Subject.ExpiresAt.Add(time.Nanosecond)
		},
		"empty-interval": func(q *DirectManagedSourcePoPChallenge) { q.ExpiresAt = q.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			if _, err := ConfirmDirectManagedSourceHostCustody(q, host, p.IssuedAt); err == nil {
				t.Fatal("confirmed invalid challenge")
			}
			if _, _, err := DeriveDirectManagedSourcePoPVerifier(q, server, p.IssuedAt); err == nil {
				t.Fatal("derived invalid challenge verifier")
			}
		})
	}
	for _, now := range []time.Time{p.IssuedAt.Add(-time.Nanosecond), p.ExpiresAt, p.ExpiresAt.Add(time.Second)} {
		if _, err := ConfirmDirectManagedSourceHostCustody(p, host, now); err == nil {
			t.Fatal("confirmed outside validity interval")
		}
		if _, _, err := DeriveDirectManagedSourcePoPVerifier(p, server, now); err == nil {
			t.Fatal("derived outside validity interval")
		}
	}
	for name, key := range map[string][]byte{"nil": nil, "short": make([]byte, 31), "long": make([]byte, 33), "different": bytes.Repeat([]byte{7}, 32)} {
		t.Run("private-"+name, func(t *testing.T) {
			if _, err := ConfirmDirectManagedSourceHostCustody(p, key, p.IssuedAt); err == nil {
				t.Fatal("confirmed with wrong host key")
			}
			transcript, digest, err := DeriveDirectManagedSourcePoPVerifier(p, key, p.IssuedAt)
			if err == nil || transcript != "" || digest != "" {
				t.Fatal("derived with wrong server key")
			}
		})
	}
}

func TestDirectManagedSourcePoPEveryLeafBound(t *testing.T) {
	p, host, _ := directManagedSourceFixture(t)
	raw, _ := p.CanonicalBytes()
	original, err := ConfirmDirectManagedSourceHostCustody(p, host, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	json.Unmarshal(raw, &root)
	count := 0
	var visit func(map[string]any, []string)
	visit = func(node map[string]any, path []string) {
		for field, value := range node {
			next := append(append([]string{}, path...), field)
			if child, ok := value.(map[string]any); ok {
				visit(child, next)
				continue
			}
			count++
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			container := changed
			for _, key := range next[:len(next)-1] {
				container = container[key].(map[string]any)
			}
			switch v := value.(type) {
			case string:
				container[field] = v + "x"
			case float64:
				container[field] = v + 1
			default:
				t.Fatalf("unhandled leaf %v", next)
			}
			altered, _ := json.Marshal(changed)
			var q DirectManagedSourcePoPChallenge
			json.Unmarshal(altered, &q)
			proof, err := ConfirmDirectManagedSourceHostCustody(q, host, p.IssuedAt)
			if err == nil && proof.HostConfirmation == original.HostConfirmation {
				t.Fatalf("unbound field %v", next)
			}
		}
	}
	visit(root, nil)
	// This fixed count detects accidentally removing any source consent/budget field.
	if count != 98 {
		t.Fatalf("unexpected source leaf coverage %d", count)
	}
}

func TestDirectManagedSourcePoPRetryAndTamper(t *testing.T) {
	p, host, server := directManagedSourceFixture(t)
	original, err := ConfirmDirectManagedSourceHostCustody(p, host, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	transcript, digest, err := DeriveDirectManagedSourcePoPVerifier(p, server, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := ConfirmDirectManagedSourceHostCustody(p, host, p.IssuedAt.Add(time.Second))
	if err != nil || repeated != original {
		t.Fatal("identical live retry changed proof", err)
	}
	for name, mutate := range map[string]func(*DirectManagedSourcePoPChallenge){
		"nonce":     func(q *DirectManagedSourcePoPChallenge) { q.Nonce = strings.Repeat("cd", 32) },
		"challenge": func(q *DirectManagedSourcePoPChallenge) { q.ChallengeID = q.Prepare.Subject.ProposalID },
		"expiry":    func(q *DirectManagedSourcePoPChallenge) { q.ExpiresAt = q.ExpiresAt.Add(-time.Second) },
		"budget":    func(q *DirectManagedSourcePoPChallenge) { q.Prepare.Subject.BudgetAcceptedRevision++ },
		"grant":     func(q *DirectManagedSourcePoPChallenge) { q.Prepare.Subject.GrantGeneration++ },
		"source-generation": func(q *DirectManagedSourcePoPChallenge) {
			q.Prepare.Subject.SourceAuthorityGeneration = q.Prepare.Subject.TargetAuthorityGeneration
		},
		"host-incarnation": func(q *DirectManagedSourcePoPChallenge) { q.Prepare.Subject.BootID = "new-boot" },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			q.ACK.Reservation.Subject = q.Prepare.Subject
			q.ACK.Reservation.EnrollmentDigest, _ = q.ACK.Reservation.Digest()
			q.Receipt, _ = NewDirectManagedSourcePrepareReceiptReference(q.ACK)
			q.SourceBindingDigest, _ = q.Prepare.Subject.Digest()
			proof, err := ConfirmDirectManagedSourceHostCustody(q, host, p.IssuedAt)
			if err != nil {
				t.Fatal(err)
			}
			changedTranscript, changedDigest, err := DeriveDirectManagedSourcePoPVerifier(q, server, p.IssuedAt)
			if err != nil || proof.HostConfirmation == original.HostConfirmation || changedTranscript == transcript || changedDigest == digest {
				t.Fatal("fresh transcript reused old proof", err)
			}
		})
	}
	for name, mutate := range map[string]func(*DirectManagedSourcePoPProof){
		"challenge":    func(q *DirectManagedSourcePoPProof) { q.ChallengeID = p.Prepare.Subject.ProposalID },
		"transcript":   func(q *DirectManagedSourcePoPProof) { q.TranscriptHash = strings.Repeat("ab", 32) },
		"confirmation": func(q *DirectManagedSourcePoPProof) { q.HostConfirmation = strings.Repeat("ab", 32) },
	} {
		t.Run("proof-"+name, func(t *testing.T) {
			q := original
			mutate(&q)
			raw, _ := q.CanonicalBytes()
			got, verifier, err := DecodeDirectManagedSourcePoPProofVerifier(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.ChallengeID == p.ChallengeID && got.TranscriptHash == transcript && verifier == digest {
				t.Fatal("tampered proof matched retained server state")
			}
		})
	}
}

func TestDirectManagedSourceFailureAndEnvelope(t *testing.T) {
	p, _, _ := directManagedSourceFixture(t)
	if MsgDirectManagedSourcePrepare != "host.direct_managed_source_prepare" || MsgDirectManagedSourcePoP != "host.direct_managed_source_pop" {
		t.Fatal("source message names changed")
	}
	raw, _ := p.CanonicalBytes()
	envelope, err := NewEnvelope(MsgDirectManagedSourcePoP, p)
	if err != nil || envelope.Type != MsgDirectManagedSourcePoP || !bytes.Equal(envelope.Payload, raw) {
		t.Fatal("PoP challenge must be direct payload", err)
	}
	failure := DirectManagedSourcePoPFailureACK{DirectManagedSourcePoPProtocol, p.ChallengeID, DirectManagedSourcePoPFailure}
	failureRaw, _ := failure.CanonicalBytes()
	if _, err := DecodeDirectManagedSourcePoPProof(failureRaw); err == nil {
		t.Fatal("failure accepted as proof")
	}
	if _, err := DecodeDirectManagedSourcePoPFailureACK(failureRaw, p.Prepare.Subject.ID); err == nil {
		t.Fatal("failure accepted wrong challenge")
	}
	if _, err := DecodeDirectManagedSourcePoPFailureACK(bytes.Replace(failureRaw, []byte(DirectManagedSourcePoPFailure), []byte("diagnostic detail"), 1), p.ChallengeID); err == nil {
		t.Fatal("failure accepted arbitrary diagnostic")
	}
	prepare := DirectManagedSourcePrepareFailureACK{DirectManagedSourcePrepareProtocol, p.Prepare.CommandID, DirectManagedSourcePrepareFailure}
	prepareRaw, _ := prepare.CanonicalBytes()
	if _, err := DecodeDirectManagedSourcePrepareACK(prepareRaw, p.Prepare); err == nil {
		t.Fatal("failure accepted as success ACK")
	}
	if _, err := DecodeDirectManagedSourcePrepareFailureACK(prepareRaw, p.Prepare.Subject.ID); err == nil {
		t.Fatal("failure accepted wrong command")
	}
}
