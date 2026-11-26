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
)

// Convert public v1 fixture fields, then construct independent v2 evidence.
func directManagedSourceFixtureV2(t *testing.T) (DirectManagedSourceCredentialIssueV2, []byte, []byte, []byte) {
	t.Helper()
	old, host, popServer := directManagedSourceFixture(t)
	raw, err := json.Marshal(old.Prepare.Subject)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "bindingGeneration")
	delete(fields, "expiresAt")
	raw, _ = json.Marshal(fields)
	var subject DirectManagedSourceBindingV2
	if err := json.Unmarshal(raw, &subject); err != nil {
		t.Fatal(err)
	}
	subject.ProtocolVersion = DirectManagedSourceBindingProtocolV2
	subject.BindingGeneration = "1"
	subject.EnrollmentExpiresAt = old.Prepare.Subject.ExpiresAt
	subject.AuthorizationExpiresAt = subject.CreatedAt.Add(time.Hour)
	command := DirectManagedSourcePrepareCommandV2{DirectManagedSourcePrepareProtocolV2, old.Prepare.CommandID, subject}
	reservation := DirectManagedSourceKeyReservationV2{Subject: subject, ServerURL: old.ACK.Reservation.ServerURL, InstallationID: old.ACK.Reservation.InstallationID, KeyGeneration: 1, X25519: old.ACK.Reservation.X25519}
	reservation.EnrollmentDigest, err = reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ack := DirectManagedSourcePrepareACKV2{DirectManagedSourcePrepareProtocolV2, command.CommandID, reservation}
	receipt, err := NewDirectManagedSourcePrepareReceiptReferenceV2(ack)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	pop := DirectManagedSourcePoPChallengeV2{DirectManagedSourcePoPProtocolV2, DirectManagedSourcePoPSuiteV2, old.ChallengeID, old.Nonce, old.ServerEphemeralX25519, old.IssuedAt, old.ExpiresAt, command, ack, receipt, digest}
	proof, err := ConfirmDirectManagedSourceHostCustodyV2(pop, host, pop.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	server := bytes.Repeat([]byte{0x53}, 32)
	key, _ := ecdh.X25519().NewPrivateKey(server)
	oldIssue, _, _ := sourceCredentialFixture(t)
	issue, err := NewDirectManagedSourceCredentialIssueV2(DirectManagedSourceCredentialIssueV2{CredentialID: oldIssue.CredentialID, ChannelGeneration: "1", Nonce: oldIssue.Nonce, ServerEphemeralX25519: hex.EncodeToString(key.PublicKey().Bytes()), IssuedAt: pop.IssuedAt, InstallExpiresAt: subject.EnrollmentExpiresAt, CredentialExpiresAt: subject.CreatedAt.Add(30 * time.Minute), BudgetExpiresAt: subject.AuthorizationExpiresAt}, pop, proof)
	if err != nil {
		t.Fatal(err)
	}
	return issue, host, popServer, server
}

func sourceDigestV2(domain string, parts ...[]byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestDirectManagedSourceGoldenV2(t *testing.T) {
	issue, host, popServer, server := directManagedSourceFixtureV2(t)
	defer clear(host)
	defer clear(popServer)
	defer clear(server)
	pop := issue.PoP
	raw, _ := issue.CanonicalBytes()
	popRaw, _ := pop.CanonicalBytes()
	proof, err := ConfirmDirectManagedSourceHostCustodyV2(pop, host, pop.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, _ := proof.CanonicalBytes()
	popTH, popVerifier, err := DeriveDirectManagedSourcePoPVerifierV2(pop, popServer, pop.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	_, gotPopVerifier, err := DecodeDirectManagedSourcePoPProofVerifierV2(proofRaw)
	if err != nil || gotPopVerifier != popVerifier {
		t.Fatal("PoP verifier mismatch", err)
	}
	secret, ack, err := DeriveDirectManagedSourceCredentialHostV2(issue, host, issue.InstallExpiresAt.Add(-time.Nanosecond))
	if err != nil {
		t.Fatal("installation must remain valid after PoP expiry", err)
	}
	defer clear(secret)
	ackRaw, _ := ack.CanonicalBytes()
	th, hash, verifier, err := DeriveDirectManagedSourceCredentialVerifierV2(issue, server, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	_, gotVerifier, err := DecodeDirectManagedSourceCredentialACKVerifierV2(ackRaw)
	if err != nil || gotVerifier != verifier {
		t.Fatal("credential verifier mismatch", err)
	}
	gotHash, err := DirectManagedSourceCredentialHashV2(th, secret)
	if err != nil || gotHash != hash {
		t.Fatal("credential hash mismatch", err)
	}
	// Derive both protocols independently with literal domains and standard crypto.
	derive := func(server []byte, nonce, transcript, purpose string) []byte {
		sk, _ := ecdh.X25519().NewPrivateKey(server)
		hk, _ := ecdh.X25519().NewPrivateKey(host)
		shared, err := sk.ECDH(hk.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(shared)
		salt, _ := hex.DecodeString(nonce)
		tr, _ := hex.DecodeString(transcript)
		key, err := hkdf.Key(sha256.New, shared, salt, purpose+string(tr), 32)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	mac := func(key []byte, domain, transcript string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(domain))
		tr, _ := hex.DecodeString(transcript)
		h.Write(tr)
		return h.Sum(nil)
	}
	wantPopTH := sourceDigestV2("pagnet/direct-managed-source-host-custody-pop/transcript/v2/", popRaw)
	popKey := derive(popServer, pop.Nonce, wantPopTH, "pagnet/direct-managed-source-host-custody-pop/kdf/v2/")
	defer clear(popKey)
	popConfirmation := mac(popKey, "pagnet/direct-managed-source-host-custody-pop/host-confirm/v2/", wantPopTH)
	popTranscript, _ := hex.DecodeString(wantPopTH)
	if popTH != wantPopTH || proof.HostConfirmation != hex.EncodeToString(popConfirmation) || popVerifier != sourceDigestV2("pagnet/direct-managed-source-host-custody-pop/verifier/v2/", popTranscript, popConfirmation) {
		t.Fatal("independent PoP derivation mismatch")
	}
	wantTH := sourceDigestV2("pagnet/direct-managed-source-credential/transcript/v2/", raw)
	wantSecret := derive(server, issue.Nonce, wantTH, "pagnet/direct-managed-source-credential/credential-secret/v2/")
	defer clear(wantSecret)
	install := derive(server, issue.Nonce, wantTH, "pagnet/direct-managed-source-credential/install-key/v2/")
	defer clear(install)
	confirmation := mac(install, "pagnet/direct-managed-source-credential/host-install/v2/", wantTH)
	transcript, _ := hex.DecodeString(wantTH)
	if th != wantTH || !hmac.Equal(secret, wantSecret) || ack.HostConfirmation != hex.EncodeToString(confirmation) || hash != sourceDigestV2("pagnet/direct-managed-source-credential/credential-hash/v2/", transcript, wantSecret) || verifier != sourceDigestV2("pagnet/direct-managed-source-credential/install-verifier/v2/", transcript, confirmation) {
		t.Fatal("independent credential derivation mismatch")
	}
	binding, _ := pop.Prepare.Subject.CanonicalBytes()
	prepareACK, _ := pop.ACK.CanonicalBytes()
	if pop.SourceBindingDigest != sourceDigestV2("pagnet/direct-managed-source-binding/v2/", binding) || pop.Receipt.ReceiptDigest != sourceDigestV2("pagnet/direct-managed-source-prepare/receipt/v2/", prepareACK) || issue.PoPReceipt.ProofDigest != sourceDigestV2("pagnet/direct-managed-source-host-custody-pop/proof/v2/", proofRaw) {
		t.Fatal("evidence domain mismatch")
	}
	reservation := pop.ACK.Reservation
	reservation.EnrollmentDigest = ""
	reservationRaw, _ := json.Marshal(reservation)
	if pop.ACK.Reservation.EnrollmentDigest != sourceDigestV2("pagnet/closed-direct-managed-source-key/v2/", reservationRaw) {
		t.Fatal("reservation domain mismatch")
	}
	for name, got := range map[string][]byte{"binding.json": binding, "challenge.json": popRaw, "proof.json": proofRaw, "issue.json": raw, "ack.json": ackRaw, "pop_verifier.txt": []byte(popVerifier), "transcript_hash.txt": []byte(th), "credential_hash.txt": []byte(hash), "install_verifier.txt": []byte(verifier)} {
		path := filepath.Join("testdata", "direct_managed_source_v2", name)
		if os.Getenv("UPDATE_DIRECT_MANAGED_SOURCE_V2_GOLDEN") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("golden %s mismatch: %v", name, err)
		}
	}
}

func TestDirectManagedSourceStrictRoundTripV2(t *testing.T) {
	issue, host, _, _ := directManagedSourceFixtureV2(t)
	pop := issue.PoP
	proof, _ := ConfirmDirectManagedSourceHostCustodyV2(pop, host, pop.IssuedAt)
	secret, ack, err := DeriveDirectManagedSourceCredentialHostV2(issue, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	prepareFailure := DirectManagedSourcePrepareFailureACKV2{DirectManagedSourcePrepareProtocolV2, pop.Prepare.CommandID, DirectManagedSourcePrepareFailureV2}
	popFailure := DirectManagedSourcePoPFailureACKV2{DirectManagedSourcePoPProtocolV2, pop.ChallengeID, DirectManagedSourcePoPFailureV2}
	credentialFailure := DirectManagedSourceCredentialFailureACKV2{DirectManagedSourceCredentialProtocolV2, issue.CredentialID, DirectManagedSourceCredentialInstallFailureV2}
	type canonical interface{ CanonicalBytes() ([]byte, error) }
	for _, tc := range []struct {
		name   string
		value  canonical
		decode func([]byte) error
	}{
		{"binding", pop.Prepare.Subject, func(b []byte) error { _, e := DecodeDirectManagedSourceBindingV2(b); return e }},
		{"reservation", pop.ACK.Reservation, func(b []byte) error { _, e := DecodeDirectManagedSourceKeyReservationV2(b); return e }},
		{"prepare", pop.Prepare, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareCommandV2(b); return e }},
		{"prepare-ack", pop.ACK, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareACKV2(b, pop.Prepare); return e }},
		{"prepare-failure", prepareFailure, func(b []byte) error {
			_, e := DecodeDirectManagedSourcePrepareFailureACKV2(b, pop.Prepare.CommandID)
			return e
		}},
		{"receipt", pop.Receipt, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareReceiptReferenceV2(b); return e }},
		{"challenge", pop, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPChallengeV2(b); return e }},
		{"proof", proof, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPProofV2(b); return e }},
		{"pop-failure", popFailure, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPFailureACKV2(b, pop.ChallengeID); return e }},
		{"issue", issue, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialIssueV2(b); return e }},
		{"credential-ack", ack, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialACKV2(b); return e }},
		{"credential-failure", credentialFailure, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialFailureACKV2(b); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.decode(raw); err != nil {
				t.Fatal("roundtrip", err)
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			for key, value := range fields {
				quoted, _ := json.Marshal(key)
				duplicate := append([]byte("{"+string(quoted)+":"+string(value)+","), raw[1:]...)
				if tc.decode(duplicate) == nil {
					t.Fatal("accepted duplicate", key)
				}
				var missing map[string]json.RawMessage
				json.Unmarshal(raw, &missing)
				delete(missing, key)
				b, _ := json.Marshal(missing)
				if tc.decode(b) == nil {
					t.Fatal("accepted missing", key)
				}
				fieldsCopy := make(map[string]json.RawMessage)
				json.Unmarshal(raw, &fieldsCopy)
				fieldsCopy[key] = json.RawMessage("null")
				b, _ = json.Marshal(fieldsCopy)
				if tc.decode(b) == nil {
					t.Fatal("accepted null", key)
				}
			}
			for _, bad := range [][]byte{append([]byte(" "), raw...), append(append([]byte{}, raw...), '\n'), append(append([]byte{}, raw...), []byte("{}")...), append([]byte("{\"unknown\":null,"), raw[1:]...), append([]byte("{\"invalid\":\"\xff\","), raw[1:]...), bytes.Replace(raw, []byte("v2"), []byte(`v\ud800`), 1), bytes.Repeat([]byte(" "), 96*1024+1)} {
				if tc.decode(bad) == nil {
					t.Fatal("accepted noncanonical JSON")
				}
			}
		})
	}
}

func TestDirectManagedSourceCrossVersionV2(t *testing.T) {
	issue, host, _, _ := directManagedSourceFixtureV2(t)
	old, oldHost, _ := sourceCredentialFixture(t)
	proof, _ := ConfirmDirectManagedSourceHostCustodyV2(issue.PoP, host, issue.IssuedAt)
	oldProof, _ := ConfirmDirectManagedSourceHostCustody(old.PoP, oldHost, old.IssuedAt)
	secret, ack, _ := DeriveDirectManagedSourceCredentialHostV2(issue, host, issue.IssuedAt)
	clear(secret)
	oldSecret, oldACK, _ := DeriveDirectManagedSourceCredentialHost(old, oldHost, old.IssuedAt)
	clear(oldSecret)
	type canonical interface{ CanonicalBytes() ([]byte, error) }
	for _, tc := range []struct {
		name             string
		v1, v2           canonical
		decode1, decode2 func([]byte) error
	}{
		{"binding", old.PoP.Prepare.Subject, issue.PoP.Prepare.Subject, func(b []byte) error { _, e := DecodeDirectManagedSourceBindingV1(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourceBindingV2(b); return e }},
		{"reservation", old.PoP.ACK.Reservation, issue.PoP.ACK.Reservation, func(b []byte) error { _, e := DecodeDirectManagedSourceKeyReservation(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourceKeyReservationV2(b); return e }},
		{"prepare-ack", old.PoP.ACK, issue.PoP.ACK, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareACK(b, old.PoP.Prepare); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareACKV2(b, issue.PoP.Prepare); return e }},
		{"prepare-failure", DirectManagedSourcePrepareFailureACK{DirectManagedSourcePrepareProtocol, old.PoP.Prepare.CommandID, DirectManagedSourcePrepareFailure}, DirectManagedSourcePrepareFailureACKV2{DirectManagedSourcePrepareProtocolV2, issue.PoP.Prepare.CommandID, DirectManagedSourcePrepareFailureV2}, func(b []byte) error {
			_, e := DecodeDirectManagedSourcePrepareFailureACK(b, old.PoP.Prepare.CommandID)
			return e
		}, func(b []byte) error {
			_, e := DecodeDirectManagedSourcePrepareFailureACKV2(b, issue.PoP.Prepare.CommandID)
			return e
		}},
		{"pop-failure", DirectManagedSourcePoPFailureACK{DirectManagedSourcePoPProtocol, old.PoP.ChallengeID, DirectManagedSourcePoPFailure}, DirectManagedSourcePoPFailureACKV2{DirectManagedSourcePoPProtocolV2, issue.PoP.ChallengeID, DirectManagedSourcePoPFailureV2}, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPFailureACK(b, old.PoP.ChallengeID); return e }, func(b []byte) error {
			_, e := DecodeDirectManagedSourcePoPFailureACKV2(b, issue.PoP.ChallengeID)
			return e
		}},
		{"credential-failure", DirectManagedSourceCredentialFailureACK{DirectManagedSourceCredentialProtocol, old.CredentialID, DirectManagedSourceCredentialInstallFailure}, DirectManagedSourceCredentialFailureACKV2{DirectManagedSourceCredentialProtocolV2, issue.CredentialID, DirectManagedSourceCredentialInstallFailureV2}, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialFailureACK(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialFailureACKV2(b); return e }},
		{"receipt", old.PoP.Receipt, issue.PoP.Receipt, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareReceiptReference(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareReceiptReferenceV2(b); return e }},
		{"prepare", old.PoP.Prepare, issue.PoP.Prepare, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareCommand(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourcePrepareCommandV2(b); return e }},
		{"challenge", old.PoP, issue.PoP, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPChallenge(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPChallengeV2(b); return e }},
		{"proof", oldProof, proof, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPProof(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourcePoPProofV2(b); return e }},
		{"issue", old, issue, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialIssue(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialIssueV2(b); return e }},
		{"ack", oldACK, ack, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialACK(b); return e }, func(b []byte) error { _, e := DecodeDirectManagedSourceCredentialACKV2(b); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			one, _ := tc.v1.CanonicalBytes()
			two, _ := tc.v2.CanonicalBytes()
			if tc.decode1(two) == nil || tc.decode2(one) == nil {
				t.Fatal("cross-version evidence accepted")
			}
		})
	}
}

func TestDirectManagedSourceSubstitutionsV2(t *testing.T) {
	issue, host, _, server := directManagedSourceFixtureV2(t)
	for name, mutate := range map[string]func(*DirectManagedSourceCredentialIssueV2){
		"generation-mismatch": func(p *DirectManagedSourceCredentialIssueV2) { p.ChannelGeneration = "2" },
		"role":                func(p *DirectManagedSourceCredentialIssueV2) { p.PoP.Prepare.Subject.Role = "P" },
		"host":                func(p *DirectManagedSourceCredentialIssueV2) { p.PoP.ACK.Reservation.Subject.HostID = p.CredentialID },
		"budget":              func(p *DirectManagedSourceCredentialIssueV2) { p.PoP.Prepare.Subject.BudgetID = p.CredentialID },
		"budget-terms": func(p *DirectManagedSourceCredentialIssueV2) {
			p.PoP.Prepare.Subject.BudgetTermsDigest = strings.Repeat("ab", 32)
		},
		"issue-at-pop-expiry": func(p *DirectManagedSourceCredentialIssueV2) { p.IssuedAt = p.PoP.ExpiresAt },
		"issue-before-pop":    func(p *DirectManagedSourceCredentialIssueV2) { p.IssuedAt = p.PoP.IssuedAt.Add(-time.Nanosecond) },
		"install-empty":       func(p *DirectManagedSourceCredentialIssueV2) { p.InstallExpiresAt = p.IssuedAt },
		"install-after-enrollment": func(p *DirectManagedSourceCredentialIssueV2) {
			p.InstallExpiresAt = p.PoP.Prepare.Subject.EnrollmentExpiresAt.Add(time.Nanosecond)
		},
		"credential-before-install": func(p *DirectManagedSourceCredentialIssueV2) {
			p.CredentialExpiresAt = p.InstallExpiresAt.Add(-time.Nanosecond)
		},
		"credential-after-authorization": func(p *DirectManagedSourceCredentialIssueV2) {
			p.CredentialExpiresAt = p.PoP.Prepare.Subject.AuthorizationExpiresAt.Add(time.Nanosecond)
		},
		"credential-after-budget": func(p *DirectManagedSourceCredentialIssueV2) {
			p.BudgetExpiresAt = p.CredentialExpiresAt.Add(-time.Nanosecond)
		},
		"reused-key": func(p *DirectManagedSourceCredentialIssueV2) { p.ServerEphemeralX25519 = p.PoP.ServerEphemeralX25519 },
	} {
		t.Run(name, func(t *testing.T) {
			q := issue
			mutate(&q)
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted substitution")
			}
		})
	}
	for _, generation := range []string{"", "0", "-1", "+1", "01", "1.0", " 1", "1e2", "١"} {
		q := issue
		q.ChannelGeneration = generation
		if _, err := q.CanonicalBytes(); err == nil {
			t.Fatalf("accepted channel generation %q", generation)
		}
		subject := issue.PoP.Prepare.Subject
		subject.BindingGeneration = generation
		if _, err := subject.CanonicalBytes(); err == nil {
			t.Fatalf("accepted binding generation %q", generation)
		}
	}
	for name, mutate := range map[string]func(*DirectManagedSourceBindingV2){
		"first-predecessor": func(p *DirectManagedSourceBindingV2) { p.PredecessorBindingID = issue.CredentialID },
		"first-credential":  func(p *DirectManagedSourceBindingV2) { p.PreviousCredentialID = issue.CredentialID },
		"later-no-predecessor": func(p *DirectManagedSourceBindingV2) {
			p.BindingGeneration = "2"
			p.PreviousCredentialID = issue.CredentialID
		},
		"later-no-credential": func(p *DirectManagedSourceBindingV2) {
			p.BindingGeneration = "2"
			p.PredecessorBindingID = issue.CredentialID
		},
		"self-predecessor": func(p *DirectManagedSourceBindingV2) {
			p.BindingGeneration = "2"
			p.PredecessorBindingID = p.ID
			p.PreviousCredentialID = issue.CredentialID
		},
		"enrollment-empty": func(p *DirectManagedSourceBindingV2) { p.EnrollmentExpiresAt = p.CreatedAt },
		"enrollment-too-long": func(p *DirectManagedSourceBindingV2) {
			p.EnrollmentExpiresAt = p.CreatedAt.Add(5*time.Minute + time.Nanosecond)
		},
		"authorization-too-short": func(p *DirectManagedSourceBindingV2) {
			p.AuthorizationExpiresAt = p.EnrollmentExpiresAt.Add(-time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := issue.PoP.Prepare.Subject
			mutate(&q)
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted binding substitution")
			}
		})
	}
	for _, now := range []time.Time{issue.IssuedAt.Add(-time.Nanosecond), issue.InstallExpiresAt} {
		if _, _, err := DeriveDirectManagedSourceCredentialHostV2(issue, host, now); err == nil {
			t.Fatal("host accepted expired issue")
		}
		if _, _, _, err := DeriveDirectManagedSourceCredentialVerifierV2(issue, server, now); err == nil {
			t.Fatal("server accepted expired issue")
		}
	}
}

func TestDirectManagedSourceRenewalV2(t *testing.T) {
	issue, host, _, _ := directManagedSourceFixtureV2(t)
	// Use a generation beyond machine integer ranges to catch numeric coercion.
	subject := issue.PoP.Prepare.Subject
	subject.BindingGeneration = "184467440737095516160000000000000000000"
	subject.PredecessorBindingID = subject.ProposalID
	subject.PreviousCredentialID = subject.GrantID
	issue.ChannelGeneration = subject.BindingGeneration
	issue.PoP.Prepare.Subject = subject
	issue.PoP.ACK.Reservation.Subject = subject
	var err error
	issue.PoP.ACK.Reservation.EnrollmentDigest, err = issue.PoP.ACK.Reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	issue.PoP.Receipt, err = NewDirectManagedSourcePrepareReceiptReferenceV2(issue.PoP.ACK)
	if err != nil {
		t.Fatal(err)
	}
	issue.PoP.SourceBindingDigest, err = subject.Digest()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ConfirmDirectManagedSourceHostCustodyV2(issue.PoP, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	issue, err = NewDirectManagedSourceCredentialIssueV2(issue, issue.PoP, proof)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDirectManagedSourceCredentialIssueV2(raw); err != nil {
		t.Fatal(err)
	}
	q := issue
	q.CredentialID = subject.PreviousCredentialID
	if _, err = q.CanonicalBytes(); err == nil {
		t.Fatal("accepted previous credential reuse")
	}
	for _, change := range []func(*DirectManagedSourceBindingV2){func(p *DirectManagedSourceBindingV2) { p.PredecessorBindingID = p.BudgetID }, func(p *DirectManagedSourceBindingV2) { p.PreviousCredentialID = p.BudgetID }, func(p *DirectManagedSourceBindingV2) { p.BindingGeneration += "0" }} {
		retained := issue.PoP.Prepare
		change(&retained.Subject)
		ackRaw, _ := issue.PoP.ACK.CanonicalBytes()
		if _, err := DecodeDirectManagedSourcePrepareACKV2(ackRaw, retained); err == nil {
			t.Fatal("accepted ACK against changed retained renewal")
		}
	}
	q = issue
	q.PoP.ExpiresAt = q.PoP.Prepare.Subject.EnrollmentExpiresAt.Add(time.Nanosecond)
	if _, err := q.PoP.CanonicalBytes(); err == nil {
		t.Fatal("accepted PoP beyond enrollment")
	}
	q = issue
	q.PoP.IssuedAt = q.PoP.Prepare.Subject.CreatedAt.Add(-time.Nanosecond)
	if _, err := q.PoP.CanonicalBytes(); err == nil {
		t.Fatal("accepted PoP before enrollment")
	}
	old, _, _ := directManagedSourceFixture(t)
	oldRaw, _ := old.Receipt.CanonicalBytes()
	newRaw, _ := issue.PoP.Receipt.CanonicalBytes()
	if _, err := DecodeDirectManagedSourcePrepareReceiptReferenceV2(oldRaw); err == nil {
		t.Fatal("v2 accepted v1 receipt")
	}
	if _, err := DecodeDirectManagedSourcePrepareReceiptReference(newRaw); err == nil {
		t.Fatal("v1 accepted v2 receipt")
	}
	q = issue
	q.PoP.Receipt.ProtocolVersion = DirectManagedSourcePrepareProtocol
	if _, err := q.PoP.CanonicalBytes(); err == nil {
		t.Fatal("accepted v1 receipt version")
	}
}

func TestDirectManagedSourceInvalidCryptoInputsV2(t *testing.T) {
	issue, host, popServer, _ := directManagedSourceFixtureV2(t)
	for _, bad := range []string{"", strings.Repeat("AB", 32), strings.Repeat("00", 31), strings.Repeat("zz", 32)} {
		q := issue
		q.Nonce = bad
		if _, err := q.CanonicalBytes(); err == nil {
			t.Fatal("accepted credential nonce")
		}
		pop := issue.PoP
		pop.Nonce = bad
		if _, err := pop.CanonicalBytes(); err == nil {
			t.Fatal("accepted PoP nonce")
		}
	}
	for _, bad := range []string{strings.Repeat("00", 32), "01" + strings.Repeat("00", 31), "ed" + strings.Repeat("ff", 30) + "7f", strings.Repeat("ff", 32), strings.ToUpper(issue.ServerEphemeralX25519), issue.ServerEphemeralX25519[:62]} {
		q := issue
		q.ServerEphemeralX25519 = bad
		if _, err := q.CanonicalBytes(); err == nil {
			t.Fatal("accepted credential public key")
		}
		pop := issue.PoP
		pop.ServerEphemeralX25519 = bad
		if _, err := pop.CanonicalBytes(); err == nil {
			t.Fatal("accepted PoP public key")
		}
		reservation := issue.PoP.ACK.Reservation
		reservation.X25519 = bad
		if _, err := reservation.Digest(); err == nil {
			t.Fatal("accepted reservation public key")
		}
	}
	for _, bad := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)} {
		for i := 0; i < 4; i++ {
			q := issue
			switch i {
			case 0:
				q.IssuedAt = bad
			case 1:
				q.InstallExpiresAt = bad
			case 2:
				q.CredentialExpiresAt = bad
			case 3:
				q.BudgetExpiresAt = bad
			}
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted credential time")
			}
		}
		for i := 0; i < 2; i++ {
			q := issue.PoP
			if i == 0 {
				q.IssuedAt = bad
			} else {
				q.ExpiresAt = bad
			}
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted PoP time")
			}
		}
		for i := 0; i < 4; i++ {
			q := issue.PoP.Prepare.Subject
			switch i {
			case 0:
				q.RunnerConnectedAt = bad
			case 1:
				q.CreatedAt = bad
			case 2:
				q.EnrollmentExpiresAt = bad
			case 3:
				q.AuthorizationExpiresAt = bad
			}
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted binding time")
			}
		}
	}
	for _, now := range []time.Time{issue.PoP.IssuedAt.Add(-time.Nanosecond), issue.PoP.ExpiresAt} {
		if _, err := ConfirmDirectManagedSourceHostCustodyV2(issue.PoP, host, now); err == nil {
			t.Fatal("host accepted invalid PoP time")
		}
		if _, _, err := DeriveDirectManagedSourcePoPVerifierV2(issue.PoP, popServer, now); err == nil {
			t.Fatal("server accepted invalid PoP time")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{7}, 32)} {
		if _, err := ConfirmDirectManagedSourceHostCustodyV2(issue.PoP, bad, issue.IssuedAt); err == nil {
			t.Fatal("host accepted invalid PoP private key")
		}
		if _, _, err := DeriveDirectManagedSourcePoPVerifierV2(issue.PoP, bad, issue.IssuedAt); err == nil {
			t.Fatal("server accepted invalid PoP private key")
		}
		if _, _, err := DeriveDirectManagedSourceCredentialHostV2(issue, bad, issue.IssuedAt); err == nil {
			t.Fatal("host accepted invalid credential private key")
		}
		if _, _, _, err := DeriveDirectManagedSourceCredentialVerifierV2(issue, bad, issue.IssuedAt); err == nil {
			t.Fatal("server accepted invalid credential private key")
		}
	}
}

func TestDirectManagedSourceDeadlineEqualityV2(t *testing.T) {
	issue, _, _, _ := directManagedSourceFixtureV2(t)
	issue.CredentialExpiresAt = issue.PoP.Prepare.Subject.AuthorizationExpiresAt
	issue.BudgetExpiresAt = issue.CredentialExpiresAt
	if _, err := issue.CanonicalBytes(); err != nil {
		t.Fatal("authorization and budget equality rejected", err)
	}
	issue.CredentialExpiresAt = issue.InstallExpiresAt
	issue.BudgetExpiresAt = issue.InstallExpiresAt
	if _, err := issue.CanonicalBytes(); err != nil {
		t.Fatal("installation and credential equality rejected", err)
	}
}

func TestDirectManagedSourcePoPReceiptV2CanonicalDomain(t *testing.T) {
	issue, host, _, _ := directManagedSourceFixtureV2(t)
	defer clear(host)
	proof, err := ConfirmDirectManagedSourceHostCustodyV2(issue.PoP, host, issue.PoP.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewDirectManagedSourceCredentialPoPReceiptV2(proof)
	if err != nil || receipt != issue.PoPReceipt {
		t.Fatal("receipt changed existing V2 issue", err)
	}
	raw, _ := proof.CanonicalBytes()
	plain := sha256.Sum256(raw)
	if receipt.ProofDigest != sourceDigestV2("pagnet/direct-managed-source-host-custody-pop/proof/v2/", raw) || receipt.ProofDigest == hex.EncodeToString(plain[:]) {
		t.Fatal("wrong proof digest domain")
	}
	proof.ProtocolVersion = DirectManagedSourcePoPProtocol
	if _, err := NewDirectManagedSourceCredentialPoPReceiptV2(proof); err == nil {
		t.Fatal("accepted V1 proof domain")
	}
}
