package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func directKeyEvidenceFixtureV2(t *testing.T) DirectKeyEvidenceTranscriptV2 {
	t.Helper()
	old := directKeyEvidenceFixture(t, "S")
	raw, _ := json.Marshal(old)
	var p DirectKeyEvidenceTranscriptV2
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	issue, _, _, _ := directManagedSourceFixtureV2(t)
	s := issue.PoP.Prepare.Subject
	binding, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	bindingHash, err := DirectKeyEvidenceBindingTranscriptHashV2("S", binding)
	if err != nil {
		t.Fatal(err)
	}
	p.Domain = DirectKeyEvidenceDomainV2
	p.BindingProtocol = DirectManagedSourceBindingProtocolV2
	p.PrepareProtocol = DirectManagedSourcePrepareProtocolV2
	p.PoPProtocol = DirectManagedSourcePoPProtocolV2
	p.CredentialProtocol = DirectManagedSourceCredentialProtocolV2
	p.NetworkID, p.DirectIntentID, p.ProposalID, p.ParentGrantID = string(s.NetworkID), string(s.DirectIntentID), string(s.ProposalID), string(s.GrantID)
	p.ChannelGeneration = issue.ChannelGeneration
	p.SourcePrincipalID, p.TargetPrincipalID = string(s.SourcePrincipalID), string(s.TargetPrincipalID)
	p.SourceAuthorityGeneration, p.SourceMembershipAuthorityGeneration, p.TargetAuthorityGeneration = s.SourceAuthorityGeneration, s.SourceMembershipAuthorityGeneration, s.TargetAuthorityGeneration
	publicKey, _ := hex.DecodeString(issue.PoP.ACK.Reservation.X25519)
	p.Party = DirectKeyEvidencePartyV1{string(s.TenantID), string(s.PrincipalID), string(s.EndpointID), string(issue.CredentialID), base64.RawURLEncoding.EncodeToString(publicKey)}
	p.Binding = DirectKeyEvidenceBindingV1{string(s.ID), s.BindingGeneration, bindingHash}
	p.Reservation = DirectKeyEvidenceReservationV1{string(issue.PoP.ACK.Reservation.InstallationID), "1", issue.PoP.ACK.Reservation.EnrollmentDigest}
	p.Budget.AgreementID, p.Budget.AcceptedRevision, p.Budget.TermsDigest = string(s.BudgetID), "2", s.BudgetTermsDigest
	p.Budget.ExpiresAt = issue.BudgetExpiresAt.Format(time.RFC3339Nano)
	p.AuthorizationExpiresAt = s.AuthorizationExpiresAt.Format(time.RFC3339Nano)
	p.CredentialExpiresAt = issue.CredentialExpiresAt.Format(time.RFC3339Nano)
	p.EffectiveExpiresAt = p.CredentialExpiresAt
	return p
}

func TestDirectKeyEvidenceV2Golden(t *testing.T) {
	p := directKeyEvidenceFixtureV2(t)
	raw, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	issue, _, _, _ := directManagedSourceFixtureV2(t)
	binding, _ := issue.PoP.Prepare.Subject.CanonicalBytes()
	for name, got := range map[string][]byte{"transcript.json": raw, "digest.txt": []byte(digest), "binding.json": binding, "binding_hash.txt": []byte(p.Binding.BindingTranscriptHash)} {
		want, err := os.ReadFile(filepath.Join("testdata", "direct_key_evidence_v2", "S", name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed: %v", name, err)
		}
	}
	decoded, err := DecodeDirectKeyEvidenceTranscriptV2(raw)
	if err != nil || decoded != p {
		t.Fatal("roundtrip", err)
	}
	// The durable lifetime extends beyond the historical enrollment deadline.
	expiry, _ := directV2Time(p.EffectiveExpiresAt)
	if !expiry.After(issue.PoP.Prepare.Subject.EnrollmentExpiresAt) {
		t.Fatal("effective lifetime bounded by enrollment")
	}
}

func TestDirectKeyEvidenceV2RejectsMalformed(t *testing.T) {
	mutations := map[string]func(*DirectKeyEvidenceTranscriptV2){
		"domain":               func(p *DirectKeyEvidenceTranscriptV2) { p.Domain = DirectKeyEvidenceDomainV1 },
		"target-role":          func(p *DirectKeyEvidenceTranscriptV2) { p.Role = "P" },
		"binding-v1":           func(p *DirectKeyEvidenceTranscriptV2) { p.BindingProtocol = DirectManagedSourceBindingProtocol },
		"prepare-v1":           func(p *DirectKeyEvidenceTranscriptV2) { p.PrepareProtocol = DirectManagedSourcePrepareProtocol },
		"pop-v1":               func(p *DirectKeyEvidenceTranscriptV2) { p.PoPProtocol = DirectManagedSourcePoPProtocol },
		"credential-v1":        func(p *DirectKeyEvidenceTranscriptV2) { p.CredentialProtocol = DirectManagedSourceCredentialProtocol },
		"target-protocol":      func(p *DirectKeyEvidenceTranscriptV2) { p.BindingProtocol = ManagedEndpointBindingProtocol },
		"party":                func(p *DirectKeyEvidenceTranscriptV2) { p.Party.PrincipalID = p.TargetPrincipalID },
		"same-principal":       func(p *DirectKeyEvidenceTranscriptV2) { p.TargetPrincipalID = p.SourcePrincipalID },
		"binding-generation":   func(p *DirectKeyEvidenceTranscriptV2) { p.Binding.BindingGeneration = "2" },
		"key-generation":       func(p *DirectKeyEvidenceTranscriptV2) { p.Reservation.KeyGeneration = "2" },
		"channel-generation":   func(p *DirectKeyEvidenceTranscriptV2) { p.ChannelGeneration = "2" },
		"leading-zero":         func(p *DirectKeyEvidenceTranscriptV2) { p.GrantGeneration = "01" },
		"zero":                 func(p *DirectKeyEvidenceTranscriptV2) { p.ProposalVersion = "0" },
		"overflow":             func(p *DirectKeyEvidenceTranscriptV2) { p.GrantGeneration = "18446744073709551616" },
		"hash":                 func(p *DirectKeyEvidenceTranscriptV2) { p.AuthorizationDigest = strings.Repeat("AB", 32) },
		"low-order-key":        func(p *DirectKeyEvidenceTranscriptV2) { p.Party.PublicKey = directV2TestPoint(0) },
		"authorization-expiry": func(p *DirectKeyEvidenceTranscriptV2) { p.AuthorizationExpiresAt = "2026-11-24T12:29:59Z" },
		"budget-expiry":        func(p *DirectKeyEvidenceTranscriptV2) { p.Budget.ExpiresAt = "2026-11-24T12:29:59Z" },
		"credential-expiry":    func(p *DirectKeyEvidenceTranscriptV2) { p.CredentialExpiresAt = "2026-11-24T12:31:00Z" },
		"effective-expiry":     func(p *DirectKeyEvidenceTranscriptV2) { p.EffectiveExpiresAt = "2026-11-24T12:29:00Z" },
		"time-zone":            func(p *DirectKeyEvidenceTranscriptV2) { p.AuthorizationExpiresAt = "2026-11-24T13:00:00+00:00" },
		"time-fraction":        func(p *DirectKeyEvidenceTranscriptV2) { p.CredentialExpiresAt = "2026-11-24T12:30:00.0Z" },
		"counting":             func(p *DirectKeyEvidenceTranscriptV2) { p.Budget.CountingVersion = "unknown" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := directKeyEvidenceFixtureV2(t)
			mutate(&p)
			if _, err := p.CanonicalBytes(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	p := directKeyEvidenceFixtureV2(t)
	raw, _ := p.CanonicalBytes()
	for _, bad := range [][]byte{append(raw, ' '), append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","unknown":1`), 1), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","role":"S"`), 1), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":null`), 1), bytes.Replace(raw, []byte(`"role":"S",`), nil, 1), bytes.Replace(raw, []byte(`"channelGeneration":"1"`), []byte(`"channelGeneration":1`), 1), bytes.Repeat([]byte(" "), DirectKeyEvidenceTranscriptMaxBytesV2+1)} {
		if _, err := DecodeDirectKeyEvidenceTranscriptV2(bad); err == nil {
			t.Fatal("accepted malformed JSON")
		}
	}
	for _, role := range []string{"S", "P"} {
		v1 := directKeyEvidenceFixture(t, role)
		v1Raw, _ := v1.CanonicalBytes()
		if _, err := DecodeDirectKeyEvidenceTranscriptV2(v1Raw); err == nil {
			t.Fatal("accepted v1 evidence", role)
		}
	}
	if _, err := DecodeDirectKeyEvidenceTranscriptV1(raw); err == nil {
		t.Fatal("v1 accepted v2 evidence")
	}
}

func TestDirectKeyEvidenceV2BindingHash(t *testing.T) {
	issue, _, _, _ := directManagedSourceFixtureV2(t)
	s := issue.PoP.Prepare.Subject
	raw, _ := s.CanonicalBytes()
	got, err := DirectKeyEvidenceBindingTranscriptHashV2("S", raw)
	want := sha256.Sum256(append([]byte("pagnet/direct-key-evidence/binding/v2/"), raw...))
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatal("binding hash", err)
	}
	for _, role := range []string{"", "s", "P"} {
		if _, err := DirectKeyEvidenceBindingTranscriptHashV2(role, raw); err == nil {
			t.Fatal("accepted role", role)
		}
	}
	for _, bad := range [][]byte{append([]byte(" "), raw...), append(append([]byte(nil), raw...), ' '), bytes.Replace(raw, []byte(`,"directIntentId"`), []byte(`, "directIntentId"`), 1)} {
		if _, err := DirectKeyEvidenceBindingTranscriptHashV2("S", bad); err == nil {
			t.Fatal("accepted noncanonical binding")
		}
	}
	for _, role := range []string{"S", "P"} {
		v1, err := os.ReadFile(filepath.Join("testdata", "direct_key_evidence_v1", role, "binding.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DirectKeyEvidenceBindingTranscriptHashV2("S", v1); err == nil {
			t.Fatal("accepted v1 binding", role)
		}
	}
	if _, err := DirectKeyEvidenceBindingTranscriptHashV1("S", raw); err == nil {
		t.Fatal("v1 accepted v2 binding")
	}
	// The underlying source-v2 subject supports successors, but this initial
	// evidence contract deliberately does not enable rollover.
	s.BindingGeneration = "2"
	s.PredecessorBindingID = s.BudgetID
	s.PreviousCredentialID = issue.CredentialID
	successor, err := s.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DirectKeyEvidenceBindingTranscriptHashV2("S", successor); err == nil {
		t.Fatal("accepted successor")
	}
}
