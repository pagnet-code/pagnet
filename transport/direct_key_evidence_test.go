package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func directKeyEvidenceFixture(t *testing.T, role string) DirectKeyEvidenceTranscriptV1 {
	t.Helper()
	p, _, _, _, _ := directV2TestFixture(t)
	d := p.Descriptor
	party := d.S
	protocols := []string{DirectManagedSourceBindingProtocol, DirectManagedSourcePrepareProtocol, DirectManagedSourcePoPProtocol, DirectManagedSourceCredentialProtocol}
	if role == "P" {
		party = d.P
		protocols = []string{ManagedEndpointBindingProtocol, ManagedEndpointPrepareProtocol, ManagedEndpointPoPProtocol, ManagedDirectCredentialProtocol}
	}
	return DirectKeyEvidenceTranscriptV1{
		Domain: DirectKeyEvidenceDomainV1, Role: role, BindingProtocol: protocols[0], PrepareProtocol: protocols[1], PoPProtocol: protocols[2], CredentialProtocol: protocols[3],
		NetworkID: d.NetworkID, DirectIntentID: d.DirectIntentID, ProposalID: directV2TestID(20), ProposalVersion: "3", ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration, ChannelGeneration: d.ChannelGeneration, AuthorizationDigest: d.AuthorizationDigest,
		SourcePrincipalID: d.S.PrincipalID, TargetPrincipalID: d.P.PrincipalID, SourceAuthorityGeneration: directV2TestID(21), SourceMembershipAuthorityGeneration: directV2TestID(22), TargetAuthorityGeneration: directV2TestID(23),
		Party:   DirectKeyEvidencePartyV1{party.TenantID, party.PrincipalID, party.EndpointID, party.CredentialID, party.PublicKey},
		Binding: DirectKeyEvidenceBindingV1{directV2TestID(24), "1", strings.Repeat("ab", 32)}, Reservation: DirectKeyEvidenceReservationV1{directV2TestID(25), "1", strings.Repeat("bc", 32)},
		Evidence: DirectKeyEvidenceDigestsV1{strings.Repeat("01", 32), strings.Repeat("02", 32), strings.Repeat("03", 32), strings.Repeat("04", 32), strings.Repeat("05", 32), strings.Repeat("06", 32)}, Budget: d.Budget, Limits: d.Limits, EffectiveExpiresAt: d.ExpiresAt,
	}
}

func TestDirectKeyEvidenceGolden(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			p := directKeyEvidenceFixture(t, role)
			raw, err := p.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := p.Digest()
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string][]byte{"transcript.json": raw, "digest.txt": []byte(digest)} {
				path := filepath.Join("testdata", "direct_key_evidence_v1", role, name)
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s changed", name)
				}
			}
			decoded, err := DecodeDirectKeyEvidenceTranscriptV1(raw)
			if err != nil || decoded != p {
				t.Fatal("roundtrip", err)
			}
		})
	}
}

func TestDirectKeyEvidenceEveryFieldBound(t *testing.T) {
	p := directKeyEvidenceFixture(t, "S")
	raw, _ := p.CanonicalBytes()
	digest, _ := p.Digest()
	// Mutating each leaf must either fail validation or change the commitment.
	var visit func(reflect.Value, string)
	visit = func(v reflect.Value, path string) {
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			name := path + v.Type().Field(i).Name
			if f.Kind() == reflect.Struct {
				visit(f, name+".")
				continue
			}
			old := reflect.New(f.Type()).Elem()
			old.Set(f)
			switch f.Kind() {
			case reflect.String:
				value := f.String()
				switch {
				case directV2ID(value):
					if strings.HasSuffix(value, "ff") {
						value = value[:len(value)-2] + "fe"
					} else {
						value = value[:len(value)-2] + "ff"
					}
				case directV2Digest(value):
					if value[0] == 'f' {
						value = "e" + value[1:]
					} else {
						value = "f" + value[1:]
					}
				case directV2Decimal(value):
					n, _ := strconv.ParseUint(value, 10, 64)
					value = strconv.FormatUint(n+1, 10)
				case strings.HasSuffix(value, "Z"):
					value = "2030-01-01T01:30:00Z"
				case name == "Party.PublicKey":
					value = directV2TestPoint(12)
				default:
					value += "x"
				}
				f.SetString(value)
			case reflect.Int:
				f.SetInt(f.Int() + 1)
			default:
				t.Fatal("unhandled field", name)
			}
			mutated, err := p.CanonicalBytes()
			if err == nil {
				next, _ := p.Digest()
				if bytes.Equal(raw, mutated) || digest == next {
					t.Fatal("unbound", name)
				}
			}
			f.Set(old)
		}
	}
	visit(reflect.ValueOf(&p).Elem(), "")
}

func TestDirectKeyEvidenceRejectsMalformed(t *testing.T) {
	mutations := map[string]func(*DirectKeyEvidenceTranscriptV1){
		"role":          func(p *DirectKeyEvidenceTranscriptV1) { p.Role = "s" },
		"role-protocol": func(p *DirectKeyEvidenceTranscriptV1) { p.BindingProtocol = ManagedEndpointBindingProtocol },
		"party":         func(p *DirectKeyEvidenceTranscriptV1) { p.Party.PrincipalID = p.TargetPrincipalID },
		"uuid": func(p *DirectKeyEvidenceTranscriptV1) {
			p.NetworkID = strings.ToUpper("abcdefab-0000-4000-8000-000000000001")
		},
		"generation":       func(p *DirectKeyEvidenceTranscriptV1) { p.GrantGeneration = "01" },
		"zero":             func(p *DirectKeyEvidenceTranscriptV1) { p.Reservation.KeyGeneration = "0" },
		"overflow":         func(p *DirectKeyEvidenceTranscriptV1) { p.ProposalVersion = "18446744073709551616" },
		"revision":         func(p *DirectKeyEvidenceTranscriptV1) { p.Budget.AcceptedRevision = "1" },
		"hash":             func(p *DirectKeyEvidenceTranscriptV1) { p.AuthorizationDigest = strings.Repeat("AB", 32) },
		"padded-key":       func(p *DirectKeyEvidenceTranscriptV1) { p.Party.PublicKey += "=" },
		"low-order-key":    func(p *DirectKeyEvidenceTranscriptV1) { p.Party.PublicKey = directV2TestPoint(0) },
		"noncanonical-key": func(p *DirectKeyEvidenceTranscriptV1) { p.Party.PublicKey = directV2TestBinary(255, 32) },
		"time-zone":        func(p *DirectKeyEvidenceTranscriptV1) { p.EffectiveExpiresAt = "2030-01-01T01:00:00+00:00" },
		"time-fraction":    func(p *DirectKeyEvidenceTranscriptV1) { p.EffectiveExpiresAt = "2030-01-01T01:00:00.0Z" },
		"budget-expiry":    func(p *DirectKeyEvidenceTranscriptV1) { p.EffectiveExpiresAt = "2031-01-01T01:00:00Z" },
		"counting":         func(p *DirectKeyEvidenceTranscriptV1) { p.Budget.CountingVersion = "unknown" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := directKeyEvidenceFixture(t, "S")
			mutate(&p)
			if _, err := p.CanonicalBytes(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	p := directKeyEvidenceFixture(t, "S")
	raw, _ := p.CanonicalBytes()
	for _, bad := range [][]byte{append(raw, ' '), append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","unknown":1`), 1), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":"S","role":"S"`), 1), bytes.Replace(raw, []byte(`"role":"S"`), []byte(`"role":null`), 1), bytes.Replace(raw, []byte(`"role":"S",`), nil, 1), bytes.Repeat([]byte(" "), 8193)} {
		if _, err := DecodeDirectKeyEvidenceTranscriptV1(bad); err == nil {
			t.Fatal("accepted malformed JSON")
		}
	}
}

func TestDirectKeyEvidenceCounting(t *testing.T) {
	for _, version := range []string{DirectChannelCountingVersionV2, DirectChannelCountingVersionReservedV2} {
		p := directKeyEvidenceFixture(t, "P")
		p.Budget.CountingVersion = version
		if _, err := p.CanonicalBytes(); err != nil {
			t.Fatal(err)
		}
		p.Limits.MaxMessagesPerMinute = 1
		_, err := p.CanonicalBytes()
		if (err == nil) != (version == DirectChannelCountingVersionV2) {
			t.Fatal("pair counting validation")
		}
		p = directKeyEvidenceFixture(t, "P")
		p.Budget.CountingVersion = version
		p.Limits.MaxMessagesPerDay = 1
		p.Budget.GrantLimits.MaxMessagesPerDay = 1
		_, err = p.CanonicalBytes()
		if (err == nil) != (version == DirectChannelCountingVersionV2) {
			t.Fatal("grant counting validation")
		}
	}
}

func TestDirectKeyEvidenceBindingHash(t *testing.T) {
	source, _, _ := directManagedSourceFixture(t)
	sraw, err := source.Prepare.Subject.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	party := managedBindingFixture()
	praw, err := party.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for role, raw := range map[string][]byte{"S": sraw, "P": praw} {
		got, err := DirectKeyEvidenceBindingTranscriptHashV1(role, raw)
		sum := sha256.Sum256(append([]byte("pagnet/direct-key-evidence/binding/v1/"), raw...))
		if err != nil || got != hex.EncodeToString(sum[:]) {
			t.Fatal("hash", err)
		}
		if _, err := DirectKeyEvidenceBindingTranscriptHashV1(role, append(raw, ' ')); err == nil {
			t.Fatal("noncanonical binding")
		}
		other := "P"
		if role == "P" {
			other = "S"
		}
		if _, err := DirectKeyEvidenceBindingTranscriptHashV1(other, raw); err == nil {
			t.Fatal("wrong role")
		}
	}
	if _, err := DirectKeyEvidenceBindingTranscriptHashV1("", sraw); err == nil {
		t.Fatal("missing role")
	}
}
