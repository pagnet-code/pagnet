package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func directV2TestID(n byte) string {
	return "00000000-0000-4000-8000-0000000000" + hex.EncodeToString([]byte{n})
}
func directV2TestBinary(n byte, size int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{n}, size))
}
func directV2TestPoint(n byte) string {
	b := make([]byte, 32)
	b[0] = n
	return base64.RawURLEncoding.EncodeToString(b)
}
func directV2TestFixture(t *testing.T) (DirectChannelPublicationV2, DirectChannelReadinessChallengeV2, DirectChannelReadinessProofV2, []byte, time.Time) {
	t.Helper()
	limits := DirectChannelLimitsV2{4096, 5, 100, 1048576, 2, 8}
	endpoint := func(n byte) DirectChannelEndpointV2 {
		return DirectChannelEndpointV2{directV2TestID(n), directV2TestID(n + 1), directV2TestID(n + 2), directV2TestPoint(n), directV2TestID(n + 3), strings.Repeat("ab", 32)}
	}
	d := DirectChannelDescriptorV2{Domain: DirectChannelDomainV2, Suite: DirectChannelSuiteV2, ParentGrantID: directV2TestID(1), GrantGeneration: "1", ChannelGeneration: "2", DirectIntentID: directV2TestID(2), NetworkID: directV2TestID(3), AuthorizationDigest: strings.Repeat("cd", 32), S: endpoint(9), P: endpoint(10), EpochID: "01900000-0000-7000-8000-000000000001", ExpiresAt: "2030-01-01T01:00:00Z", Budget: DirectChannelBudgetV2{directV2TestID(4), "3", strings.Repeat("ef", 32), "2030-01-01T02:00:00Z", DirectChannelCountingVersionV2, limits}, Limits: limits}
	p := DirectChannelPublicationV2{d, directV2TestPoint(11), directV2TestBinary(7, 48)}
	channel, err := DirectChannelIDV2(d)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := DescriptorHashV2(d)
	if err != nil {
		t.Fatal(err)
	}
	ph, err := PublicationHashV2(p)
	if err != nil {
		t.Fatal(err)
	}
	c := DirectChannelReadinessChallengeV2{DirectChannelDomainV2 + "/proof", directV2TestID(5), "S", d.S.PrincipalID, d.S.EndpointID, d.S.CredentialID, channel, d.ParentGrantID, d.GrantGeneration, d.ChannelGeneration, d.DirectIntentID, dh, ph, d.EpochID, directV2TestBinary(8, 32), "2030-01-01T00:00:00Z", "2030-01-01T00:05:00Z"}
	key := bytes.Repeat([]byte{0x42}, 32)
	return p, c, directV2TestSign(t, c, key), key, time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC)
}
func directV2TestSign(t *testing.T, c DirectChannelReadinessChallengeV2, key []byte) DirectChannelReadinessProofV2 {
	t.Helper()
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return DirectChannelReadinessProofV2{DirectChannelReadinessProtocolV2, c.ChallengeID, base64.RawURLEncoding.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}
func TestDirectChannelV2Golden(t *testing.T) {
	p, c, proof, key, now := directV2TestFixture(t)
	channel, _ := DirectChannelIDV2(p.Descriptor)
	dh, _ := DescriptorHashV2(p.Descriptor)
	ph, _ := PublicationHashV2(p)
	got := []string{channel, dh, ph, proof.TranscriptHash, proof.Confirmation}
	want := []string{"-39Ng8iI84fm9IFqJJDM1u7sQqYBxK8JMjayxbge4QY", "lkcpDH-23pBaLtAdUhg5fSSEzeYqLRkbD9lvfqjcQX4", "tvpboS168tHeDtqWlDm0CjpTiG6RIKx4TFB47U7pxBw", "hxofBsbyxkSszscNyR8G-B--aJBzn8JaelblzmCNvCM", "Mvi1MJLRM9u1NbGvMVvBaER1rgIxJ5gpFSRRoTR82uk"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vector %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if err := VerifyDirectChannelReadinessProofV2(p, c, proof, key, now); err != nil {
		t.Fatal(err)
	}
}
func TestDirectChannelV2StrictDecode(t *testing.T) {
	p, c, proof, _, _ := directV2TestFixture(t)
	cases := []struct {
		name   string
		value  interface{ CanonicalBytes() ([]byte, error) }
		max    int
		decode func([]byte) error
	}{
		{"descriptor", p.Descriptor, DirectChannelDescriptorMaxBytesV2, func(b []byte) error { _, e := DecodeDirectChannelDescriptorV2(b); return e }},
		{"publication", p, DirectChannelPublicationMaxBytesV2, func(b []byte) error { _, e := DecodeDirectChannelPublicationV2(b); return e }},
		{"challenge", c, DirectChannelReadinessChallengeMaxBytesV2, func(b []byte) error { _, e := DecodeDirectChannelReadinessChallengeV2(b); return e }},
		{"proof", proof, DirectChannelReadinessProofMaxBytesV2, func(b []byte) error { _, e := DecodeDirectChannelReadinessProofV2(b); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			if err = tc.decode(raw); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			// Preserve every other byte when removing or nulling the first field.
			firstEnd := bytes.IndexByte(raw, ':')
			firstKey := string(raw[1:firstEnd])
			firstName := strings.Trim(firstKey, "\"")
			var bad = map[string][]byte{"empty": nil, "unknown": append([]byte(`{"unknown":1,`), raw[1:]...), "duplicate": append([]byte("{"+firstKey+":"+string(fields[firstName])+","), raw[1:]...), "whitespace": append([]byte(" "), raw...), "trailing": append(append([]byte{}, raw...), []byte("{}")...), "oversize": bytes.Repeat([]byte(" "), tc.max+1), "malformed_utf8": append([]byte{'{', '"', 0xff, '"', ':', '0', ','}, raw[1:]...), "surrogate": bytes.Replace(raw, []byte(firstKey), []byte(`"\ud800"`), 1)}
			valueEnd := firstEnd + 1 + len(fields[firstName])
			bad["missing"] = append([]byte("{"), raw[valueEnd+1:]...)
			bad["null"] = append([]byte("{"+firstKey+":null"), raw[valueEnd:]...)
			bad["order"], _ = json.Marshal(fields) // Sorted map order differs from declaration order.
			for name, b := range bad {
				t.Run(name, func(t *testing.T) {
					if err := tc.decode(b); err == nil {
						t.Fatal("accepted noncanonical JSON")
					}
				})
			}
		})
	}
}
func TestDirectChannelV2PublicKeys(t *testing.T) {
	p, _, _, _, _ := directV2TestFixture(t)
	lowHex := []string{strings.Repeat("00", 32), "01" + strings.Repeat("00", 31), "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", "ec" + strings.Repeat("ff", 30) + "7f", "ed" + strings.Repeat("ff", 30) + "7f", "ee" + strings.Repeat("ff", 30) + "7f", strings.Repeat("ff", 32)}
	for i, h := range lowHex {
		b, e := hex.DecodeString(h)
		if e != nil {
			t.Fatal(e)
		}
		s := base64.RawURLEncoding.EncodeToString(b)
		t.Run(h, func(t *testing.T) {
			if directV2PublicKey(s) {
				t.Fatalf("accepted point %d", i)
			}
			for _, field := range []string{"S", "P", "Enc"} {
				q := p
				switch field {
				case "S":
					q.Descriptor.S.PublicKey = s
				case "P":
					q.Descriptor.P.PublicKey = s
				case "Enc":
					q.Enc = s
				}
				if _, e := q.CanonicalBytes(); e == nil {
					t.Fatalf("accepted %s point", field)
				}
			}
		})
	}
}
func TestDirectChannelV2Limits(t *testing.T) {
	minimum := DirectChannelLimitsV2{1024, 1, 1, 1024, 1, 1}
	maximum := DirectChannelLimitsV2{65536, 10, 200, 8388608, 2, 16}
	if !minimum.valid() || !maximum.valid() || !minimum.within(maximum) {
		t.Fatal("valid boundary rejected")
	}
	minValues := []int{1024, 1, 1, 1024, 1, 1}
	maxValues := []int{65536, 10, 200, 8388608, 2, 16}
	for i := range minValues {
		name := reflect.TypeOf(minimum).Field(i).Name
		t.Run(name, func(t *testing.T) {
			for _, value := range []int{minValues[i] - 1, maxValues[i] + 1} {
				l := minimum
				reflect.ValueOf(&l).Elem().Field(i).SetInt(int64(value))
				if l.valid() {
					t.Fatalf("accepted %d", value)
				}
			}
			p, _, _, _, now := directV2TestFixture(t)
			p.Descriptor.Limits = minimum
			p.Descriptor.Budget.GrantLimits = maximum
			if e := ValidateDirectChannelDescriptorV2(p.Descriptor, now); e != nil {
				t.Fatal(e)
			}
			p.Descriptor.Limits = maximum
			p.Descriptor.Budget.GrantLimits = maximum
			reflect.ValueOf(&p.Descriptor.Budget.GrantLimits).Elem().Field(i).SetInt(int64(maxValues[i] - 1))
			if e := ValidateDirectChannelDescriptorV2(p.Descriptor, now); e == nil {
				t.Fatal("accepted limit exceeding grant")
			}
		})
	}
	l := maximum
	l.MaxWireBytesPerDay = l.MaxMessageWireBytes - 1
	if l.valid() {
		t.Fatal("accepted daily byte cap below message cap")
	}
}
func TestDirectChannelV2DescriptorMutations(t *testing.T) {
	p, _, _, _, now := directV2TestFixture(t)
	mutations := map[string]func(*DirectChannelDescriptorV2){
		"domain": func(d *DirectChannelDescriptorV2) { d.Domain = "other" }, "suite": func(d *DirectChannelDescriptorV2) { d.Suite = "other" },
		"nil_id": func(d *DirectChannelDescriptorV2) { d.ParentGrantID = "00000000-0000-0000-0000-000000000000" },
		"noncanonical_id": func(d *DirectChannelDescriptorV2) {
			d.ParentGrantID = strings.ToUpper(d.S.PrincipalID[:len(d.S.PrincipalID)-2] + "ab")
		},
		"generation_zero": func(d *DirectChannelDescriptorV2) { d.GrantGeneration = "0" }, "generation_leading_zero": func(d *DirectChannelDescriptorV2) { d.ChannelGeneration = "01" }, "generation_overflow": func(d *DirectChannelDescriptorV2) { d.GrantGeneration = "18446744073709551616" },
		"revision_zero": func(d *DirectChannelDescriptorV2) { d.Budget.AcceptedRevision = "0" }, "revision_one": func(d *DirectChannelDescriptorV2) { d.Budget.AcceptedRevision = "1" },
		"authorization_digest": func(d *DirectChannelDescriptorV2) { d.AuthorizationDigest = strings.Repeat("AB", 32) },
		"evidence_digest":      func(d *DirectChannelDescriptorV2) { d.S.KeyEvidenceDigest = "00" }, "terms_digest": func(d *DirectChannelDescriptorV2) { d.Budget.TermsDigest = "" },
		"same_principal": func(d *DirectChannelDescriptorV2) { d.P.PrincipalID = d.S.PrincipalID }, "same_endpoint": func(d *DirectChannelDescriptorV2) { d.P.EndpointID = d.S.EndpointID }, "same_key": func(d *DirectChannelDescriptorV2) { d.P.PublicKey = d.S.PublicKey },
		"epoch_version": func(d *DirectChannelDescriptorV2) { d.EpochID = directV2TestID(42) }, "expired": func(d *DirectChannelDescriptorV2) { d.ExpiresAt = now.Format(time.RFC3339Nano) },
		"budget_expired_first": func(d *DirectChannelDescriptorV2) { d.Budget.ExpiresAt = "2030-01-01T00:30:00Z" }, "non_utc": func(d *DirectChannelDescriptorV2) { d.ExpiresAt = "2030-01-01T01:00:00+00:00" }, "counting": func(d *DirectChannelDescriptorV2) { d.Budget.CountingVersion = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := p.Descriptor
			mutate(&d)
			if err := ValidateDirectChannelDescriptorV2(d, now); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
}
func TestDirectChannelV2ReadinessBinding(t *testing.T) {
	p, c, proof, key, now := directV2TestFixture(t)
	// Change every transcript field independently. Re-sign structurally valid
	// challenges to exercise binding checks as well as transcript authentication.
	cv := reflect.ValueOf(c)
	for i := 0; i < cv.NumField(); i++ {
		name := cv.Type().Field(i).Name
		t.Run(name, func(t *testing.T) {
			changed := c
			field := reflect.ValueOf(&changed).Elem().Field(i)
			old := field.String()
			replacement := directV2TestID(99)
			switch name {
			case "Domain":
				replacement = old + "x"
			case "Role":
				replacement = "P"
			case "GrantGeneration", "ChannelGeneration":
				replacement = "99"
			case "ChannelID", "DescriptorHash", "PublicationHash", "Nonce":
				replacement = directV2TestBinary(99, 32)
			case "EpochID":
				replacement = "01900000-0000-7000-8000-000000000099"
			case "IssuedAt":
				replacement = "2030-01-01T00:00:01Z"
			case "ExpiresAt":
				replacement = "2030-01-01T00:04:59Z"
			}
			field.SetString(replacement)
			if err := VerifyDirectChannelReadinessProofV2(p, changed, proof, key, now); err != errDirectChannelV2 {
				t.Fatalf("changed transcript returned %v", err)
			}
			if _, err := changed.CanonicalBytes(); err == nil && name != "ChallengeID" && name != "Nonce" && name != "IssuedAt" && name != "ExpiresAt" {
				resigned := directV2TestSign(t, changed, key)
				if err := VerifyDirectChannelReadinessProofV2(p, changed, resigned, key, now); err != errDirectChannelV2 {
					t.Fatalf("rebound challenge returned %v", err)
				}
			}
		})
	}
	// A fresh proof for P is valid only with P's selected identity.
	cp := c
	cp.Role = "P"
	cp.PrincipalID = p.Descriptor.P.PrincipalID
	cp.EndpointID = p.Descriptor.P.EndpointID
	cp.CredentialID = p.Descriptor.P.CredentialID
	if err := VerifyDirectChannelReadinessProofV2(p, cp, directV2TestSign(t, cp, key), key, now); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 31, 32, 33} {
		t.Run("wrong_key_"+string(rune('A'+n)), func(t *testing.T) {
			if err := VerifyDirectChannelReadinessProofV2(p, c, proof, bytes.Repeat([]byte{1}, n), now); err != errDirectChannelV2 {
				t.Fatalf("wrong key returned %v", err)
			}
		})
	}
	issued, _ := time.Parse(time.RFC3339, c.IssuedAt)
	expiry, _ := time.Parse(time.RFC3339, c.ExpiresAt)
	for _, when := range []time.Time{issued.Add(-time.Nanosecond), expiry, expiry.Add(time.Nanosecond)} {
		if err := VerifyDirectChannelReadinessProofV2(p, c, proof, key, when); err != errDirectChannelV2 {
			t.Fatalf("invalid verification time returned %v", err)
		}
	}
	if err := VerifyDirectChannelReadinessProofV2(p, c, proof, key, issued); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDirectChannelReadinessProofV2(p, c, proof, key, expiry.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Enc", "Ciphertext", "Descriptor"} {
		t.Run("publication_"+field, func(t *testing.T) {
			q := p
			switch field {
			case "Enc":
				q.Enc = directV2TestPoint(12)
			case "Ciphertext":
				q.Ciphertext = directV2TestBinary(9, 48)
			case "Descriptor":
				q.Descriptor.AuthorizationDigest = strings.Repeat("aa", 32)
			}
			if err := VerifyDirectChannelReadinessProofV2(q, c, proof, key, now); err != errDirectChannelV2 {
				t.Fatalf("publication mutation returned %v", err)
			}
		})
	}
	// Rebind all descriptor/publication hashes after shortening descriptor expiry;
	// the challenge still cannot outlive the descriptor.
	q := p
	q.Descriptor.ExpiresAt = "2030-01-01T00:04:00Z"
	cc := c
	cc.DescriptorHash, _ = DescriptorHashV2(q.Descriptor)
	cc.PublicationHash, _ = PublicationHashV2(q)
	if err := VerifyDirectChannelReadinessProofV2(q, cc, directV2TestSign(t, cc, key), key, now); err != errDirectChannelV2 {
		t.Fatalf("challenge outliving descriptor returned %v", err)
	}
	for i := 0; i < reflect.TypeOf(proof).NumField(); i++ {
		bad := proof
		v := reflect.ValueOf(&bad).Elem().Field(i)
		if i < 2 {
			v.SetString("invalid")
		} else {
			v.SetString(directV2TestBinary(99, 32))
		}
		if err := VerifyDirectChannelReadinessProofV2(p, c, bad, key, now); err != errDirectChannelV2 {
			t.Fatalf("proof mutation %d returned %v", i, err)
		}
	}
}

func TestDirectChannelV2ChallengeBoundaries(t *testing.T) {
	p, c, _, _, now := directV2TestFixture(t)
	for _, expiry := range []string{c.IssuedAt, "2029-12-31T23:59:59Z", "2030-01-01T00:05:00.000000001Z", "2030-01-01T00:05:00+00:00", "2030-01-01T00:05:00.000Z"} {
		bad := c
		bad.ExpiresAt = expiry
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatalf("accepted challenge expiry %q", expiry)
		}
	}
	for _, nonce := range []string{c.Nonce + "=", directV2TestBinary(8, 31), directV2TestBinary(8, 33)} {
		bad := c
		bad.Nonce = nonce
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("accepted malformed nonce")
		}
	}
	for _, ct := range []string{p.Ciphertext + "=", directV2TestBinary(7, 47), directV2TestBinary(7, 49)} {
		bad := p
		bad.Ciphertext = ct
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("accepted malformed wrapped key")
		}
	}
	p.Descriptor.Budget.AcceptedRevision = "2"
	p.Descriptor.GrantGeneration = "18446744073709551615"
	p.Descriptor.ChannelGeneration = "18446744073709551615"
	if err := ValidateDirectChannelDescriptorV2(p.Descriptor, now); err != nil {
		t.Fatal(err)
	}
}

func TestDirectChannelV2TimeYearAndEpochVariant(t *testing.T) {
	for _, timestamp := range []string{"0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z"} {
		if _, ok := directV2Time(timestamp); !ok {
			t.Fatalf("rejected year boundary %q", timestamp)
		}
	}
	if _, ok := directV2Time("0000-01-01T00:00:00Z"); ok {
		t.Fatal("accepted year zero")
	}
	p, c, _, _, _ := directV2TestFixture(t)
	for _, epoch := range []string{"01900000-0000-7000-0000-000000000001", "01900000-0000-7000-c000-000000000001", "01900000-0000-7000-e000-000000000001"} {
		t.Run(epoch, func(t *testing.T) {
			d := p.Descriptor
			d.EpochID = epoch
			if _, err := d.CanonicalBytes(); err == nil {
				t.Fatal("accepted descriptor epoch with non-RFC4122 variant")
			}
			challenge := c
			challenge.EpochID = epoch
			if _, err := challenge.CanonicalBytes(); err == nil {
				t.Fatal("accepted challenge epoch with non-RFC4122 variant")
			}
		})
	}
	for _, field := range []string{"ExpiresAt", "BudgetExpiresAt"} {
		d := p.Descriptor
		if field == "ExpiresAt" {
			d.ExpiresAt = "0000-01-01T00:00:00Z"
		} else {
			d.Budget.ExpiresAt = "0000-01-01T00:00:00Z"
			d.ExpiresAt = d.Budget.ExpiresAt
		}
		// A pre-year-zero clock ensures rejection comes from timestamp validation.
		if err := ValidateDirectChannelDescriptorV2(d, time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("accepted descriptor year zero in %s", field)
		}
	}
	challenge := c
	challenge.IssuedAt = "0000-01-01T00:00:00Z"
	challenge.ExpiresAt = "0000-01-01T00:05:00Z"
	if _, err := challenge.CanonicalBytes(); err == nil {
		t.Fatal("accepted challenge year zero")
	}
}
