package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func nativeShareSourceEnrollmentFixture(t *testing.T) (NativeShareSourcePreparedPayload, ed25519.PublicKey) {
	t.Helper()
	binding, _, _ := nativeSharePrepared(t)
	b, s := binding.Prepare.Binding, binding.Subject
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	pub := private.Public().(ed25519.PublicKey)
	p := NativeShareSourcePreparedPayload{
		Prepare: NativeShareSourcePreparePayload{CommandID: binding.Prepare.CommandID, Enrollment: NativeShareSourceEnrollment{
			Version: 1, EnrollmentID: b.BindingID, NetworkID: b.NetworkID, PreviousEpochID: b.ContextID, ProposalID: b.ProposalID, ProposalRevision: b.ProposalRevision, GrantID: b.GrantID, GrantGeneration: b.GrantGeneration, BindingID: b.BindingID, BindingDigest: binding.BindingDigest, Subject: NativeShareSourceHostSubject{ServerURL: s.ServerURL, TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID, NativeAdmissionID: s.NativeAdmissionID, RunnerID: s.RunnerID, RunnerEpoch: s.RunnerEpoch, BootID: s.BootID}, HostCredentialID: "host-credential", OwnershipScope: "account", ExpiresAt: b.ExpiresAt,
		}},
		Descriptor: NativeShareSourceHolderDescriptor{Version: 1, Scope: NativeShareSourceHolderScope{ServerURL: s.ServerURL, TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID}, InstallationID: b.ContextID, HolderID: binding.HolderID, Generation: 1, X25519: binding.HolderX25519, Ed25519: hex.EncodeToString(pub)},
	}
	var err error
	p.Descriptor.Fingerprint, err = p.Descriptor.DigestFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollmentDigest, err = p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(private, raw)
	return p, pub
}

func TestNativeShareSourceEnrollmentRoundTrip(t *testing.T) {
	p, pub := nativeShareSourceEnrollmentFixture(t)
	if p.Descriptor.Fingerprint != "e7d77061e8ef6a237cafebea34fcf5e0500fa0d464314d41825047c8ce177d4d" || p.EnrollmentDigest != "11d0d490fe210022988bc96c8d1e0371ba55359c1f7e9cab7b1b8119dc1df366" {
		t.Fatal("ordered transcript vector changed")
	}
	for _, prepared := range []bool{false, true} {
		var raw, again []byte
		var err error
		if prepared {
			raw, err = p.CanonicalBytes()
			decoded, e := DecodeNativeShareSourcePreparedPayload(raw)
			if e != nil {
				t.Fatal(e)
			}
			again, err = decoded.CanonicalBytes()
			if e := decoded.Verify(p.Prepare, p.Descriptor, pub); e != nil {
				t.Fatal(e)
			}
		} else {
			raw, err = p.Prepare.CanonicalBytes()
			decoded, e := DecodeNativeShareSourcePreparePayload(raw)
			if e != nil {
				t.Fatal(e)
			}
			again, err = decoded.CanonicalBytes()
		}
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("canonical round trip changed", err)
		}
	}
	d := p.Descriptor
	d.Fingerprint = ""
	raw, _ := json.Marshal(d)
	fingerprint := sha256.Sum256(raw)
	if p.Descriptor.Fingerprint != hex.EncodeToString(fingerprint[:]) {
		t.Fatal("persisted fingerprint mismatch")
	}
	raw, _ = json.Marshal(struct {
		Prepare    NativeShareSourcePreparePayload   `json:"prepare"`
		Descriptor NativeShareSourceHolderDescriptor `json:"descriptor"`
	}{p.Prepare, p.Descriptor})
	digest := sha256.Sum256(append([]byte("pagnet/native-share-source/enrollment/v1/"), raw...))
	if p.EnrollmentDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("enrollment digest mismatch")
	}
	signed, _ := p.SignatureBytes()
	if string(signed) != "pagnet/native-share-source/prepared/v1/"+p.EnrollmentDigest {
		t.Fatal("signature input mismatch")
	}
	e, _ := p.Prepare.Enrollment.CanonicalBytes()
	wantFields := `"version":1,"enrollmentId":`
	if !bytes.HasPrefix(e, []byte("{"+wantFields)) || !bytes.Contains(e, []byte(`"proposalRevision":"1","grantId":`)) || !bytes.Contains(e, []byte(`"grantGeneration":"2","bindingId":`)) {
		t.Fatal("enrollment field encoding changed")
	}
}

func TestNativeShareSourceEnrollmentTamper(t *testing.T) {
	p, pub := nativeShareSourceEnrollmentFixture(t)
	value := reflect.ValueOf(&p.Prepare.Enrollment).Elem()
	for i := 0; i < value.NumField(); i++ {
		t.Run(value.Type().Field(i).Name, func(t *testing.T) {
			changed := p
			f := reflect.ValueOf(&changed.Prepare.Enrollment).Elem().Field(i)
			switch f.Kind() {
			case reflect.String:
				f.SetString(f.String() + "x")
			case reflect.Int:
				f.SetInt(2)
			case reflect.Uint64:
				f.SetUint(f.Uint() + 1)
			case reflect.Struct:
				changed.Prepare.Enrollment.Subject.BootID += "x"
			}
			// Even when the attacker recomputes a digest, the original signature fails.
			changed.EnrollmentDigest, _ = changed.Digest()
			if changed.Verify(changed.Prepare, changed.Descriptor, pub) == nil {
				t.Fatal("accepted modified enrollment")
			}
		})
	}
	changed := p
	changed.Prepare.CommandID = domain.ID("10000000-0000-4000-8000-000000000099")
	if changed.Verify(p.Prepare, p.Descriptor, pub) == nil {
		t.Fatal("accepted wrong command")
	}
	changed = p
	changed.Descriptor.HolderID = changed.Prepare.CommandID
	changed.Descriptor.Fingerprint, _ = changed.Descriptor.DigestFingerprint()
	changed.EnrollmentDigest, _ = changed.Digest()
	if changed.Verify(changed.Prepare, changed.Descriptor, pub) == nil {
		t.Fatal("accepted substituted descriptor")
	}
	changed = p
	changed.Signature = append([]byte(nil), p.Signature...)
	changed.Signature[0] ^= 1
	if changed.Verify(p.Prepare, p.Descriptor, pub) == nil {
		t.Fatal("accepted modified signature")
	}
	if p.Verify(p.Prepare, p.Descriptor, make(ed25519.PublicKey, 32)) == nil {
		t.Fatal("accepted untrusted signer")
	}
}

func TestNativeShareSourceEnrollmentStrictDecode(t *testing.T) {
	p, _ := nativeShareSourceEnrollmentFixture(t)
	raw, _ := p.CanonicalBytes()
	cases := map[string][]byte{
		"unknown":               bytes.Replace(raw, []byte(`"prepare":`), []byte(`"extra":1,"prepare":`), 1),
		"duplicate":             bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"alias":                 bytes.Replace(raw, []byte(`"bootId":`), []byte(`"BootId":`), 1),
		"null":                  bytes.Replace(raw, []byte(`"bootId":"`+p.Prepare.Enrollment.Subject.BootID+`"`), []byte(`"bootId":null`), 1),
		"missing":               bytes.Replace(raw, []byte(`"ownershipScope":"account",`), nil, 1),
		"number revision":       bytes.Replace(raw, []byte(`"proposalRevision":"1"`), []byte(`"proposalRevision":1`), 1),
		"leading zero revision": bytes.Replace(raw, []byte(`"proposalRevision":"1"`), []byte(`"proposalRevision":"01"`), 1),
		"signature array":       bytes.Replace(raw, []byte(`"signature":"`), []byte(`"signature":[] ,"ignored":"`), 1),
		"trailing":              append(bytes.Clone(raw), []byte(` {}`)...),
		"oversize":              append(bytes.Clone(raw), bytes.Repeat([]byte(" "), NativeShareSourceEnrollmentMaxBodyBytes)...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNativeShareSourcePreparedPayload(body); err == nil {
				t.Fatal("accepted ambiguous wire object")
			}
		})
	}
	for _, endpoint := range []string{"https://user@example.test", "https://example.test?", "https://example.test/#", "ftp://example.test", "https://example.test/" + strings.Repeat("x", 2048)} {
		changed := p.Prepare
		changed.Enrollment.Subject.ServerURL = endpoint
		if _, err := changed.CanonicalBytes(); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	for _, timestamp := range []string{"2027-01-02T03:04:05+00:00", "2027-01-02T03:04:05.000Z", ""} {
		changed := p.Prepare
		changed.Enrollment.ExpiresAt = timestamp
		if _, err := changed.CanonicalBytes(); err == nil {
			t.Fatal("accepted noncanonical expiry")
		}
	}
	changed := p
	changed.Descriptor.Scope.AccountID = changed.Descriptor.Scope.HostID
	changed.Descriptor.Fingerprint, _ = changed.Descriptor.DigestFingerprint()
	if _, err := changed.Digest(); err == nil {
		t.Fatal("accepted descriptor outside subject scope")
	}
	changed = p
	changed.Signature = changed.Signature[:63]
	if _, err := changed.CanonicalBytes(); err == nil {
		t.Fatal("accepted short signature")
	}
}

func TestNativeShareSourceEnrollmentRejectsRemovedFields(t *testing.T) {
	p, _ := nativeShareSourceEnrollmentFixture(t)
	prepare, _ := p.Prepare.CanonicalBytes()
	prepared, _ := p.CanonicalBytes()
	for _, name := range []string{"sourceInstanceId", "nativeGeneration", "connectedAt", "connectionId", "authorityConnectionId", "profileFingerprint"} {
		t.Run(name, func(t *testing.T) {
			anchor := []byte(`"enrollment":{`)
			if name == "profileFingerprint" {
				anchor = []byte(`"subject":{`)
			}
			extra := append(bytes.Clone(anchor), []byte(`"`+name+`":"removed",`)...)
			if _, err := DecodeNativeShareSourcePreparePayload(bytes.Replace(prepare, anchor, extra, 1)); err == nil {
				t.Fatal("prepare accepted removed field")
			}
			if _, err := DecodeNativeShareSourcePreparedPayload(bytes.Replace(prepared, anchor, extra, 1)); err == nil {
				t.Fatal("prepared accepted removed field")
			}
		})
	}
}

func TestNativeShareSourceEnrollmentRequiresCapturedHostSession(t *testing.T) {
	p, pub := nativeShareSourceEnrollmentFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	check := func(t *testing.T, changed NativeShareSourcePreparedPayload) {
		t.Helper()
		changed.Descriptor.Scope = NativeShareSourceHolderScope{ServerURL: changed.Prepare.Enrollment.Subject.ServerURL, TenantID: changed.Prepare.Enrollment.Subject.TenantID, AccountID: changed.Prepare.Enrollment.Subject.AccountID, HostID: changed.Prepare.Enrollment.Subject.HostID}
		changed.Descriptor.Fingerprint, _ = changed.Descriptor.DigestFingerprint()
		var err error
		changed.EnrollmentDigest, err = changed.Digest()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := changed.SignatureBytes()
		if err != nil {
			t.Fatal(err)
		}
		changed.Signature = ed25519.Sign(private, raw)
		// A valid dedicated-holder signature cannot substitute session evidence for
		// the independently captured expected request, even with a matching scope.
		if err := changed.Verify(p.Prepare, changed.Descriptor, pub); err == nil {
			t.Fatal("accepted substituted authenticated host session")
		}
	}
	subject := reflect.TypeOf(p.Prepare.Enrollment.Subject)
	for i := 0; i < subject.NumField(); i++ {
		t.Run(subject.Field(i).Name, func(t *testing.T) {
			changed := p
			field := reflect.ValueOf(&changed.Prepare.Enrollment.Subject).Elem().Field(i)
			switch subject.Field(i).Name {
			case "ServerURL":
				field.SetString("https://other.test")
			case "RunnerEpoch":
				field.SetString("2026-11-02T09:10:12Z")
			case "BootID":
				field.SetString("other-boot")
			default:
				field.SetString("10000000-0000-4000-8000-000000000099")
			}
			check(t, changed)
		})
	}
	for _, name := range []string{"HostCredentialID", "OwnershipScope"} {
		t.Run(name, func(t *testing.T) {
			changed := p
			reflect.ValueOf(&changed.Prepare.Enrollment).Elem().FieldByName(name).SetString("other")
			check(t, changed)
		})
	}
}
