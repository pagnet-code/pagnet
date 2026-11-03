package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nativeShareEpochFixture(t *testing.T) (NativeShareEpochPackage, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := NativeShareEpochPackage{Metadata: NativeShareEpochMetadata{
		Version: 1, OperationID: "10000000-0000-4000-8000-000000000001",
		TenantID: "10000000-0000-4000-8000-000000000002", NetworkID: "10000000-0000-4000-8000-000000000003",
		PreviousEpochID: "10000000-0000-4000-8000-000000000004", EpochID: "10000000-0000-4000-8000-000000000005",
		EpochPossessionVerifier: hex.EncodeToString(pub),
		ProposalRevision:        1, GrantGeneration: 2, BindingDigest: strings.Repeat("ab", 32),
		HolderID: "10000000-0000-4000-8000-000000000006", HolderX25519: strings.Repeat("cd", 32),
		CommandID: "10000000-0000-4000-8000-000000000007", CommandConnectionID: "command-connection", AuthorityConnectionID: "authority-connection",
		Deadline: "2027-01-02T03:04:05Z",
	}, Wrapped: CryptoHPKEWrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 48)}}
	raw, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(private, raw)
	return p, pub, private, time.Date(2027, 1, 2, 3, 4, 4, 0, time.UTC)
}

func TestNativeShareEpochRoundTrip(t *testing.T) {
	p, pub, _, now := nativeShareEpochFixture(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeShareEpochPackage(raw, p.Metadata, pub, now)
	if err != nil || !reflect.DeepEqual(decoded, p) {
		t.Fatal("package round trip failed", err)
	}
	aad, _ := p.Metadata.AAD()
	again, _ := decoded.Metadata.AAD()
	if !bytes.Equal(aad, again) || !bytes.Contains(aad, []byte(`"proposalRevision":"1"`)) || !bytes.Contains(aad, []byte(`"grantGeneration":"2"`)) {
		t.Fatal("metadata canonical encoding changed")
	}
}

func TestNativeShareEpochEveryMetadataFieldBound(t *testing.T) {
	p, pub, private, now := nativeShareEpochFixture(t)
	typ := reflect.TypeOf(p.Metadata)
	originalAAD, _ := p.Metadata.AAD()
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			changed := p
			field := reflect.ValueOf(&changed.Metadata).Elem().Field(i)
			field.SetZero()
			if _, err := changed.Metadata.AAD(); err == nil {
				t.Fatal("accepted omitted metadata field")
			}
			changed = p
			field = reflect.ValueOf(&changed.Metadata).Elem().Field(i)
			switch field.Kind() {
			case reflect.Int:
				field.SetInt(2)
			case reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.String:
				switch typ.Field(i).Name {
				case "EpochPossessionVerifier", "BindingDigest", "HolderX25519":
					field.SetString(strings.Repeat("ef", 32))
				case "Deadline":
					field.SetString("2027-01-02T03:04:06Z")
				case "CommandConnectionID", "AuthorityConnectionID":
					field.SetString("another-connection")
				default:
					field.SetString("20000000-0000-4000-8000-000000000001")
				}
			}
			if changed.Verify(changed.Metadata, pub, now) == nil {
				t.Fatal("accepted metadata tampering with original signature")
			}
			if typ.Field(i).Name == "Version" {
				return
			}
			aad, err := changed.Metadata.AAD()
			if err != nil || bytes.Equal(aad, originalAAD) {
				t.Fatal("valid metadata change did not change AAD", err)
			}
			raw, err := changed.SignatureBytes()
			if err != nil {
				t.Fatal(err)
			}
			changed.Signature = ed25519.Sign(private, raw)
			if changed.Verify(p.Metadata, pub, now) == nil {
				t.Fatal("accepted signed substitution of expected context")
			}
			if p.Verify(changed.Metadata, pub, now) == nil {
				t.Fatal("accepted mismatched caller context")
			}
		})
	}
}

func TestNativeShareEpochRejectsMalformedMetadata(t *testing.T) {
	p, _, _, _ := nativeShareEpochFixture(t)
	for name, mutate := range map[string]func(*NativeShareEpochMetadata){
		"same epoch":            func(m *NativeShareEpochMetadata) { m.EpochID = m.PreviousEpochID },
		"malformed id":          func(m *NativeShareEpochMetadata) { m.NetworkID = "invalid" },
		"zero id":               func(m *NativeShareEpochMetadata) { m.NetworkID = "00000000-0000-0000-0000-000000000000" },
		"uppercase digest":      func(m *NativeShareEpochMetadata) { m.BindingDigest = strings.Repeat("AB", 32) },
		"uppercase verifier":    func(m *NativeShareEpochMetadata) { m.EpochPossessionVerifier = strings.Repeat("AB", 32) },
		"short verifier":        func(m *NativeShareEpochMetadata) { m.EpochPossessionVerifier = strings.Repeat("ab", 31) },
		"long verifier":         func(m *NativeShareEpochMetadata) { m.EpochPossessionVerifier = strings.Repeat("ab", 33) },
		"nonhex verifier":       func(m *NativeShareEpochMetadata) { m.EpochPossessionVerifier = strings.Repeat("gg", 32) },
		"short holder key":      func(m *NativeShareEpochMetadata) { m.HolderX25519 = "ab" },
		"invalid deadline":      func(m *NativeShareEpochMetadata) { m.Deadline = "tomorrow" },
		"zero deadline":         func(m *NativeShareEpochMetadata) { m.Deadline = "0001-01-01T00:00:00Z" },
		"noncanonical deadline": func(m *NativeShareEpochMetadata) { m.Deadline = "2027-01-02T03:04:05+00:00" },
		"connection whitespace": func(m *NativeShareEpochMetadata) { m.CommandConnectionID = " connection" },
		"connection newline":    func(m *NativeShareEpochMetadata) { m.AuthorityConnectionID = "connection\nother" },
		"connection oversized":  func(m *NativeShareEpochMetadata) { m.CommandConnectionID = strings.Repeat("a", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			m := p.Metadata
			mutate(&m)
			if _, err := m.AAD(); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
}

func TestNativeShareEpochRejectsAuthorityTamperingAndExpiry(t *testing.T) {
	p, pub, _, now := nativeShareEpochFixture(t)
	_, wrongPub, _, _ := nativeShareEpochFixture(t)
	if p.Verify(p.Metadata, wrongPub, now) == nil || p.Verify(p.Metadata, nil, now) == nil {
		t.Fatal("accepted untrusted authority")
	}
	for _, at := range []time.Time{{}, now.Add(time.Second), now.Add(2 * time.Second)} {
		if p.Verify(p.Metadata, pub, at) == nil {
			t.Fatal("accepted zero time or expired deadline")
		}
	}
	for name, mutate := range map[string]func(*NativeShareEpochPackage){
		"signature": func(p *NativeShareEpochPackage) {
			p.Signature = append([]byte(nil), p.Signature...)
			p.Signature[0] ^= 1
		},
		"missing signature": func(p *NativeShareEpochPackage) { p.Signature = nil },
		"enc": func(p *NativeShareEpochPackage) {
			p.Wrapped.Enc = append([]byte(nil), p.Wrapped.Enc...)
			p.Wrapped.Enc[0] ^= 1
		},
		"ciphertext": func(p *NativeShareEpochPackage) {
			p.Wrapped.Ciphertext = append([]byte(nil), p.Wrapped.Ciphertext...)
			p.Wrapped.Ciphertext[0] ^= 1
		},
		"short enc":       func(p *NativeShareEpochPackage) { p.Wrapped.Enc = p.Wrapped.Enc[:31] },
		"long ciphertext": func(p *NativeShareEpochPackage) { p.Wrapped.Ciphertext = make([]byte, 49) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if changed.Verify(p.Metadata, pub, now) == nil {
				t.Fatal("accepted modified package")
			}
		})
	}
}

func TestNativeShareEpochStrictDecode(t *testing.T) {
	p, pub, _, now := nativeShareEpochFixture(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"unknown package field":  append([]byte(`{"unknown":true,`), raw[1:]...),
		"unknown metadata field": bytes.Replace(raw, []byte(`"metadata":{`), []byte(`"metadata":{"unknown":true,`), 1),
		"unknown wrapped field":  bytes.Replace(raw, []byte(`"wrapped":{`), []byte(`"wrapped":{"unknown":true,`), 1),
		"trailing object":        append(append([]byte(nil), raw...), []byte(` {}`)...),
		"trailing null":          append(append([]byte(nil), raw...), []byte(` null`)...),
		"trailing malformed":     append(append([]byte(nil), raw...), '!'),
		"oversized":              append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), 16<<10)...),
		"truncated":              raw[:len(raw)-1],
		"numeric revision":       bytes.Replace(raw, []byte(`"proposalRevision":"1"`), []byte(`"proposalRevision":1`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNativeShareEpochPackage(input, p.Metadata, pub, now); err == nil {
				t.Fatal("accepted malformed wire package")
			}
		})
	}
}

func TestNativeShareEpochStrictSchema(t *testing.T) {
	p, pub, _, now := nativeShareEpochFixture(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "metadata", "wrapped"} {
		fields := root
		if scope != "" {
			fields = make(map[string]json.RawMessage)
			if err := json.Unmarshal(root[scope], &fields); err != nil {
				t.Fatal(err)
			}
		}
		for name, value := range fields {
			for _, mutation := range []string{"null", "missing", "case alias", "duplicate"} {
				t.Run(scope+"/"+name+"/"+mutation, func(t *testing.T) {
					var changedRoot map[string]json.RawMessage
					if err := json.Unmarshal(raw, &changedRoot); err != nil {
						t.Fatal(err)
					}
					changedFields := changedRoot
					if scope != "" {
						changedFields = make(map[string]json.RawMessage)
						if err := json.Unmarshal(changedRoot[scope], &changedFields); err != nil {
							t.Fatal(err)
						}
					}
					switch mutation {
					case "null":
						changedFields[name] = json.RawMessage(`null`)
					case "missing":
						delete(changedFields, name)
					case "case alias":
						delete(changedFields, name)
						changedFields[strings.ToUpper(name[:1])+name[1:]] = value
					}
					if scope != "" {
						changedRoot[scope], err = json.Marshal(changedFields)
						if err != nil {
							t.Fatal(err)
						}
					}
					input, err := json.Marshal(changedRoot)
					if err != nil {
						t.Fatal(err)
					}
					if mutation == "duplicate" {
						key := []byte(`"` + name + `":`)
						repeated := append(append(append([]byte(nil), key...), value...), ',')
						repeated = append(repeated, key...)
						input = bytes.Replace(input, key, repeated, 1)
					}
					if _, err := DecodeNativeShareEpochPackage(input, p.Metadata, pub, now); err == nil {
						t.Fatal("accepted noncanonical schema")
					}
				})
			}
		}
	}
}
