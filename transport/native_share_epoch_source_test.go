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
	"time"
)

func nativeShareEpochSourceFixture(t *testing.T) (NativeShareEpochSourceEnvelope, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	recipient, pub, private, now := nativeShareEpochFixture(t)
	digest, err := NativeShareEpochPackageDigest(recipient)
	if err != nil {
		t.Fatal(err)
	}
	p := NativeShareEpochSourceEnvelope{Metadata: NativeShareEpochSourceMetadata{
		Recipient: recipient.Metadata, RecipientPackageDigest: digest,
		Source: NativeShareEpochSourceContext{
			Subject: NativeShareBindingSubject{ServerURL: "https://example.test", TenantID: "10000000-0000-4000-8000-000000000025",
				AccountID: "10000000-0000-4000-8000-000000000017", HostID: "10000000-0000-4000-8000-000000000018",
				NativeAdmissionID: "10000000-0000-4000-8000-000000000019", RunnerID: "10000000-0000-4000-8000-000000000020",
				RunnerEpoch: "2027-01-02T03:00:00Z", BootID: "source-boot", ProfileFingerprint: strings.Repeat("ab", 32)},
			ConnectedAt: "2027-01-02T03:01:00Z", HostCredentialID: "source-credential", OwnershipScope: "source-owner",
			ConnectionID: "source-connection", AuthorityConnectionID: "source-authority", HolderID: "10000000-0000-4000-8000-000000000021",
			HolderX25519: strings.Repeat("ef", 32), SigningKey: hex.EncodeToString(pub),
			ProposalID: "10000000-0000-4000-8000-000000000022", GrantID: "10000000-0000-4000-8000-000000000023", BindingID: "10000000-0000-4000-8000-000000000024"},
	}, Wrapped: CryptoHPKEWrap{Enc: make([]byte, 32), Ciphertext: make([]byte, 48)}}
	raw, err := p.SignatureBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = ed25519.Sign(private, raw)
	return p, pub, private, now
}

func TestNativeShareEpochSourceRoundTrip(t *testing.T) {
	p, pub, _, now := nativeShareEpochSourceFixture(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNativeShareEpochSourceEnvelope(raw, p.Metadata, pub, now)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("round trip failed", err)
	}
	aad, _ := p.Metadata.AAD()
	decodedAAD, _ := got.Metadata.AAD()
	if !bytes.Equal(aad, decodedAAD) || !bytes.HasPrefix(aad, []byte("pagnet/native-share-epoch/source/aad/v1/")) {
		t.Fatal("noncanonical AAD")
	}
}

func TestNativeShareEpochSourcePackageDigest(t *testing.T) {
	p, _, _, _ := nativeShareEpochFixture(t)
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	digest, err := NativeShareEpochPackageDigest(p)
	if err != nil || digest != hex.EncodeToString(sum[:]) {
		t.Fatal("digest does not match canonical signed package", err)
	}
	for _, name := range []string{"ciphertext", "signature", "metadata", "enc"} {
		t.Run(name, func(t *testing.T) {
			changed := p
			switch name {
			case "ciphertext":
				changed.Wrapped.Ciphertext = bytes.Repeat([]byte{1}, 48)
			case "signature":
				changed.Signature = bytes.Repeat([]byte{1}, 64)
			case "enc":
				changed.Wrapped.Enc = bytes.Repeat([]byte{1}, 32)
			case "metadata":
				changed.Metadata.CommandConnectionID = "changed-connection"
			}
			got, err := NativeShareEpochPackageDigest(changed)
			if err != nil || got == digest {
				t.Fatal("package change did not alter digest", err)
			}
		})
	}
	for _, name := range []string{"metadata", "enc", "ciphertext", "signature"} {
		t.Run("invalid/"+name, func(t *testing.T) {
			changed := p
			switch name {
			case "metadata":
				changed.Metadata.Version = 0
			case "enc":
				changed.Wrapped.Enc = nil
			case "ciphertext":
				changed.Wrapped.Ciphertext = nil
			case "signature":
				changed.Signature = nil
			}
			if _, err := NativeShareEpochPackageDigest(changed); err == nil {
				t.Fatal("accepted malformed package")
			}
		})
	}
}

// Walk leaf fields so additions to either nested context automatically need coverage.
func nativeShareEpochSourceLeaves(v reflect.Value, path []int, visit func([]int, string)) {
	for i := 0; i < v.NumField(); i++ {
		next := append(append([]int(nil), path...), i)
		f := v.Field(i)
		if f.Kind() == reflect.Struct {
			nativeShareEpochSourceLeaves(f, next, visit)
		} else {
			visit(next, v.Type().Field(i).Name)
		}
	}
}

func TestNativeShareEpochSourceEveryMetadataFieldBound(t *testing.T) {
	p, pub, private, now := nativeShareEpochSourceFixture(t)
	originalAAD, _ := p.Metadata.AAD()
	nativeShareEpochSourceLeaves(reflect.ValueOf(p.Metadata), nil, func(path []int, name string) {
		names := make([]string, len(path))
		typ := reflect.TypeOf(p.Metadata)
		for i, index := range path {
			member := typ.Field(index)
			names[i] = member.Name
			typ = member.Type
		}
		t.Run(strings.Join(names, "/"), func(t *testing.T) {
			changed := p
			field := reflect.ValueOf(&changed.Metadata).Elem().FieldByIndex(path)
			field.SetZero()
			if _, err := changed.Metadata.AAD(); err == nil {
				t.Fatal("accepted empty field", name)
			}
			changed = p
			field = reflect.ValueOf(&changed.Metadata).Elem().FieldByIndex(path)
			switch field.Kind() {
			case reflect.Int:
				field.SetInt(2)
			case reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.String:
				value := field.String()
				switch {
				case name == "ServerURL":
					value = "https://other.test"
				case name == "Deadline" || name == "RunnerEpoch" || name == "ConnectedAt":
					value = "2027-01-02T03:04:06Z"
				case len(value) == 64:
					value = strings.Repeat("12", 32)
				case len(value) == 36 && strings.Count(value, "-") == 4:
					value = "20000000-0000-4000-8000-000000000001"
				default:
					value = "changed-opaque"
				}
				field.SetString(value)
			}
			if changed.Verify(changed.Metadata, pub, now) == nil {
				t.Fatal("accepted tamper with original signature")
			}
			if name == "Version" {
				return
			}
			aad, err := changed.Metadata.AAD()
			if err != nil || bytes.Equal(aad, originalAAD) {
				t.Fatal("valid field change did not change AAD", name, err)
			}
			raw, err := changed.SignatureBytes()
			if err != nil {
				t.Fatal(err)
			}
			changed.Signature = ed25519.Sign(private, raw)
			if changed.Verify(p.Metadata, pub, now) == nil || p.Verify(changed.Metadata, pub, now) == nil {
				t.Fatal("accepted mismatched independently pinned metadata")
			}
		})
	})
}

func TestNativeShareEpochSourceRejectsMalformedMetadata(t *testing.T) {
	p, _, _, _ := nativeShareEpochSourceFixture(t)
	for name, mutate := range map[string]func(*NativeShareEpochSourceMetadata){
		"same holder":     func(m *NativeShareEpochSourceMetadata) { m.Source.HolderID = m.Recipient.HolderID },
		"same holder key": func(m *NativeShareEpochSourceMetadata) { m.Source.HolderX25519 = m.Recipient.HolderX25519 },

		"uppercase digest":  func(m *NativeShareEpochSourceMetadata) { m.RecipientPackageDigest = strings.Repeat("AB", 32) },
		"short digest":      func(m *NativeShareEpochSourceMetadata) { m.RecipientPackageDigest = "ab" },
		"noncanonical time": func(m *NativeShareEpochSourceMetadata) { m.Source.ConnectedAt = "2027-01-02T03:01:00+00:00" },
		"zero time":         func(m *NativeShareEpochSourceMetadata) { m.Source.ConnectedAt = "0001-01-01T00:00:00Z" },
		"uppercase key":     func(m *NativeShareEpochSourceMetadata) { m.Source.SigningKey = strings.Repeat("AB", 32) },
		"nonhex key":        func(m *NativeShareEpochSourceMetadata) { m.Source.HolderX25519 = strings.Repeat("gg", 32) },
		"zero id":           func(m *NativeShareEpochSourceMetadata) { m.Source.HolderID = "00000000-0000-0000-0000-000000000000" },
		"malformed id":      func(m *NativeShareEpochSourceMetadata) { m.Source.GrantID = "invalid" },
		"whitespace":        func(m *NativeShareEpochSourceMetadata) { m.Source.OwnershipScope = " scope" },
		"newline":           func(m *NativeShareEpochSourceMetadata) { m.Source.HostCredentialID = "credential\nother" },
		"oversize opaque":   func(m *NativeShareEpochSourceMetadata) { m.Source.ConnectionID = strings.Repeat("a", 257) },
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

func TestNativeShareEpochSourceRejectsTamperingAndExpiry(t *testing.T) {
	p, pub, private, now := nativeShareEpochSourceFixture(t)
	_, wrong, _, _ := nativeShareEpochFixture(t)
	for _, key := range []ed25519.PublicKey{wrong, nil, pub[:31]} {
		if p.Verify(p.Metadata, key, now) == nil {
			t.Fatal("accepted wrong signer")
		}
	}
	for _, at := range []time.Time{{}, now.Add(time.Second), now.Add(2 * time.Second)} {
		if p.Verify(p.Metadata, pub, at) == nil {
			t.Fatal("accepted zero time or expiry")
		}
	}
	for name, mutate := range map[string]func(*NativeShareEpochSourceEnvelope){
		"signing key mismatch": func(p *NativeShareEpochSourceEnvelope) { p.Metadata.Source.SigningKey = hex.EncodeToString(wrong) },
		"signature": func(p *NativeShareEpochSourceEnvelope) {
			p.Signature = append([]byte(nil), p.Signature...)
			p.Signature[0] ^= 1
		},
		"missing signature": func(p *NativeShareEpochSourceEnvelope) { p.Signature = nil },
		"short signature":   func(p *NativeShareEpochSourceEnvelope) { p.Signature = p.Signature[:63] },
		"enc":               func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Enc = bytes.Repeat([]byte{1}, 32) },
		"ciphertext":        func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Ciphertext = bytes.Repeat([]byte{1}, 48) },
		"short enc":         func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Enc = make([]byte, 31) },
		"long enc":          func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Enc = make([]byte, 33) },
		"short ciphertext":  func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Ciphertext = make([]byte, 47) },
		"long ciphertext":   func(p *NativeShareEpochSourceEnvelope) { p.Wrapped.Ciphertext = make([]byte, 49) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if name == "signing key mismatch" {
				raw, err := changed.SignatureBytes()
				if err != nil {
					t.Fatal(err)
				}
				changed.Signature = ed25519.Sign(private, raw)
			}
			if changed.Verify(changed.Metadata, pub, now) == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
}

func TestNativeShareEpochSourceStrictDecode(t *testing.T) {
	p, pub, _, now := nativeShareEpochSourceFixture(t)
	raw, _ := json.Marshal(p)
	for name, input := range map[string][]byte{
		"trailing object":    append(append([]byte(nil), raw...), []byte(` {}`)...),
		"trailing null":      append(append([]byte(nil), raw...), []byte(` null`)...),
		"trailing malformed": append(append([]byte(nil), raw...), '!'),
		"oversize":           append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), 16<<10)...),
		"truncated":          raw[:len(raw)-1],
		"numeric revision":   bytes.Replace(raw, []byte(`"proposalRevision":"1"`), []byte(`"proposalRevision":1`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeNativeShareEpochSourceEnvelope(input, p.Metadata, pub, now); err == nil || !reflect.DeepEqual(got, NativeShareEpochSourceEnvelope{}) {
				t.Fatal("accepted malformed wire envelope or returned partial envelope", err)
			}
		})
	}
	var walk func(json.RawMessage, string, func(json.RawMessage) []byte)
	walk = func(node json.RawMessage, path string, rebuild func(json.RawMessage) []byte) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(node, &fields); err != nil {
			t.Fatal(err)
		}
		for name, value := range fields {
			for _, mutation := range []string{"null", "missing", "case alias", "duplicate"} {
				t.Run(path+"/"+name+"/"+mutation, func(t *testing.T) {
					changed := make(map[string]json.RawMessage)
					for k, v := range fields {
						changed[k] = v
					}
					switch mutation {
					case "null":
						changed[name] = json.RawMessage(`null`)
					case "missing":
						delete(changed, name)
					case "case alias":
						delete(changed, name)
						changed[strings.ToUpper(name[:1])+name[1:]] = value
					}
					input, _ := json.Marshal(changed)
					if mutation == "duplicate" {
						key := []byte(`"` + name + `":`)
						repeated := append(append(append([]byte(nil), key...), value...), ',')
						repeated = append(repeated, key...)
						input = bytes.Replace(input, key, repeated, 1)
					}
					if got, err := DecodeNativeShareEpochSourceEnvelope(rebuild(input), p.Metadata, pub, now); err == nil || !reflect.DeepEqual(got, NativeShareEpochSourceEnvelope{}) {
						t.Fatal("accepted noncanonical schema or returned partial envelope", err)
					}
				})
			}
			if len(value) > 0 && value[0] == '{' {
				walk(value, path+"/"+name, func(child json.RawMessage) []byte {
					changed := make(map[string]json.RawMessage)
					for k, v := range fields {
						changed[k] = v
					}
					changed[name] = child
					encoded, _ := json.Marshal(changed)
					return rebuild(encoded)
				})
			}
		}
		t.Run(path+"/unknown", func(t *testing.T) {
			input := append([]byte(`{"unknown":true,`), node[1:]...)
			if got, err := DecodeNativeShareEpochSourceEnvelope(rebuild(input), p.Metadata, pub, now); err == nil || !reflect.DeepEqual(got, NativeShareEpochSourceEnvelope{}) {
				t.Fatal("accepted unknown field or returned partial envelope", err)
			}
		})
	}
	walk(raw, "", func(node json.RawMessage) []byte { return node })
}
