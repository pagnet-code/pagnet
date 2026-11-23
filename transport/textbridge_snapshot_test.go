package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func snapshotWireFixture(t *testing.T) (SignedSnapshotPreparation, ed25519.PrivateKey, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	id := "10000000-0000-4000-8000-000000000001"
	transcript := SnapshotPreparedTranscript{
		Binding: SnapshotPreparationBinding{InstallationID: id, ServiceID: id, Generation: 1, TenantID: id, HostID: id, Target: SnapshotTarget{id, 3, "sha256:" + strings.Repeat("ab", 32)}, RunnerID: id, Epoch: "2026-11-03T10:00:00.123456Z", BootID: "boot-id", ServerAudience: "https://server.example", ServerChallenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), ServerRevision: 2},
		Profile: SnapshotDescriptor{SnapshotProfileVersion, "sha256:" + strings.Repeat("cd", 32), false, 16000, 16000, 128 << 10, 30, 4096, 1, 9}, IssuedAt: 10000, ExpiresAt: 10060,
	}
	s, err := SignSnapshotPreparation(transcript, key)
	if err != nil {
		t.Fatal(err)
	}
	return s, key, time.Unix(10000, 0)
}

func TestSnapshotWireGolden(t *testing.T) {
	s, key, now := snapshotWireFixture(t)
	raw, err := EncodeSnapshotPreparation(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSnapshotPreparation(raw, s.Transcript, now, key.Public().(ed25519.PublicKey))
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal("round trip", err)
	}
	transcript, err := s.Transcript.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	const golden = `{"binding":{"installationId":"10000000-0000-4000-8000-000000000001","serviceId":"10000000-0000-4000-8000-000000000001","generation":1,"tenantId":"10000000-0000-4000-8000-000000000001","hostId":"10000000-0000-4000-8000-000000000001","target":{"agentId":"10000000-0000-4000-8000-000000000001","definitionRevision":3,"definitionFingerprint":"sha256:abababababababababababababababababababababababababababababababab"},"runnerId":"10000000-0000-4000-8000-000000000001","epoch":"2026-11-03T10:00:00.123456Z","bootId":"boot-id","serverAudience":"https://server.example","serverChallenge":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","serverRevision":2},"profile":{"version":"textbridge_snapshot_v2","digest":"sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","executionReady":false,"maxInputChars":16000,"maxOutputChars":16000,"maxResponseBytes":131072,"requestTimeoutSeconds":30,"maxTokens":4096,"maxConcurrent":1,"callsPerDay":9},"issuedAt":10000,"expiresAt":10060}`
	if string(transcript) != PreparedSnapshotDomain+golden {
		t.Fatalf("golden transcript changed: %s", transcript)
	}
	// Fixed seed and transcript make the signature independently reproducible.
	if hex.EncodeToString(s.Signature) != "5892183d6df7ac7615a2893c268904d22d11d42a73af93707269006fa66577f0843f4389c31da9b230eab86630016e90056e33899107c8c469fae04c2bf17c0e" {
		t.Fatal("golden signature changed")
	}
}

func TestSnapshotWireStrictJSON(t *testing.T) {
	s, key, now := snapshotWireFixture(t)
	raw, _ := EncodeSnapshotPreparation(s)
	input := string(raw)
	bad := map[string]string{
		"space": " " + input, "trailing": input + "\n", "second object": input + "{}", "null": "null", "array": "[]", "unknown": strings.Replace(input, `"transcript":`, `"unknown":0,"transcript":`, 1),
		"duplicate": strings.Replace(input, `"generation":1`, `"generation":1,"generation":1`, 1),
		"case":      strings.Replace(input, `"generation"`, `"Generation"`, 1), "escape": strings.Replace(input, "boot-id", `boot\u002did`, 1),
		"null bool": strings.Replace(input, `"executionReady":false`, `"executionReady":null`, 1), "missing bool": strings.Replace(input, `"executionReady":false,`, "", 1),
		"float": strings.Replace(input, `"generation":1`, `"generation":1.0`, 1), "integer overflow": strings.Replace(input, `"generation":1`, `"generation":9223372036854775808`, 1),
		"signature array": strings.Replace(input, `"signature":"`+base64.StdEncoding.EncodeToString(s.Signature)+`"`, `"signature":[1,2,3]`, 1),
		"invalid utf8":    strings.Replace(input, "boot-id", "boot-\xff", 1), "oversize": strings.Repeat(" ", MaxSnapshotPreparationBytes+1),
	}
	for name, input := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeSnapshotPreparation([]byte(input), s.Transcript, now, key.Public().(ed25519.PublicKey))
			if err == nil || !reflect.DeepEqual(got, SignedSnapshotPreparation{}) {
				t.Fatal("accepted malformed encoding")
			}
		})
	}
}

func TestSnapshotWireTypedValidation(t *testing.T) {
	s, key, now := snapshotWireFixture(t)
	bad := map[string]func(*SnapshotPreparedTranscript){
		"id": func(t *SnapshotPreparedTranscript) { t.Binding.HostID = "host" }, "nil id": func(t *SnapshotPreparedTranscript) { t.Binding.Target.AgentID = "00000000-0000-0000-0000-000000000000" },
		"epoch offset": func(t *SnapshotPreparedTranscript) { t.Binding.Epoch = "2026-11-03T10:00:00.123456+00:00" }, "epoch nanos": func(t *SnapshotPreparedTranscript) { t.Binding.Epoch = "2026-11-03T10:00:00.123456789Z" },
		"audience case": func(t *SnapshotPreparedTranscript) { t.Binding.ServerAudience = "https://SERVER.example" }, "audience remote http": func(t *SnapshotPreparedTranscript) { t.Binding.ServerAudience = "http://server.example" }, "audience query": func(t *SnapshotPreparedTranscript) { t.Binding.ServerAudience = "https://server.example?" },
		"challenge": func(t *SnapshotPreparedTranscript) { t.Binding.ServerChallenge = "challenge" }, "challenge padded": func(t *SnapshotPreparedTranscript) { t.Binding.ServerChallenge += "=" },
		"utf8": func(t *SnapshotPreparedTranscript) { t.Binding.BootID = "\xff" }, "ready": func(t *SnapshotPreparedTranscript) { t.Profile.ExecutionReady = true },
		"bounds": func(t *SnapshotPreparedTranscript) { t.Profile.MaxTokens++ }, "allowance": func(t *SnapshotPreparedTranscript) { t.Profile.CallsPerDay = 0 }, "digest": func(t *SnapshotPreparedTranscript) { t.Profile.Digest = "sha256:" + strings.Repeat("AB", 32) },
		"overflow": func(t *SnapshotPreparedTranscript) { t.IssuedAt = math.MinInt64; t.ExpiresAt = math.MaxInt64 }, "negative": func(t *SnapshotPreparedTranscript) { t.IssuedAt = -1; t.ExpiresAt = 60 }, "zero": func(t *SnapshotPreparedTranscript) { t.IssuedAt = 0 }, "duration": func(t *SnapshotPreparedTranscript) { t.ExpiresAt = t.IssuedAt + 301 },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			bad := s.Transcript
			mutate(&bad)
			if _, err := SignSnapshotPreparation(bad, key); err == nil {
				t.Fatal("signed invalid transcript")
			}
			raw, _ := json.Marshal(bad)
			sig := ed25519.Sign(key, append([]byte(PreparedSnapshotDomain), raw...))
			if (SignedSnapshotPreparation{bad, sig}).Verify(bad, now, key.Public().(ed25519.PublicKey)) == nil {
				t.Fatal("verified invalid transcript")
			}
		})
	}
	for _, audience := range []string{"http://127.0.0.1:8080", "http://[::1]:8080", "https://server.example/pagnet"} {
		tt := s.Transcript
		tt.Binding.ServerAudience = audience
		if tt.Validate() != nil {
			t.Fatal("rejected valid audience", audience)
		}
	}
	// Near MaxInt64 is safe when ordered and within the short lifetime.
	tt := s.Transcript
	tt.IssuedAt = math.MaxInt64 - 60
	tt.ExpiresAt = math.MaxInt64
	if tt.Validate() != nil {
		t.Fatal("overflow-safe valid lifetime rejected")
	}
}

func TestSnapshotWireSignatureTrust(t *testing.T) {
	s, key, now := snapshotWireFixture(t)
	public := key.Public().(ed25519.PublicKey)
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	for name, check := range map[string]func() error{
		"pinned key": func() error { return s.Verify(s.Transcript, now, wrong) }, "expired": func() error { return s.Verify(s.Transcript, time.Unix(s.Transcript.ExpiresAt, 0), public) }, "future": func() error { return s.Verify(s.Transcript, now.Add(-time.Second), public) },
		"expected": func() error {
			expected := s.Transcript
			expected.Binding.ServerRevision++
			return s.Verify(expected, now, public)
		},
		"signature": func() error {
			copy := s
			copy.Signature = bytes.Repeat([]byte{0}, 64)
			return copy.Verify(s.Transcript, now, public)
		},
		"domain": func() error {
			copy := s
			raw, _ := json.Marshal(s.Transcript)
			copy.Signature = ed25519.Sign(key, raw)
			return copy.Verify(s.Transcript, now, public)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if check() == nil {
				t.Fatal("accepted untrusted signature")
			}
		})
	}
}

func TestSnapshotWireEveryTranscriptFieldBound(t *testing.T) {
	s, key, now := snapshotWireFixture(t)
	var visit func(reflect.Value, []int, string)
	visit = func(v reflect.Value, path []int, name string) {
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			next := append(append([]int(nil), path...), i)
			label := name + "/" + v.Type().Field(i).Name
			if field.Kind() == reflect.Struct {
				visit(field, next, label)
				continue
			}
			t.Run(label, func(t *testing.T) {
				changed := s
				leaf := reflect.ValueOf(&changed.Transcript).Elem().FieldByIndex(next)
				switch leaf.Kind() {
				case reflect.String:
					leaf.SetString(leaf.String() + "x")
				case reflect.Int, reflect.Int64:
					leaf.SetInt(leaf.Int() + 1)
				case reflect.Bool:
					leaf.SetBool(!leaf.Bool())
				default:
					t.Fatal("unhandled transcript field")
				}
				public := key.Public().(ed25519.PublicKey)
				if changed.Verify(changed.Transcript, now, public) == nil {
					t.Fatal("accepted tampered transcript")
				}
				if s.Verify(changed.Transcript, now, public) == nil {
					t.Fatal("ignored independently expected transcript")
				}
			})
		}
	}
	visit(reflect.ValueOf(s.Transcript), nil, "")
}

func TestSnapshotTargetFingerprintServerMapping(t *testing.T) {
	s, _, _ := snapshotWireFixture(t)
	target := s.Transcript.Binding.Target
	serverFingerprint := bytes.Repeat([]byte{0xab}, 32)
	raw, err := hex.DecodeString(strings.TrimPrefix(target.DefinitionFingerprint, "sha256:"))
	if err != nil || !bytes.Equal(raw, serverFingerprint) {
		t.Fatal("wire fingerprint does not map to raw managed definition fingerprint")
	}
	if target.DefinitionFingerprint != "sha256:"+hex.EncodeToString(serverFingerprint) {
		t.Fatal("server fingerprint canonical representation changed")
	}
}
