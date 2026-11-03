package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

func nativeShareStageReceiptFixture(t *testing.T) (NativeShareEpochStageReceipt, ed25519.PublicKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	r := NativeShareEpochStageReceipt{Version: 1, BindingID: "11111111-1111-4111-8111-111111111111", OperationID: "22222222-2222-4222-8222-222222222222", Digest: strings.Repeat("ab", 32)}
	raw, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(key, raw)
	return r, key.Public().(ed25519.PublicKey)
}

func TestNativeShareEpochStageReceiptCanonicalCompatibility(t *testing.T) {
	r, host := nativeShareStageReceiptFixture(t)
	raw, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `pagnet/native-share-epoch/staged/v1/{"version":1,"bindingId":"11111111-1111-4111-8111-111111111111","operationId":"22222222-2222-4222-8222-222222222222","digest":"abababababababababababababababababababababababababababababababab","signature":null}`
	if string(raw) != want {
		t.Fatalf("changed original signed transcript: %s", raw)
	}
	if !ed25519.Verify(host, []byte(want), r.Signature) {
		t.Fatal("signature does not verify with original transcript")
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeShareEpochStageReceipt(wire)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatalf("round trip: %v", err)
	}
	if err := decoded.Verify(r.BindingID, r.OperationID, host); err != nil {
		t.Fatal(err)
	}
}

func TestNativeShareEpochStageReceiptRejectsTamperingAndReplay(t *testing.T) {
	r, host := nativeShareStageReceiptFixture(t)
	other := domain.ID("33333333-3333-4333-8333-333333333333")
	cases := map[string]func(*NativeShareEpochStageReceipt){
		"version":              func(r *NativeShareEpochStageReceipt) { r.Version = 2 },
		"binding":              func(r *NativeShareEpochStageReceipt) { r.BindingID = other },
		"operation":            func(r *NativeShareEpochStageReceipt) { r.OperationID = other },
		"digest":               func(r *NativeShareEpochStageReceipt) { r.Digest = strings.Repeat("cd", 32) },
		"uppercase digest":     func(r *NativeShareEpochStageReceipt) { r.Digest = strings.ToUpper(r.Digest) },
		"short digest":         func(r *NativeShareEpochStageReceipt) { r.Digest = "ab" },
		"invalid digest":       func(r *NativeShareEpochStageReceipt) { r.Digest = strings.Repeat("zz", 32) },
		"nil binding":          func(r *NativeShareEpochStageReceipt) { r.BindingID = "00000000-0000-0000-0000-000000000000" },
		"invalid operation":    func(r *NativeShareEpochStageReceipt) { r.OperationID = "invalid" },
		"noncanonical binding": func(r *NativeShareEpochStageReceipt) { r.BindingID = "11111111111141118111111111111111" },
		"signature":            func(r *NativeShareEpochStageReceipt) { r.Signature[0] ^= 1 },
		"short signature":      func(r *NativeShareEpochStageReceipt) { r.Signature = r.Signature[:63] },
		"long signature":       func(r *NativeShareEpochStageReceipt) { r.Signature = append(r.Signature, 0) },
		"missing signature":    func(r *NativeShareEpochStageReceipt) { r.Signature = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			changed := r
			changed.Signature = append([]byte(nil), r.Signature...)
			change(&changed)
			if changed.Verify(r.BindingID, r.OperationID, host) == nil {
				t.Fatal("accepted tampered receipt")
			}
		})
	}
	for name, expected := range map[string][2]domain.ID{"binding replay": {other, r.OperationID}, "operation replay": {r.BindingID, other}, "missing binding": {"", r.OperationID}, "missing operation": {r.BindingID, ""}} {
		t.Run(name, func(t *testing.T) {
			if r.Verify(expected[0], expected[1], host) == nil {
				t.Fatal("accepted wrong expected context")
			}
		})
	}
	wrongHost := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, key := range []ed25519.PublicKey{nil, host[:31], append(append(ed25519.PublicKey(nil), host...), 0), wrongHost} {
		if r.Verify(r.BindingID, r.OperationID, key) == nil {
			t.Fatal("accepted wrong recipient host")
		}
	}
}

func TestDecodeNativeShareEpochStageReceiptStrict(t *testing.T) {
	r, _ := nativeShareStageReceiptFixture(t)
	wire, _ := json.Marshal(r)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{"missing", "null", "duplicate", "case", "object", "array", "wrong type"} {
				t.Run(kind, func(t *testing.T) {
					copyFields := make(map[string]json.RawMessage)
					for k, v := range fields {
						copyFields[k] = v
					}
					switch kind {
					case "missing":
						delete(copyFields, name)
					case "null":
						copyFields[name] = json.RawMessage(`null`)
					case "case":
						copyFields[strings.ToUpper(name)] = copyFields[name]
						delete(copyFields, name)
					case "object":
						copyFields[name] = json.RawMessage(`{}`)
					case "array":
						copyFields[name] = json.RawMessage(`[]`)
					case "wrong type":
						copyFields[name] = json.RawMessage(`true`)
					}
					raw, _ := json.Marshal(copyFields)
					if kind == "duplicate" {
						raw = append(raw[:len(raw)-1], []byte(`,"`+name+`":`+string(fields[name])+`}`)...)
					}
					if decoded, err := DecodeNativeShareEpochStageReceipt(raw); err == nil || !reflect.DeepEqual(decoded, NativeShareEpochStageReceipt{}) {
						t.Fatal("accepted malformed receipt or returned partial receipt")
					}
				})
			}
		})
	}
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]", "truncated": string(wire[:len(wire)-1]),
		"trailing object": string(wire) + `{}`, "trailing scalar": string(wire) + ` true`,
		"unknown":             strings.TrimSuffix(string(wire), "}") + `,"extra":1}`,
		"oversized":           string(wire) + strings.Repeat(" ", 4<<10),
		"invalid version":     strings.Replace(string(wire), `"version":1`, `"version":2`, 1),
		"uppercase digest":    strings.Replace(string(wire), r.Digest, strings.ToUpper(r.Digest), 1),
		"short signature":     strings.Replace(string(wire), base64.StdEncoding.EncodeToString(r.Signature), base64.StdEncoding.EncodeToString(r.Signature[:63]), 1),
		"noncanonical base64": strings.Replace(string(wire), base64.StdEncoding.EncodeToString(r.Signature), base64.StdEncoding.EncodeToString(r.Signature)+`\n`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNativeShareEpochStageReceipt([]byte(raw)); err == nil {
				t.Fatal("accepted malformed receipt")
			}
		})
	}
}
