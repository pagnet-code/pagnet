package transport

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func standbyTestFrames() []ManagedBrowserStandbyFrame {
	const id = "10000000-0000-4000-8000-000000000001"
	const expiry = "2026-11-09T12:00:00.123456789Z"
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	session := func(kind string) ManagedBrowserStandbySession { return ManagedBrowserStandbySession{1, kind, id, 1} }
	tuple := ManagedBrowserStandbyTuple{id, id, id, id, id, "chatgpt", 1, id, id, 1, id, 1, strings.Repeat("ab", 32)}
	return []ManagedBrowserStandbyFrame{
		ManagedBrowserStandbyChallenge{session("challenge"), tuple, nonce, 5000, false},
		ManagedBrowserStandbyAck{session("ack"), nonce},
		ManagedBrowserStandby{session("standby"), 0, expiry, expiry, 10000, false},
		ManagedBrowserStandbyHeartbeat{session("heartbeat"), 1},
		ManagedBrowserStandbyHeartbeatAck{session("heartbeat_ack"), 1, expiry, expiry, 10000, false},
	}
}
func standbyTestObject(t *testing.T, f ManagedBrowserStandbyFrame) map[string]any {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}
func standbyTestReject(t *testing.T, object map[string]any) {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManagedBrowserStandbyFrame(1, raw); err == nil {
		t.Fatalf("accepted %s", raw)
	}
}
func TestManagedBrowserStandbyRoundTrip(t *testing.T) {
	for _, f := range standbyTestFrames() {
		raw, err := EncodeManagedBrowserStandbyFrame(f)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeManagedBrowserStandbyFrame(1, raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := EncodeManagedBrowserStandbyFrame(decoded)
		if err != nil || string(again) != string(raw) {
			t.Fatalf("round trip: %s %v", again, err)
		}
	}
	if _, err := EncodeManagedBrowserStandbyFrame(nil); err == nil {
		t.Fatal("accepted nil frame")
	}
	var pointer *ManagedBrowserStandbyChallenge
	if _, err := EncodeManagedBrowserStandbyFrame(pointer); err == nil {
		t.Fatal("accepted nil pointer")
	}
}
func TestManagedBrowserStandbyRequiredFields(t *testing.T) {
	for _, f := range standbyTestFrames() {
		original := standbyTestObject(t, f)
		for field := range original {
			for _, operation := range []string{"missing", "null", "duplicate"} {
				t.Run(original["type"].(string)+"/"+field+"/"+operation, func(t *testing.T) {
					object := standbyTestObject(t, f)
					switch operation {
					case "missing":
						delete(object, field)
						standbyTestReject(t, object)
					case "null":
						object[field] = nil
						standbyTestReject(t, object)
					case "duplicate":
						raw, _ := json.Marshal(object)
						value, _ := json.Marshal(object[field])
						raw = append(raw[:len(raw)-1], []byte(",\""+field+"\":"+string(value)+"}")...)
						if _, err := DecodeManagedBrowserStandbyFrame(1, raw); err == nil {
							t.Fatal("accepted duplicate")
						}
					}
				})
			}
		}
		object := standbyTestObject(t, f)
		object["unexpected"] = false
		standbyTestReject(t, object)
		object = standbyTestObject(t, f)
		object["Version"] = object["version"]
		delete(object, "version")
		standbyTestReject(t, object)
	}
}
func TestManagedBrowserStandbyTupleFields(t *testing.T) {
	challenge := standbyTestFrames()[0]
	original := standbyTestObject(t, challenge)["tuple"].(map[string]any)
	for field, value := range original {
		for _, operation := range []string{"missing", "null", "invalid", "duplicate"} {
			t.Run(field+"/"+operation, func(t *testing.T) {
				object := standbyTestObject(t, challenge)
				tuple := object["tuple"].(map[string]any)
				switch operation {
				case "missing":
					delete(tuple, field)
				case "null":
					tuple[field] = nil
				case "invalid":
					if _, ok := value.(float64); ok {
						tuple[field] = 0
					} else {
						tuple[field] = ""
					}
				case "duplicate":
					raw, _ := json.Marshal(object)
					key := "\"" + field + "\":"
					encoded, _ := json.Marshal(value)
					raw = []byte(strings.Replace(string(raw), key, key+string(encoded)+","+key, 1))
					if _, err := DecodeManagedBrowserStandbyFrame(1, raw); err == nil {
						t.Fatal("accepted duplicate tuple field")
					}
					return
				}
				standbyTestReject(t, object)
			})
		}
	}
	object := standbyTestObject(t, challenge)
	object["tuple"].(map[string]any)["extra"] = 1
	standbyTestReject(t, object)
	for _, fingerprint := range []string{strings.Repeat("AB", 32), strings.Repeat("aa", 31), strings.Repeat("gg", 32)} {
		object := standbyTestObject(t, challenge)
		object["tuple"].(map[string]any)["policyFingerprint"] = fingerprint
		standbyTestReject(t, object)
	}
	for _, field := range []string{"connectionId", "bindingId", "networkId", "principalId", "hostId", "leaseId", "instanceId", "credentialId"} {
		object := standbyTestObject(t, challenge)
		object["tuple"].(map[string]any)[field] = "not-a-uuid"
		standbyTestReject(t, object)
	}
}
func TestManagedBrowserStandbyValues(t *testing.T) {
	for _, f := range standbyTestFrames() {
		original := standbyTestObject(t, f)
		mutations := map[string][]any{
			"version": {0, 2, "1", 1.5}, "sessionId": {"", "invalid"}, "sessionGeneration": {0, -1, 1.5, "1"},
		}
		if _, ok := original["executionReady"]; ok {
			mutations["executionReady"] = []any{true, 0, "false"}
		}
		if _, ok := original["nonce"]; ok {
			mutations["nonce"] = []any{"", strings.Repeat("a", 42), strings.Repeat("a", 44), original["nonce"].(string) + "="}
		}
		if _, ok := original["validForMs"]; ok {
			max := 10000
			if original["type"] == "challenge" {
				max = 5000
			}
			mutations["validForMs"] = []any{0, -1, max + 1, 1.5}
			object := standbyTestObject(t, f)
			object["validForMs"] = 1
			raw, _ := json.Marshal(object)
			if _, err := DecodeManagedBrowserStandbyFrame(1, raw); err != nil {
				t.Fatal("rejected lower validity boundary", err)
			}
		}
		if _, ok := original["sequence"]; ok {
			mutations["sequence"] = []any{-1, 1.5, "1"}
			if original["type"] == "standby" {
				mutations["sequence"] = append(mutations["sequence"], 1)
			} else {
				mutations["sequence"] = append(mutations["sequence"], 0)
			}
		}
		for _, field := range []string{"leaseExpiresAt", "credentialExpiresAt"} {
			if _, ok := original[field]; ok {
				mutations[field] = []any{"", "2026-11-09T12:00:00+00:00", "2026-11-09T13:00:00+01:00", "2026-11-09T12:00:00", "invalid"}
			}
		}
		for field, values := range mutations {
			for _, value := range values {
				t.Run(original["type"].(string)+"/"+field+"/"+reflect.TypeOf(value).String(), func(t *testing.T) {
					object := standbyTestObject(t, f)
					object[field] = value
					standbyTestReject(t, object)
				})
			}
		}
	}
}
func TestManagedBrowserStandbyRejectOtherProtocols(t *testing.T) {
	for _, kind := range []string{"mcp", "request", "response", "discovery", "initialize", "tools/list", "tools/call", "heartbeatAck"} {
		object := standbyTestObject(t, standbyTestFrames()[0])
		object["type"] = kind
		standbyTestReject(t, object)
	}
	for _, raw := range []string{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"result":{}}`, `{"type":"discovery","capabilities":{}}`} {
		if _, err := DecodeManagedBrowserStandbyFrame(1, []byte(raw)); err == nil {
			t.Fatal("accepted other protocol", raw)
		}
	}
}
func TestManagedBrowserStandbyJSONBoundary(t *testing.T) {
	raw, _ := EncodeManagedBrowserStandbyFrame(standbyTestFrames()[0])
	for _, kind := range []int{0, 2, 8, 9, 10} {
		if _, err := DecodeManagedBrowserStandbyFrame(kind, raw); err == nil {
			t.Fatal("accepted non-text", kind)
		}
	}
	for _, bad := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("true"), append(append([]byte{}, raw...), []byte(" {}")...), append(append([]byte{}, raw...), 0xff), raw[:len(raw)-1]} {
		if _, err := DecodeManagedBrowserStandbyFrame(1, bad); err == nil {
			t.Fatalf("accepted malformed %q", bad)
		}
	}
	padded := append(append([]byte{}, raw...), []byte(strings.Repeat(" ", MaxManagedBrowserStandbyFrameBytes-len(raw)))...)
	if _, err := DecodeManagedBrowserStandbyFrame(1, padded); err != nil {
		t.Fatal("rejected 8KiB boundary", err)
	}
	if _, err := DecodeManagedBrowserStandbyFrame(1, append(padded, ' ')); err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestManagedBrowserStandbyValidation(t *testing.T) {
	for _, f := range standbyTestFrames() {
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	challenge := standbyTestFrames()[0].(ManagedBrowserStandbyChallenge)
	if err := challenge.Tuple.Validate(); err != nil {
		t.Fatal(err)
	}
	challenge.ExecutionReady = true
	if challenge.Validate() == nil {
		t.Fatal("validation accepted execution readiness")
	}
	if _, err := EncodeManagedBrowserStandbyFrame(challenge); err == nil {
		t.Fatal("encoding accepted execution readiness")
	}
	heartbeat := standbyTestFrames()[3].(ManagedBrowserStandbyHeartbeat)
	heartbeat.Sequence = 0
	if heartbeat.Validate() == nil {
		t.Fatal("validation accepted heartbeat sequence zero")
	}
	if _, err := EncodeManagedBrowserStandbyFrame(heartbeat); err == nil {
		t.Fatal("encoding accepted heartbeat sequence zero")
	}
}

func TestManagedBrowserStandbyCanonicalIDs(t *testing.T) {
	const canonical = "abcdef12-3456-4789-abcd-ef1234567890"
	aliases := []string{
		strings.ToUpper(canonical),
		strings.ReplaceAll(canonical, "-", ""),
		"{" + canonical + "}",
		"urn:uuid:" + canonical,
		"00000000-0000-0000-0000-000000000000",
	}
	for _, f := range standbyTestFrames() {
		for _, id := range aliases {
			object := standbyTestObject(t, f)
			object["sessionId"] = id
			standbyTestReject(t, object)
		}
	}
	for _, field := range []string{"connectionId", "bindingId", "networkId", "principalId", "hostId", "leaseId", "instanceId", "credentialId"} {
		for _, id := range aliases {
			object := standbyTestObject(t, standbyTestFrames()[0])
			object["tuple"].(map[string]any)[field] = id
			standbyTestReject(t, object)
		}
	}
	if !managedBrowserStandbyID(canonical) {
		t.Fatal("rejected canonical lowercase UUID")
	}
}

func TestManagedBrowserStandbyTimestamps(t *testing.T) {
	accepted := map[string]string{
		"2026-11-09T12:00:00Z":           "2026-11-09T12:00:00Z",
		"2026-11-09T12:00:00.000Z":       "2026-11-09T12:00:00Z",
		"2026-11-09T12:00:00.100Z":       "2026-11-09T12:00:00.1Z",
		"2026-11-09T12:00:00.123456789Z": "2026-11-09T12:00:00.123456789Z",
	}
	rejected := []string{
		"2026-11-09T12:00:00,100Z",
		"2026-11-09T2:00:00Z",
		"2026-11-09T12:00:00.Z",
		"2026-11-09T12:00:00.1234567890Z",
		"2026-11-09T12:00:00+00:00",
		"2026-11-09T12:00:00z",
		"2026-11-09t12:00:00Z",
		"2026-11-09T24:00:00Z",
		"2026-11-09T12:60:00Z",
		"2026-11-09T12:00:60Z",
		"2026-02-30T12:00:00Z",
	}
	for _, index := range []int{2, 4} {
		for _, field := range []string{"leaseExpiresAt", "credentialExpiresAt"} {
			for input, canonical := range accepted {
				object := standbyTestObject(t, standbyTestFrames()[index])
				object[field] = input
				raw, _ := json.Marshal(object)
				decoded, err := DecodeManagedBrowserStandbyFrame(1, raw)
				if err != nil {
					t.Fatalf("rejected %s: %v", input, err)
				}
				if err := decoded.Validate(); err != nil {
					t.Fatalf("validation rejected %s: %v", input, err)
				}
				encoded, err := EncodeManagedBrowserStandbyFrame(decoded)
				if err != nil {
					t.Fatal(err)
				}
				var normalized map[string]any
				if err := json.Unmarshal(encoded, &normalized); err != nil {
					t.Fatal(err)
				}
				if normalized[field] != canonical {
					t.Fatalf("encoded timestamp %v, want %s", normalized[field], canonical)
				}
				if standbyTestObject(t, decoded)[field] != input {
					t.Fatal("encoding mutated input frame")
				}
			}
			for _, input := range rejected {
				object := standbyTestObject(t, standbyTestFrames()[index])
				object[field] = input
				standbyTestReject(t, object)
			}
		}
	}
}
