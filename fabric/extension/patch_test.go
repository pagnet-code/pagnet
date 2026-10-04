package extension

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

func patchEnvelope() fabric.Envelope {
	return fabric.Envelope{ProtocolVersion: "1.0", ID: "original", Operation: fabric.OperationDiscover, Principal: fabric.Principal{Ref: "caller", Kind: "actor.agent", Issuer: "local"}, Source: "caller", CreatedAt: time.Unix(1, 0).UTC(), Payload: json.RawMessage(`{"value":1,"items":[1,2],"big":9007199254740993,"a/b":{"~":true}}`), Context: fabric.EnvelopeContext{Origin: "caller"}, Metadata: map[string]json.RawMessage{"extensions.acme.security.level": json.RawMessage(`"private"`), "extensions.other.audit.level": json.RawMessage(`"protected"`)}}
}

func TestPatchAtomicAndProtected(t *testing.T) {
	cases := []string{
		`[{"op":"replace","path":"/principal/ref","value":"admin"}]`,
		`[{"op":"replace","path":"/target","value":"payroll"}]`,
		`[{"op":"replace","path":"/context/extensionChain","value":[]}]`,
		`[{"op":"remove","path":"/metadata"}]`,
		`[{"op":"replace","path":"/metadata/extensions.other.audit.level","value":"public"}]`,
		`[{"op":"copy","from":"/principal","path":"/payload/stolen"}]`,
		`[{"op":"move","from":"/metadata/extensions.other.audit.level","path":"/payload/stolen"}]`,
		`[{"op":"replace","path":"/payload/value","value":2},{"op":"remove","path":"/payload/missing"}]`,
		`[{"op":"add","path":"/payload/items/-1","value":3}]`,
		`[{"op":"test","path":"/payload/items/01","value":2}]`,
		`[{"op":"test","path":"/payload/big","value":9007199254740992}]`,
		`[{"op":"move","from":"/payload/items","path":"/payload/items/0"}]`,
		`[{"op":"add","path":"/payload/a~2b","value":true}]`,
		`[{"op":"add","op":"remove","path":"/payload/value","value":2}]`,
		`[{"op":"add","path":"/payload/value"}]`,
		`[{"op":"replace","path":"/payload/value","value":2},{"op":"test","path":"/payload/value","value":1}]`,
	}
	for _, patch := range cases {
		t.Run(patch, func(t *testing.T) {
			original := patchEnvelope()
			before, _ := json.Marshal(original)
			got, err := ApplyPatch(original, "acme.security", []byte(patch))
			if err == nil || !reflect.DeepEqual(got, fabric.Envelope{}) {
				t.Fatalf("unsafe mutation accepted: %v", err)
			}
			after, _ := json.Marshal(original)
			if string(before) != string(after) {
				t.Fatal("failed patch mutated original")
			}
		})
	}
}

func TestPatchAllRFCOperationsAndNumberEquality(t *testing.T) {
	original := patchEnvelope()
	patch := `[
 {"op":"test","path":"/payload/value","value":1.00e0},
 {"op":"test","path":"/payload/a~1b/~0","value":true},
 {"op":"add","path":"/payload/items/-","value":3},
 {"op":"copy","from":"/payload/value","path":"/payload/copied"},
 {"op":"move","from":"/payload/copied","path":"/payload/moved"},
 {"op":"replace","path":"/payload/value","value":4,"ignored":true},
 {"op":"remove","path":"/payload/items/0"},
 {"op":"replace","path":"/metadata/extensions.acme.security.level","value":"checked"} ]`
	got, err := ApplyPatch(original, "acme.security", []byte(patch))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if fabric.DecodeJSON(got.Payload, &body) != nil {
		t.Fatal("bad payload")
	}
	if body["value"] != json.Number("4") || body["moved"] != json.Number("1") {
		t.Fatal(body)
	}
	if got.ID != original.ID || got.Principal != original.Principal || got.Metadata["extensions.other.audit.level"] == nil {
		t.Fatal("system fields changed")
	}
	if string(original.Metadata["extensions.acme.security.level"]) != `"private"` {
		t.Fatal("alias mutation")
	}
}

func TestExactDecimalEquality(t *testing.T) {
	for _, pair := range [][2]string{{"1", "1.0"}, {"10e-1", "0.1e1"}, {"-0", "0.000e999999999999999999999999999"}, {"100e999999999999999999999999", "1e1000000000000000000000001"}, {"-120.0", "-12e1"}} {
		if !equalJSON(json.Number(pair[0]), json.Number(pair[1])) {
			t.Fatalf("unequal %v", pair)
		}
	}
	for _, pair := range [][2]string{{"9007199254740993", "9007199254740992"}, {"1e99999999999999", "1e99999999999998"}, {"-1", "1"}} {
		if equalJSON(json.Number(pair[0]), json.Number(pair[1])) {
			t.Fatalf("false equality %v", pair)
		}
	}
}

func FuzzPatchProtectedFields(f *testing.F) {
	f.Add([]byte(`[{"op":"replace","path":"/payload/value","value":2}]`))
	f.Add([]byte(`[{"op":"copy","from":"/principal","path":"/payload"}]`))
	f.Fuzz(func(t *testing.T, patch []byte) {
		original := patchEnvelope()
		got, err := ApplyPatch(original, "acme.security", patch)
		if err != nil {
			return
		}
		a, b := original, got
		a.Payload = nil
		b.Payload = nil
		a.Metadata = nil
		b.Metadata = nil
		if !reflect.DeepEqual(a, b) {
			t.Fatal("protected fields changed")
		}
		if string(got.Metadata["extensions.other.audit.level"]) != string(original.Metadata["extensions.other.audit.level"]) {
			t.Fatal("foreign namespace changed")
		}
	})
}
