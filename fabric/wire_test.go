package fabric

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsAmbiguousOrMalformedDocumentsBeforeAssignment(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`{"id":1,"id":2}`),
		[]byte(`{"id":1,"\u0069d":2}`),
		[]byte(`{"nested":{"😀":1,"\ud83d\ude00":2}}`),
		[]byte(`[{"x":1,"x":2}]`),
		[]byte(`{"nested":{"secret-token-key":1,"secret-token-key":2}}`),
		[]byte(`{"valid":true} {"another":true}`),
		[]byte(`1 2`), []byte(`true garbage`), []byte(`null]`),
		[]byte(`{"x":1,}`), []byte(`[1,]`), []byte(`{"x" 1}`),
		[]byte(``), []byte(`  `), []byte(`[`), []byte(`{"x":`),
		[]byte(`{"x":01}`), []byte(`NaN`), []byte(`Infinity`),
		[]byte(`"unescaped`), []byte{'"', 0xff, '"'},
		[]byte{'{', '"', 'x', '"', ':', '"', 0xc0, 0xaf, '"', '}'},
	} {
		t.Run(string(input), func(t *testing.T) {
			out := any("untouched")
			err := DecodeJSON(input, &out)
			if err == nil {
				t.Fatal("invalid or ambiguous document accepted")
			}
			if out != "untouched" {
				t.Fatal("invalid document assigned caller output")
			}
			if strings.Contains(err.Error(), "secret-token-key") {
				t.Fatal("error disclosed application member")
			}
		})
	}
}

func TestDecodeJSONPrecisionRawBytesAndOptionalFields(t *testing.T) {
	original := []byte(` {"known":7,"application":{ "large":9007199254740993123456789,"decimal":0.123456789012345678901234567890,"exponent":1e309 },"optional":{"future":true}} `)
	copyInput := append([]byte(nil), original...)
	var typed struct {
		Known       int             `json:"known"`
		Application json.RawMessage `json:"application"`
	}
	if err := DecodeJSON(original, &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Known != 7 || string(typed.Application) != `{ "large":9007199254740993123456789,"decimal":0.123456789012345678901234567890,"exponent":1e309 }` {
		t.Fatal("typed/raw decoding changed application bytes")
	}
	if !bytes.Equal(original, copyInput) {
		t.Fatal("decoder rewrote signed input")
	}
	var application map[string]any
	if err := DecodeJSON(typed.Application, &application); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"large": "9007199254740993123456789", "decimal": "0.123456789012345678901234567890", "exponent": "1e309"} {
		got, ok := application[key].(json.Number)
		if !ok || string(got) != want {
			t.Fatalf("%s lost numeric precision/type", key)
		}
	}
	// Duplicate detection belongs to each object and uses decoded key equality,
	// not Unicode normalization or a global uniqueness constraint.
	for _, input := range []string{`{"a":{"id":1},"b":{"id":2}}`, `{"é":1,"é":2}`, `null`, `false`, `"text"`, `[1,2,3]`} {
		var out any
		if err := DecodeJSON([]byte(input), &out); err != nil {
			t.Fatal(input, err)
		}
	}
}

func TestDecodeJSONLimitsAreWholeDocumentAndInclusive(t *testing.T) {
	input := []byte(`{"a":[1,2],"b":{"c":3}}`)
	limits := WireLimits{MaxBytes: len(input), MaxDepth: 2, MaxMembers: 5}
	var out any
	if err := DecodeJSONWithLimits(input, &out, limits); err != nil {
		t.Fatal("exact bounds rejected", err)
	}
	for _, tooSmall := range []WireLimits{
		{MaxBytes: len(input) - 1, MaxDepth: 2, MaxMembers: 5},
		{MaxBytes: len(input), MaxDepth: 1, MaxMembers: 5},
		{MaxBytes: len(input), MaxDepth: 2, MaxMembers: 4},
	} {
		out = "untouched"
		if err := DecodeJSONWithLimits(input, &out, tooSmall); err == nil {
			t.Fatal("excess document accepted", tooSmall)
		}
		if out != "untouched" {
			t.Fatal("over-budget input assigned output")
		}
	}
	for _, invalid := range []WireLimits{{}, {MaxBytes: -1, MaxDepth: 1, MaxMembers: 1}, {MaxBytes: 1, MaxDepth: 0, MaxMembers: 1}, {MaxBytes: 1, MaxDepth: 1, MaxMembers: 0}} {
		if err := DecodeJSONWithLimits([]byte(`1`), &out, invalid); err == nil {
			t.Fatal("unbounded/invalid configuration accepted")
		}
	}
	deep := []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))
	if err := DecodeJSON(deep, &out); err == nil {
		t.Fatal("default depth limit absent")
	}
	large := []byte(`"` + strings.Repeat("x", DefaultWireLimits.MaxBytes) + `"`)
	if err := DecodeJSON(large, &out); err == nil {
		t.Fatal("default byte limit absent")
	}
	members := []byte("[" + strings.Repeat("0,", DefaultWireLimits.MaxMembers) + "0]")
	if err := DecodeJSON(members, &out); err == nil {
		t.Fatal("default cumulative array-element limit absent")
	}
}

func TestDecodeJSONInvalidTargetsAndTypedMismatch(t *testing.T) {
	var pointer *int
	for _, target := range []any{nil, pointer, 1} {
		if err := DecodeJSON([]byte(`1`), target); err == nil {
			t.Fatal("invalid output target accepted")
		}
	}
	var target struct {
		Value int `json:"value"`
	}
	if err := DecodeJSON([]byte(`{"value":"wrong type"}`), &target); err == nil {
		t.Fatal("typed mismatch accepted")
	}
}

func FuzzDecodeJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"id":1,"\u0069d":2}`), []byte(`{"nested":[{},[null,true,1e309]]}`),
		[]byte(`{"future":{"big":9007199254740993123456789}}`),
		[]byte(`null {}`), []byte(`{"x":1,}`), []byte{'"', 0xff, '"'},
		[]byte(strings.Repeat("[", 65) + strings.Repeat("]", 65)),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		unchanged := append([]byte(nil), data...)
		var out any
		err := DecodeJSON(data, &out)
		if !bytes.Equal(data, unchanged) {
			t.Fatal("original signed bytes mutated")
		}
		if err != nil {
			return
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			t.Fatal("accepted value cannot be encoded", err)
		}
		var roundtrip any
		limits := DefaultWireLimits
		limits.MaxBytes = len(encoded) + 1
		if err := DecodeJSONWithLimits(encoded, &roundtrip, limits); err != nil {
			t.Fatal("accepted value cannot roundtrip", err)
		}
	})
}

func TestDecodeJSONRejectsTypedFieldAliasesBeforeAssignment(t *testing.T) {
	type context struct {
		Principal string `json:"principal"`
	}
	type envelope struct {
		Principal   string          `json:"principal"`
		Context     *context        `json:"context"`
		Contexts    []context       `json:"contexts"`
		Payload     json.RawMessage `json:"payload"`
		Application map[string]any  `json:"application"`
	}
	for _, input := range []string{
		`{"principal":"trusted","Principal":"other"}`,
		`{"Principal":"other"}`,
		`{"\u0050rincipal":"other"}`,
		`{"CONTEXT":{"principal":"other"}}`,
		`{"context":{"principal":"trusted","Principal":"other"}}`,
		`{"contexts":[{"PRINCIPAL":"other"}]}`,
	} {
		t.Run(input, func(t *testing.T) {
			out := envelope{Principal: "untouched"}
			if err := DecodeJSON([]byte(input), &out); err == nil {
				t.Fatal("typed field alias accepted")
			}
			if out.Principal != "untouched" || out.Context != nil || out.Contexts != nil {
				t.Fatal("alias rejection assigned caller output")
			}
		})
	}
	input := []byte(`{"principal":"trusted","context":{"principal":"nested","future":true},"contexts":[{"principal":"array"}],"payload":{"X":1,"x":2},"application":{"X":1,"x":2},"future":{"Principal":"application"}}`)
	var out envelope
	if err := DecodeJSON(input, &out); err != nil {
		t.Fatal(err)
	}
	if out.Principal != "trusted" || out.Context.Principal != "nested" || out.Contexts[0].Principal != "array" || string(out.Payload) != `{"X":1,"x":2}` || len(out.Application) != 2 {
		t.Fatal("known fields or case-sensitive application keys changed")
	}
}

func TestDecodeJSONTypedEmbeddedFieldDominance(t *testing.T) {
	type promoted struct {
		Principal string `json:"principal"`
	}
	type envelope struct {
		promoted
		Principal string `json:"principal"`
	}
	var out envelope
	if err := DecodeJSON([]byte(`{"principal":"direct"}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.Principal != "direct" || out.promoted.Principal != "" {
		t.Fatal("embedded dominance changed")
	}
	if err := DecodeJSON([]byte(`{"Principal":"other"}`), &out); err == nil {
		t.Fatal("promoted field alias accepted")
	}
	type nested struct{ promoted }
	var n nested
	if err := DecodeJSON([]byte(`{"Principal":"other"}`), &n); err == nil {
		t.Fatal("embedded alias accepted")
	}
	if err := DecodeJSON([]byte(`{"principal":"promoted"}`), &n); err != nil {
		t.Fatal(err)
	}
	if n.Principal != "promoted" {
		t.Fatal("promoted field not decoded")
	}
}

func TestDecodeJSONCustomScalar(t *testing.T) {
	ref, err := NewEndpointRef(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	type envelope struct {
		Target EndpointRef `json:"target"`
	}
	input, err := json.Marshal(envelope{Target: ref})
	if err != nil {
		t.Fatal(err)
	}
	var out envelope
	if err := DecodeJSON(input, &out); err != nil {
		t.Fatal(err)
	}
	if out.Target != ref {
		t.Fatal("custom scalar changed")
	}
	if err := DecodeJSON([]byte(`{"Target":"`+ref.String()+`"}`), &out); err == nil {
		t.Fatal("custom scalar containing field alias accepted")
	}
}
