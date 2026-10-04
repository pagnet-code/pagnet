package fabric

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const goldenDomain = "d-rtgfkm3thebydbeu43ni6cmc7awrrdrxp3f6ba45tws4uvcg4fta"
const goldenEndpoint = "pagnet://" + goldenDomain + "/e/eaqseizeeutcokbjfivsyljof4ydcmrtgq2tmnzyhe5dwpb5hy7q"
const goldenOffer = goldenEndpoint + "#o-ibaueq2eivdeoscjjjfuytkoj5ifcustkrkvmv2ylfnfwxc5lzpq"

func testBytes(start byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}
func TestReferenceIndependentGolden(t *testing.T) {
	// Independently derived with Python hashlib/base64.
	d, e := DomainNamespace(testBytes(0))
	if e != nil || d != goldenDomain {
		t.Fatalf("namespace %q: %v", d, e)
	}
	r, e := newEndpointRef(testBytes(0), bytes.NewReader(testBytes(32)))
	if e != nil || r.String() != goldenEndpoint {
		t.Fatalf("endpoint %s: %v", r, e)
	}
	o, e := r.WithOfferID(testBytes(64))
	if e != nil || o.String() != goldenOffer || o.Endpoint() != r || !o.IsOffer() || r.IsOffer() {
		t.Fatalf("offer %s: %v", o, e)
	}
	a, e := NewEndpointRef(testBytes(0))
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewEndpointRef(testBytes(0))
	if e != nil || a == b || a.Domain() != d || b.Domain() != d {
		t.Fatal("random identities not independent")
	}
}
func TestReferenceRejectsNormalizationAndUnusedBits(t *testing.T) {
	invalid := []string{"", strings.ToUpper(goldenEndpoint), goldenEndpoint + "/", goldenEndpoint + "?q=1", goldenEndpoint + "#", goldenEndpoint + "#o-", strings.Replace(goldenEndpoint, "/e/", "/a/", 1), strings.Replace(goldenEndpoint, "pagnet://", "https://", 1), strings.Replace(goldenEndpoint, "d-", "D-", 1), strings.Replace(goldenEndpoint, "/e/", "/%65/", 1), strings.Replace(goldenEndpoint, "/e/", "/é/", 1), " " + goldenEndpoint, goldenEndpoint + "\n", goldenEndpoint[:117] + "r", goldenOffer[:172] + "r", strings.Replace(goldenEndpoint, "g4fta", "g4ftb", 1), strings.Replace(goldenEndpoint, "/e/", "/../e/", 1)}
	for _, s := range invalid {
		if r, e := ParseEndpointRef(s); e == nil || r != (EndpointRef{}) {
			t.Errorf("accepted %q", s)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, e := DomainNamespace(make([]byte, n)); e == nil {
			t.Errorf("key len %d", n)
		}
	}
	if _, e := newEndpointRef(testBytes(0), bytes.NewReader(make([]byte, 31))); e == nil {
		t.Fatal("short entropy accepted")
	}
	r, _ := ParseEndpointRef(goldenEndpoint)
	if _, e := r.WithOfferID(make([]byte, 31)); e == nil {
		t.Fatal("short offer accepted")
	}
	if _, e := (EndpointRef{}).WithOfferID(testBytes(0)); e == nil {
		t.Fatal("zero accepted")
	}
}
func TestReferenceJSONStrictAndAtomic(t *testing.T) {
	r, _ := ParseEndpointRef(goldenOffer)
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	var out EndpointRef
	if e = json.Unmarshal(b, &out); e != nil || out != r {
		t.Fatal(e)
	}
	if e = out.UnmarshalJSON(append([]byte(" \n"), b...)); e != nil || out != r {
		t.Fatal(e)
	}
	for _, raw := range []string{"null", "{}", "42", `"invalid"`, string(b) + ` true`, strings.Repeat(" ", 2000) + string(b)} {
		out = r
		if e = out.UnmarshalJSON([]byte(raw)); e == nil || out != r {
			t.Errorf("non-atomic or accepted %q", raw)
		}
	}
	if _, e = json.Marshal(EndpointRef{}); e == nil {
		t.Fatal("zero serialized")
	}
	var nilRef *EndpointRef
	if e = nilRef.UnmarshalJSON(b); e == nil {
		t.Fatal("nil receiver accepted")
	}
}
func FuzzParseEndpointRef(f *testing.F) {
	for _, s := range []string{goldenEndpoint, goldenOffer, "", goldenEndpoint[:117] + "r", strings.Repeat("a", 2000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, e := ParseEndpointRef(s)
		if e != nil {
			return
		}
		if r.String() != s || r.Domain() != r.Endpoint().Domain() {
			t.Fatal("normalization")
		}
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		var out EndpointRef
		if e = json.Unmarshal(b, &out); e != nil || out != r {
			t.Fatal("round trip")
		}
	})
}
