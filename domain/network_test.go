package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNetworkWireFormat pins the Network wire shape after the V2 cutover:
// the user-facing privacy mode is gone (networks are always encrypted; the
// crypto lifecycle is server-internal state), and the remaining fields keep
// their names.
func TestNetworkWireFormat(t *testing.T) {
	n := Network{
		ID:          MustParseID("01900000-0000-7000-8000-0000000000c1"),
		TenantID:    MustParseID("01900000-0000-7000-8000-0000000000c2"),
		Slug:        "priv",
		Name:        "Priv",
		Description: "A network",
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "privacyMode") {
		t.Fatalf("marshaled network %s still carries privacyMode (removed in V2)", b)
	}
	for _, key := range []string{`"ID":"01900000-0000-7000-8000-0000000000c1"`, `"Slug":"priv"`, `"Name":"Priv"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("marshaled network %s does not carry %s", b, key)
		}
	}

	// Round-trip: a legacy wire payload that still carries privacyMode
	// unmarshals cleanly (the unknown field is ignored) — old server
	// responses stay parseable during the cutover.
	var got Network
	legacy := `{"ID":"01900000-0000-7000-8000-0000000000c1","privacyMode":"private_e2ee"}`
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatalf("unmarshal legacy network: %v", err)
	}
	if got.ID != MustParseID("01900000-0000-7000-8000-0000000000c1") {
		t.Fatalf("ID = %q, want the legacy value", got.ID)
	}
}
