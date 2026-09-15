package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPrivacyModeWireFormat verifies the PrivacyMode field marshals to the
// server's wire name ("privacyMode") with the documented values, so the
// control plane and daemon agree on the contract.
func TestPrivacyModeWireFormat(t *testing.T) {
	n := Network{
		ID:          MustParseID("01900000-0000-7000-8000-0000000000c1"),
		TenantID:    MustParseID("01900000-0000-7000-8000-0000000000c2"),
		Slug:        "priv",
		Name:        "Priv",
		PrivacyMode: PrivacyModePrivateE2EE,
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"privacyMode":"private_e2ee"`) {
		t.Fatalf("marshaled network %s does not carry privacyMode=private_e2ee", b)
	}

	// Round-trip: the server's wire value unmarshals into the typed field.
	var got Network
	if err := json.Unmarshal([]byte(`{"privacyMode":"private_e2ee"}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PrivacyMode != PrivacyModePrivateE2EE {
		t.Fatalf("PrivacyMode = %q, want private_e2ee", got.PrivacyMode)
	}
	if !got.PrivacyMode.Valid() {
		t.Fatal("private_e2ee should be a valid mode")
	}
}

// TestPrivacyModeValid verifies the Valid() helper.
func TestPrivacyModeValid(t *testing.T) {
	if !PrivacyModeStandard.Valid() {
		t.Error("standard should be valid")
	}
	if !PrivacyModePrivateE2EE.Valid() {
		t.Error("private_e2ee should be valid")
	}
	if PrivacyMode("bogus").Valid() {
		t.Error("bogus should not be valid")
	}
	if PrivacyMode("").Valid() {
		t.Error("empty should not be valid")
	}
}
