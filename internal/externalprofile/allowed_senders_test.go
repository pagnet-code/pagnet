package externalprofile

import (
	"path/filepath"
	"testing"
)

func TestAllowedSendersValidationAndPersistence(t *testing.T) {
	p := Profile{Version: 1, Principal: "01900000-0000-7000-8000-000000000001", Network: "01900000-0000-7000-8000-000000000002", Server: "https://app.pagnet.dev", Credential: "pgn_act_v1_test", AllowedSenders: []string{"01900000-0000-7000-8000-000000000003"}}
	path := filepath.Join(t.TempDir(), "profiles", "test.json")
	if err := SaveNew(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.AllowedSenders) != 1 || got.AllowedSenders[0] != p.AllowedSenders[0] {
		t.Fatalf("allowlist not preserved: %v", err)
	}
	for _, senders := range [][]string{{"*"}, {p.AllowedSenders[0], p.AllowedSenders[0]}} {
		p.AllowedSenders = senders
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted invalid senders %v", senders)
		}
	}
}
