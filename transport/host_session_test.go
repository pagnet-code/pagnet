package transport

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestHostSessionSnapshotSigningPublicKeyJSON(t *testing.T) {
	for _, key := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		wire, err := json.Marshal(HostSessionPayload{SnapshotSigningPublicKey: key})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["snapshotSigningPublicKey"]; present != (key != "") {
			t.Fatal("snapshot signing field optionality lost")
		}
		var decoded HostSessionPayload
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded.SnapshotSigningPublicKey != key {
			t.Fatal("snapshot signing field round trip failed", err)
		}
	}
	var legacy HostSessionPayload
	if err := json.Unmarshal([]byte(`{"hostId":"host"}`), &legacy); err != nil || legacy.SnapshotSigningPublicKey != "" {
		t.Fatal("older server payload requires signing key", err)
	}
}

func TestHostSessionCredentialIDJSON(t *testing.T) {
	for _, credential := range []string{"", "00000000-0000-4000-8000-000000000001"} {
		payload := HostSessionPayload{HostID: "host", HostCredentialID: credential}
		wire, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["hostCredentialId"]; present != (credential != "") {
			t.Fatal("credential field optionality lost")
		}
		var decoded HostSessionPayload
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded.HostCredentialID != credential || decoded.HostID != payload.HostID {
			t.Fatal("host session credential round trip failed", err)
		}
	}
	var legacy HostSessionPayload
	if err := json.Unmarshal([]byte(`{"hostId":"host"}`), &legacy); err != nil || legacy.HostCredentialID != "" {
		t.Fatal("older server payload requires credential pin", err)
	}
}
