package transport

import (
	"encoding/json"
	"testing"
)

func TestInventoryOwnerTextConsoleProtocolOmitted(t *testing.T) {
	payload, err := json.Marshal(InventoryPayload{HostID: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `{"hostId":"h1","runtimes":null,"workspaces":null,"allowedRoots":null}`
	if string(payload) != legacy {
		t.Fatalf("inventory = %s, want legacy JSON %s", payload, legacy)
	}
}

func TestInventoryOwnerTextConsoleProtocolWireFormat(t *testing.T) {
	if OwnerTextConsoleProtocol != "owner_text_console_v1" {
		t.Fatalf("OwnerTextConsoleProtocol = %q", OwnerTextConsoleProtocol)
	}
	payload, err := json.Marshal(InventoryPayload{
		HostID:                   "h1",
		OwnerTextConsoleProtocol: OwnerTextConsoleProtocol,
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"ownerTextConsoleProtocol":"owner_text_console_v1","hostId":"h1","runtimes":null,"workspaces":null,"allowedRoots":null}`
	if string(payload) != want {
		t.Fatalf("inventory = %s, want %s", payload, want)
	}
	var decoded InventoryPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OwnerTextConsoleProtocol != OwnerTextConsoleProtocol {
		t.Fatalf("decoded protocol = %q", decoded.OwnerTextConsoleProtocol)
	}
}
