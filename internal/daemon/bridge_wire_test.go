package daemon

// The relay wire contract for the agent-facing content tools.
//
// Two layers name the same argument differently: the bridge/MCP surface
// advertises the short names an agent writes ("capability"), while the control
// plane's agent-command handler decodes its own field names ("capabilityId").
// encryptToolArgs must therefore see the AGENT-FACING names (the AAD binds
// what the agent asked for) and wireArgs must rename what CROSSES the boundary
// onto the control plane's names. These tests pin both halves and the exact key
// set the control plane receives.
//
// The failure mode is the silent one. The control plane's agent-command decode
// (pagnet-server internal/controlplane/agent_requests.go, toolInvoke) is a
// plain json.Unmarshal into its own struct — NOT the strict decodeBody
// (DisallowUnknownFields) that the REST API uses. So a foreign key is not a
// 400: it is DROPPED, and the handler then reports its own field as missing
// ("capabilityId required") or adopts an id the caller never sent. serverInvokeArgs
// below mirrors that decode so the assertion is the real one, not an assumption.

import (
	"encoding/json"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

// serverInvokeArgs mirrors the control plane's toolInvoke decode
// (agent_requests.go): the field names it reads, with the same LENIENT
// json.Unmarshal (unknown keys silently dropped, no DisallowUnknownFields).
type serverInvokeArgs struct {
	ToAgent        string `json:"toAgent"`
	ToPrincipalID  string `json:"toPrincipalId"`
	CapabilityID   string `json:"capabilityId"`
	InvocationID   string `json:"invocationId"`
	IdempotencyKey string `json:"idempotencyKey"`
	Envelope       any    `json:"envelope"`
	AAD            any    `json:"aad"`
}

// decodeAsServer decodes relayed args exactly as the control plane does and
// reports the answer toolInvoke would give when its required field is absent.
func decodeAsServer(t *testing.T, raw []byte) (serverInvokeArgs, string) {
	t.Helper()
	var a serverInvokeArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("the control plane could not decode the relayed args: %v", err)
	}
	if a.CapabilityID == "" {
		return a, "capabilityId required"
	}
	return a, ""
}

func invokeWireRow(t *testing.T) (*Daemon, *InstanceRow, string) {
	t.Helper()
	d := newTestDaemon(t)
	networkID := domain.NewID().String()
	setupActiveNetCrypto(t, d, "tenant-t", networkID)
	return d, &InstanceRow{InstanceID: "i1", NetworkID: networkID, AgentName: "agent-1"}, networkID
}

// relayedInvokeArgs runs the REAL relay order for one tool call:
// encryptToolArgs (agent-facing names, AAD bound) then wireArgs (the boundary
// rename), which is exactly what relayToServer sends.
func relayedInvokeArgs(t *testing.T, d *Daemon, row *InstanceRow, args []byte) []byte {
	t.Helper()
	enc, errMsg := d.encryptToolArgs(row, "network_invoke", args)
	if errMsg != "" {
		t.Fatalf("network_invoke refused on an active network: %q", errMsg)
	}
	return wireArgs("network_invoke", enc)
}

// TestBridge_InvokeWireFieldNames: the bytes the control plane receives for a
// network_invoke carry ITS field names — capabilityId + invocationId — and the
// control plane's own (lenient) decode finds both.
func TestBridge_InvokeWireFieldNames(t *testing.T) {
	d, row, _ := invokeWireRow(t)

	out := relayedInvokeArgs(t, d, row,
		[]byte(`{"capability":"documents.extract","input":{"uri":"https://example.com/a.pdf"},"idempotencyKey":"idem-1"}`))

	var keys map[string]any
	if err := json.Unmarshal(out, &keys); err != nil {
		t.Fatalf("relayed args are not a JSON object: %s", out)
	}
	for _, want := range []string{"capabilityId", "invocationId", "envelope", "aad", "idempotencyKey"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("the control plane never receives %q: %s", want, out)
		}
	}
	// The agent-facing name and the pre-fix object-id key must be GONE: the
	// decode is lenient, so leaving either behind is a silently dropped field,
	// not an error the agent can see.
	for _, gone := range []string{"capability", "input", "inputObjectID"} {
		if _, ok := keys[gone]; ok {
			t.Errorf("the relayed args still carry %q (the control plane drops it silently): %s", gone, out)
		}
	}

	a, toolErr := decodeAsServer(t, out)
	if toolErr != "" {
		t.Fatalf("the control plane rejects the relayed invoke: %s (args: %s)", toolErr, out)
	}
	if a.CapabilityID != "documents.extract" {
		t.Errorf("decoded capabilityId = %q, want documents.extract", a.CapabilityID)
	}
	if a.InvocationID == "" {
		t.Error("decoded invocationId is empty: the control plane would mint its own id and the AAD's bound object id would no longer match the invocation row")
	}
	if a.IdempotencyKey != "idem-1" {
		t.Errorf("decoded idempotencyKey = %q, want idem-1", a.IdempotencyKey)
	}
}

// TestBridge_InvokeWireFieldNames_FailureMode: the pre-fix shape, decoded by
// the control plane's LENIENT decode, is the pinned failure — the call never
// reaches the invoke, and nothing tells the agent which key was wrong.
func TestBridge_InvokeWireFieldNames_FailureMode(t *testing.T) {
	// Exactly what the bridge emitted before the fix: the agent-facing
	// "capability" and the object id under "inputObjectID".
	preFix := []byte(`{"capability":"documents.extract","inputObjectID":"01931f6a-0000-7000-8000-000000000000",` +
		`"envelope":{"key_epoch_id":"e1"},"aad":{"object_id":"01931f6a-0000-7000-8000-000000000000"}}`)

	a, toolErr := decodeAsServer(t, preFix)
	if toolErr != "capabilityId required" {
		t.Fatalf("the pre-fix shape decoded to %+v (err %q); want the control plane to answer %q",
			a, toolErr, "capabilityId required")
	}
	// The object id was dropped too: with the capability fixed, the server
	// would adopt its OWN invocation id while the AAD still binds the client's.
	if a.InvocationID != "" {
		t.Fatalf("inputObjectID was decoded as invocationId = %q; the control plane does not read that name", a.InvocationID)
	}
}

// TestBridge_InvokeWireFieldNames_UnencryptedCall: an invoke the encryption
// layer leaves alone (no input to protect) is still renamed at the boundary —
// the field-name contract is not conditional on encryption.
func TestBridge_InvokeWireFieldNames_UnencryptedCall(t *testing.T) {
	d := newTestDaemon(t)
	// No network at all: nothing is encrypted (metadata pass-through), yet the
	// relayed names must still be the control plane's.
	row := &InstanceRow{InstanceID: "i-plain", AgentName: "agent-1"}
	in := []byte(`{"capability":"documents.extract"}`)
	out, errMsg := d.encryptToolArgs(row, "network_invoke", in)
	if errMsg != "" {
		t.Fatalf("a content-free invoke was refused: %q", errMsg)
	}
	relayed := wireArgs("network_invoke", out)
	a, toolErr := decodeAsServer(t, relayed)
	if toolErr != "" {
		t.Fatalf("the control plane rejects the relayed invoke: %s (args: %s)", toolErr, relayed)
	}
	if a.CapabilityID != "documents.extract" {
		t.Errorf("decoded capabilityId = %q, want documents.extract", a.CapabilityID)
	}
}

// TestBridge_WireArgs_ExistingRenames: the boundary rename still covers the
// tools that landed before network_invoke (the map is shared, so a rename added
// for invoke must not disturb them).
func TestBridge_WireArgs_ExistingRenames(t *testing.T) {
	out := wireArgs("network_event_publish",
		[]byte(`{"type":"build.completed","target":"atlas","payload":{"ok":true}}`))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["eventType"] != "build.completed" || m["targetPrincipalId"] != "atlas" {
		t.Errorf("event publish rename = %v, want eventType/targetPrincipalId", m)
	}
	if _, ok := m["type"]; ok {
		t.Error(`"type" survived the rename to "eventType"`)
	}
	if _, ok := m["target"]; ok {
		t.Error(`"target" survived the rename to "targetPrincipalId"`)
	}

	sub := wireArgs("network_subscribe", []byte(`{"pattern":"build.*","mode":"wake"}`))
	var sm map[string]any
	if err := json.Unmarshal(sub, &sm); err != nil {
		t.Fatal(err)
	}
	if sm["eventPattern"] != "build.*" || sm["deliveryMode"] != "wake" {
		t.Errorf("subscribe rename = %v, want eventPattern/deliveryMode", sm)
	}

	// A tool the map does not list is relayed byte-for-byte.
	const search = `{"query":"pdf","kind":"service"}`
	if got := string(wireArgs("network_search", []byte(search))); got != search {
		t.Errorf("an unmapped tool was rewritten: %s", got)
	}
}
