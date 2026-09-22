package transport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
)

// TestProtocolVersionV2 pins the cutover: the envelope version is 2 and
// NewEnvelope stamps it.
func TestProtocolVersionV2(t *testing.T) {
	if ProtocolVersion != 2 {
		t.Fatalf("ProtocolVersion = %d, want 2", ProtocolVersion)
	}
	env, err := NewEnvelope(MsgHeartbeat, HeartbeatPayload{HostID: "h1"})
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.ProtocolVersion != 2 {
		t.Fatalf("envelope protocolVersion = %d, want 2", env.ProtocolVersion)
	}
	if !env.IsVersionSupported() {
		t.Fatal("a fresh envelope must be version-supported")
	}
}

// TestVersionGate verifies the upgrade_required contract: an unsupported
// version is detected, and the payload carries the required version + the
// user-facing message.
func TestVersionGate(t *testing.T) {
	env, err := NewEnvelope(MsgHeartbeat, HeartbeatPayload{HostID: "h1"})
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	// Simulate a v1 peer.
	env.ProtocolVersion = 1
	if env.IsVersionSupported() {
		t.Fatal("a v1 envelope must NOT be version-supported")
	}

	up := UpgradeRequiredPayload{Required: ProtocolVersion, Message: UpgradeRequiredMessage}
	b, err := json.Marshal(up)
	if err != nil {
		t.Fatalf("marshal upgrade_required: %v", err)
	}
	for _, key := range []string{`"required":2`, `"message":"Pagnet client is outdated. Please update."`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("upgrade_required payload %s does not carry %s", b, key)
		}
	}

	// The envelope type name is the wire contract.
	if MsgUpgradeRequired != "protocol.upgrade_required" {
		t.Fatalf("MsgUpgradeRequired = %q", MsgUpgradeRequired)
	}

	// A v2 envelope round-trips the payload through DecodePayload.
	var got HeartbeatPayload
	if err := env.DecodePayload(&got); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if got.HostID != "h1" {
		t.Fatalf("HostID = %q, want h1", got.HostID)
	}
}

// TestEndpointRegisterWireFormat pins the endpoint registration payload:
// camelCase wire names, the capability descriptors, and the omission of
// optional fields.
func TestEndpointRegisterWireFormat(t *testing.T) {
	p := EndpointRegisterPayload{
		PublicKey:  "base64pub",
		SDKVersion: "v0.3.0",
		Capabilities: []domain.Capability{
			{ID: "documents.extract", Version: 1, Name: "Extract text", Tags: []string{"documents"}},
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"publicKey":"base64pub"`,
		`"sdkVersion":"v0.3.0"`,
		`"capabilities":[{"id":"documents.extract","version":1,"name":"Extract text","tags":["documents"]}]`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("register payload %s does not carry %s", b, key)
		}
	}
	for _, absent := range []string{`"endpointName"`, `"region"`} {
		if strings.Contains(string(b), absent) {
			t.Fatalf("register payload %s must omit %s when empty", b, absent)
		}
	}
}

// TestEndpointAuthOKWireFormat pins the auth_ok payload, including the
// durable credential only on activation.
func TestEndpointAuthOKWireFormat(t *testing.T) {
	p := EndpointAuthOKPayload{
		PrincipalID:     "01900000-0000-7000-8000-000000000001",
		EndpointID:      "01900000-0000-7000-8000-000000000002",
		NetworkIDs:      []string{"net-a", "net-b"},
		ProtocolVersion: ProtocolVersion,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"principalId":"01900000-0000-7000-8000-000000000001"`,
		`"endpointId":"01900000-0000-7000-8000-000000000002"`,
		`"networkIds":["net-a","net-b"]`,
		`"protocolVersion":2`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("auth_ok payload %s does not carry %s", b, key)
		}
	}
	if strings.Contains(string(b), `"credential"`) {
		t.Fatalf("auth_ok payload %s must omit credential outside activation", b)
	}

	p.Credential = "pgn_epd_v1_x"
	b, _ = json.Marshal(p)
	if !strings.Contains(string(b), `"credential":"pgn_epd_v1_x"`) {
		t.Fatalf("activation auth_ok payload %s must carry the credential", b)
	}
}

// TestEndpointDeliveryWireFormats pins the encrypted-delivery payloads:
// the AAD/Envelope fields follow the existing crypto-payload convention
// (pointer envelope + aad, omitted when absent) and the ack payloads carry
// the idempotency ids.
func TestEndpointDeliveryWireFormats(t *testing.T) {
	env := &e2ee.EncryptedPayloadV1{
		Version:           e2ee.EnvelopeVersion,
		CipherSuite:       e2ee.CipherSuiteAES256GCM,
		KeyEpochID:        "epoch-1",
		Nonce:             "AAECAwQFBgcICQoL",
		Ciphertext:        "ct",
		WrappedContentKey: "wrapped",
		AADVersion:        e2ee.AADVersion,
	}
	aad := &e2ee.AAD{ProtocolVersion: 1, NetworkID: "net", ObjectType: "event_payload", ObjectID: "ev", KeyEpochID: "epoch-1"}

	md := EndpointMessageDeliverPayload{
		MessageID:         "m1",
		NetworkID:         "net",
		ThreadID:          "th",
		Kind:              "ASK",
		SenderPrincipalID: "p1",
		Envelope:          env,
		AAD:               aad,
	}
	b, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("marshal message_deliver: %v", err)
	}
	for _, key := range []string{
		`"messageId":"m1"`, `"threadId":"th"`, `"kind":"ASK"`,
		`"senderPrincipalId":"p1"`, `"envelope":`, `"aad":`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("message_deliver payload %s does not carry %s", b, key)
		}
	}

	ed := EndpointEventDeliverPayload{
		EventID:             "e1",
		DeliveryID:          "d1",
		NetworkID:           "net",
		EventType:           "pagnet.task.created",
		ProducerPrincipalID: "p1",
		Envelope:            env,
		AAD:                 aad,
	}
	b, err = json.Marshal(ed)
	if err != nil {
		t.Fatalf("marshal event_deliver: %v", err)
	}
	for _, key := range []string{
		`"eventId":"e1"`, `"deliveryId":"d1"`,
		`"eventType":"pagnet.task.created"`,
		`"producerPrincipalId":"p1"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("event_deliver payload %s does not carry %s", b, key)
		}
	}

	// Without a producer the field is omitted.
	ed.ProducerPrincipalID = ""
	b, _ = json.Marshal(ed)
	if strings.Contains(string(b), `"producerPrincipalId"`) {
		t.Fatalf("event_deliver payload %s must omit producerPrincipalId when empty", b)
	}

	ack := EndpointEventAckPayload{DeliveryID: "d1", EventID: "e1"}
	b, _ = json.Marshal(ack)
	if !strings.Contains(string(b), `"deliveryId":"d1"`) || !strings.Contains(string(b), `"eventId":"e1"`) {
		t.Fatalf("event_ack payload %s does not carry both ids", b)
	}

	mack := EndpointMessageAckedPayload{MessageID: "m1"}
	b, _ = json.Marshal(mack)
	if !strings.Contains(string(b), `"messageId":"m1"`) {
		t.Fatalf("message_acked payload %s does not carry the message id", b)
	}
}

// TestEndpointInvocationWireFormats pins the invocation dispatch/accept/
// result payloads.
func TestEndpointInvocationWireFormats(t *testing.T) {
	env := &e2ee.EncryptedPayloadV1{
		Version:           e2ee.EnvelopeVersion,
		CipherSuite:       e2ee.CipherSuiteAES256GCM,
		KeyEpochID:        "epoch-1",
		Nonce:             "AAECAwQFBgcICQoL",
		Ciphertext:        "ct",
		WrappedContentKey: "wrapped",
		AADVersion:        e2ee.AADVersion,
	}
	aad := &e2ee.AAD{ProtocolVersion: 1, NetworkID: "net", ObjectType: "invocation_input", ObjectID: "inv", KeyEpochID: "epoch-1"}

	d := EndpointInvocationDispatchPayload{
		InvocationID:      "inv-1",
		NetworkID:         "net",
		CapabilityID:      "documents.extract",
		CapabilityVersion: 1,
		IdempotencyKey:    "key-1",
		CorrelationID:     "corr-1",
		Envelope:          env,
		AAD:               aad,
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal invocation_dispatch: %v", err)
	}
	for _, key := range []string{
		`"invocationId":"inv-1"`,
		`"capabilityId":"documents.extract"`,
		`"capabilityVersion":1`,
		`"idempotencyKey":"key-1"`,
		`"correlationId":"corr-1"`,
		`"envelope":`, `"aad":`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("invocation_dispatch payload %s does not carry %s", b, key)
		}
	}

	acc := EndpointInvocationAcceptPayload{InvocationID: "inv-1"}
	b, _ = json.Marshal(acc)
	if !strings.Contains(string(b), `"invocationId":"inv-1"`) {
		t.Fatalf("invocation_accept payload %s does not carry the invocation id", b)
	}

	r := EndpointInvocationResultPayload{
		InvocationID:     "inv-1",
		OK:               true,
		Envelope:         env,
		AAD:              aad,
		PublicResultCode: "ok",
		UsageMetadata:    map[string]any{"tokens": 42},
	}
	b, err = json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal invocation_result: %v", err)
	}
	for _, key := range []string{
		`"invocationId":"inv-1"`, `"ok":true`,
		`"publicResultCode":"ok"`, `"usageMetadata":{"tokens":42}`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("invocation_result payload %s does not carry %s", b, key)
		}
	}
}

// TestEndpointHeartbeatDisconnectWireFormats pins the small endpoint
// payloads.
func TestEndpointHeartbeatDisconnectWireFormats(t *testing.T) {
	hb, err := json.Marshal(EndpointHeartbeatPayload{Inflight: 3})
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	if string(hb) != `{"inflight":3}` {
		t.Fatalf("heartbeat payload = %s", hb)
	}

	ack, err := json.Marshal(EndpointHeartbeatAckPayload{})
	if err != nil {
		t.Fatalf("marshal heartbeat_ack: %v", err)
	}
	if string(ack) != `{}` {
		t.Fatalf("heartbeat_ack payload = %s", ack)
	}

	disc, err := json.Marshal(EndpointDisconnectPayload{})
	if err != nil {
		t.Fatalf("marshal disconnect: %v", err)
	}
	if string(disc) != `{}` {
		t.Fatalf("disconnect payload = %s", disc)
	}
}

// TestEndpointStatusWireFormat pins the daemon's managed-agent endpoint
// liveness report.
func TestEndpointStatusWireFormat(t *testing.T) {
	b, err := json.Marshal(EndpointStatusPayload{
		AgentPrincipalID: "p1",
		InstanceID:       "i1",
		Online:           true,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"agentPrincipalId":"p1"`, `"instanceId":"i1"`, `"online":true`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("endpoint_status payload %s does not carry %s", b, key)
		}
	}
}

// TestLaunchAgentPayloadEnvelopeWireNames pins the W-H1 cross-repo
// contract: the encrypted launch-content fields marshal with the EXACT
// wire names the server dispatches (and omit when absent, so pre-W-H1
// launch payloads stay byte-identical).
func TestLaunchAgentPayloadEnvelopeWireNames(t *testing.T) {
	env := &e2ee.EncryptedPayloadV1{
		Version:           e2ee.EnvelopeVersion,
		CipherSuite:       e2ee.CipherSuiteAES256GCM,
		KeyEpochID:        "epoch-1",
		Nonce:             "AAECAwQFBgcICQoL",
		Ciphertext:        "ct",
		WrappedContentKey: "wrapped",
		AADVersion:        e2ee.AADVersion,
	}
	aad := &e2ee.AAD{ProtocolVersion: 2, NetworkID: "net", ObjectType: "agent_definition", ObjectID: "obj", KeyEpochID: "epoch-1"}

	// No envelopes: the fields are omitted (additive contract — a
	// plaintext launch is byte-identical to pre-W-H1).
	b, err := json.Marshal(LaunchAgentPayload{CommandID: "cmd-1", InstanceID: "i1", Mission: "plain"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, absent := range []string{`"missionEnvelope"`, `"missionAad"`, `"instructionEnvelope"`, `"instructionAad"`} {
		if strings.Contains(string(b), absent) {
			t.Fatalf("launch payload without envelopes %s must omit %s", b, absent)
		}
	}

	p := LaunchAgentPayload{
		CommandID:           "cmd-1",
		InstanceID:          "i1",
		MissionEnvelope:     env,
		MissionAAD:          aad,
		InstructionEnvelope: env,
		InstructionAAD:      aad,
	}
	b, err = json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"missionEnvelope":`, `"missionAad":`, `"instructionEnvelope":`, `"instructionAad":`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("launch payload %s does not carry %s", b, key)
		}
	}

	// Round-trip: the server's bytes decode into the same fields.
	var got LaunchAgentPayload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.MissionEnvelope == nil || got.MissionAAD == nil || got.InstructionEnvelope == nil || got.InstructionAAD == nil {
		t.Fatalf("round-trip lost envelope fields: %+v", got)
	}
	if got.MissionEnvelope.KeyEpochID != "epoch-1" || got.InstructionAAD.ObjectID != "obj" {
		t.Fatalf("round-trip corrupted envelope content: %+v / %+v", got.MissionEnvelope, got.InstructionAAD)
	}
}

// TestNetworkEventPayloadV2Fields pins the host.deliver_network_event
// extension: the v2 event-delivery fields marshal with the camelCase wire
// names and omit when empty (v1 payloads stay byte-identical).
func TestNetworkEventPayloadV2Fields(t *testing.T) {
	v1 := NetworkEventPayload{
		CommandID:  "cmd-1",
		InstanceID: "i1",
		Kind:       "ask",
		Body:       "hello",
	}
	b, err := json.Marshal(v1)
	if err != nil {
		t.Fatalf("marshal v1: %v", err)
	}
	for _, absent := range []string{`"eventId"`, `"deliveryId"`, `"eventType"`, `"targetPrincipalId"`, `"deliveryMode"`} {
		if strings.Contains(string(b), absent) {
			t.Fatalf("v1 network event payload %s must omit %s", b, absent)
		}
	}

	v2 := NetworkEventPayload{
		CommandID:         "cmd-1",
		InstanceID:        "i1",
		Kind:              "ask",
		Body:              "",
		EventID:           "e1",
		DeliveryID:        "d1",
		EventType:         "pagnet.task.created",
		TargetPrincipalID: "p1",
		DeliveryMode:      "wake",
	}
	b, err = json.Marshal(v2)
	if err != nil {
		t.Fatalf("marshal v2: %v", err)
	}
	for _, key := range []string{
		`"eventId":"e1"`, `"deliveryId":"d1"`,
		`"eventType":"pagnet.task.created"`,
		`"targetPrincipalId":"p1"`, `"deliveryMode":"wake"`,
		// v1 fields survive:
		`"commandId":"cmd-1"`, `"instanceId":"i1"`, `"kind":"ask"`,
	} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("v2 network event payload %s does not carry %s", b, key)
		}
	}
}
