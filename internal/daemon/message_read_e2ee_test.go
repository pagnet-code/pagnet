package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDecryptMessageToolResult(t *testing.T) {
	d, network, epoch := newLaunchCryptoDaemon(t, t.TempDir())
	id := domain.NewID()
	const body = "Please review the invoice <tomorrow>."
	env, aad, err := d.encryptProtected(NetworkCryptoState{TenantID: "tenant", NetworkID: network, EpochID: epoch}, e2ee.ObjectTypeMessage, id.String(), "human", "recipient", body)
	if err != nil {
		t.Fatal(err)
	}
	makeResult := func(aad e2ee.AAD) json.RawMessage {
		m := domain.Message{ID: id, NetworkID: domain.ID(network), Parts: []domain.MessagePart{}, Metadata: map[string]any{"e2ee_envelope": env, "e2ee_aad": aad, "source": "console"}}
		b, err := json.Marshal(map[string]any{"messages": []domain.Message{m}, "thread": map[string]string{"id": "retained"}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw := makeResult(aad)
	for _, tool := range []string{"network_inbox", "control_get_thread", "control_get_history"} {
		t.Run(tool, func(t *testing.T) {
			row := &InstanceRow{NetworkID: network}
			if strings.HasPrefix(tool, "control_") {
				row.NetworkID = ""
			}
			out, errMsg := d.decryptMessageToolResult(row, tool, raw)
			if errMsg != "" {
				t.Fatal(errMsg)
			}
			var result struct {
				Messages []domain.Message
				Thread   map[string]string
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Messages) != 1 || result.Messages[0].TextBody() != body || result.Messages[0].Metadata["source"] != "console" || result.Thread["id"] != "retained" {
				t.Fatalf("decrypted result = %+v", result)
			}
			if strings.Contains(string(out), "e2ee_envelope") || strings.Contains(string(out), "e2ee_aad") {
				t.Fatal("ciphertext metadata exposed to runtime")
			}
			if strings.Contains(string(raw), body) || !strings.Contains(string(raw), "e2ee_envelope") {
				t.Fatal("relay result modified or plaintext leaked")
			}
		})
	}
	for name, corrupt := range map[string]e2ee.AAD{
		"tampered sender": func() e2ee.AAD { a := aad; a.Sender = "forged"; return a }(),
		"wrong object":    func() e2ee.AAD { a := aad; a.ObjectID = domain.NewID().String(); return a }(),
		"wrong network":   func() e2ee.AAD { a := aad; a.NetworkID = domain.NewID().String(); return a }(),
	} {
		t.Run(name, func(t *testing.T) {
			out, errMsg := d.decryptMessageToolResult(&InstanceRow{NetworkID: network}, "network_inbox", makeResult(corrupt))
			if errMsg == "" || out != nil || strings.Contains(errMsg, body) {
				t.Fatalf("tampered response returned content: %s %s", out, errMsg)
			}
		})
	}
	missing, err := New(Config{StateDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Close()
	if out, errMsg := missing.decryptMessageToolResult(&InstanceRow{NetworkID: network}, "network_inbox", raw); errMsg == "" || out != nil {
		t.Fatal("missing key returned ciphertext as successful content")
	}
	if out, errMsg := d.decryptMessageToolResult(&InstanceRow{NetworkID: "foreign"}, "network_inbox", raw); errMsg == "" || out != nil {
		t.Fatal("foreign worker network accepted")
	}
	if out, errMsg := d.decryptMessageToolResult(&InstanceRow{}, "network_search", raw); errMsg != "" || string(out) != string(raw) {
		t.Fatal("unrelated tool response rewritten")
	}
	plainResult := json.RawMessage(`{"messages":[],"extra":"preserve"}`)
	if out, errMsg := d.decryptMessageToolResult(&InstanceRow{}, "network_inbox", plainResult); errMsg != "" || string(out) != string(plainResult) {
		t.Fatal("unencrypted response changed")
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	var msgs []domain.Message
	if err := json.Unmarshal(decoded["messages"], &msgs); err != nil {
		t.Fatal(err)
	}
	bad := msgs[0]
	bad.Metadata = map[string]any{"e2ee_envelope": env}
	decoded["messages"], _ = json.Marshal([]domain.Message{msgs[0], bad})
	mixed, _ := json.Marshal(decoded)
	if out, errMsg := d.decryptMessageToolResult(&InstanceRow{}, "network_inbox", mixed); out != nil || errMsg == "" {
		t.Fatal("partially decrypted response leaked on missing AAD")
	}
	kr, err := crypto.LoadKeyring(d.StateDir, network)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Activate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveKeyring(d.StateDir, kr); err != nil {
		t.Fatal(err)
	}
	if out, errMsg := d.decryptMessageToolResult(&InstanceRow{}, "control_get_thread", raw); out == nil || errMsg != "" {
		t.Fatalf("known previous epoch rejected: %s", errMsg)
	}
}

func TestEmptyMessageDeliveryRequiresEnvelope(t *testing.T) {
	for _, kind := range []string{"ask", "reply"} {
		if !deliveryHasContent(transport.NetworkEventPayload{Kind: kind, MessageID: "encrypted-message", ThreadID: "thread"}) {
			t.Fatalf("empty %s accepted as metadata-only notice", kind)
		}
	}
	if deliveryHasContent(transport.NetworkEventPayload{Kind: "notice"}) {
		t.Fatal("metadata-only notice rejected")
	}
}
