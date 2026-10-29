//go:build unix

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/sdk"
	"github.com/pagnet-code/pagnet/transport"
)

type consoleTestMessage struct {
	typ     string
	payload any
}

type consoleTestFixture struct {
	d        *Daemon
	c        *ownerTextConsoleConnection
	n        *NativeObservationConnection
	desc     e2ee.OwnerTextConsoleDescriptor
	browser  []byte
	done     chan struct{}
	messages chan consoleTestMessage
}

func newConsoleTestFixture(t *testing.T) *consoleTestFixture {
	t.Helper()
	f, state, saved := senderLifecycle(t)
	d := f.s.daemon
	d.textServices = f.s
	if err := f.s.reconcile(context.Background(), f.c); err != nil {
		t.Fatal(err)
	}
	awaitSenderSend(t, state, saved.AskID)
	identity, err := d.cryptoManager().hostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := f.c.session
	x := &consoleTestFixture{d: d, browser: browser.Bytes(), done: make(chan struct{}), messages: make(chan consoleTestMessage, 32)}
	r := f.runtime()
	x.desc = e2ee.OwnerTextConsoleDescriptor{
		OwnershipScope: "personal", Role: "sender", ProjectContract: textbridge.OwnerTextProjectContract,
		TenantID: p.TenantID, OwnerUserID: p.AccountID, ProjectID: managedSenderProject, NetworkID: uuid.NewString(), SessionID: uuid.NewString(),
		ProjectVersion: "1", PolicyHash: strings.Repeat("ab", 32), ProjectDescriptorHash: bytes.Repeat([]byte{0x55}, 32),
		SenderPrincipalID: f.profile.Service, SenderInstallationID: f.item.ID, ResponderPrincipalID: managedSenderRecipient, ResponderInstallationID: uuid.NewString(),
		HostID: p.HostID, RunnerID: p.RunnerID, RunnerEpoch: p.RunnerEpoch.UTC().Format(ownerTextConsoleEpoch), HostCredentialID: p.HostCredentialID,
		SenderGeneration: strconv.FormatInt(r.generation, 10), SenderClaimID: r.claimID, SenderEndpointID: uuid.NewString(), SenderEndpointCredentialID: uuid.NewString(),
		SenderEndpointStartedAt: time.Now().UTC().Format(ownerTextConsoleEpoch), SenderProofID: uuid.NewString(),
		BrowserX25519Pub: browser.PublicKey().Bytes(), HostX25519Pub: identity.X25519Pub, HostEd25519Pub: identity.Ed25519Pub,
		IssuedAtUnixSeconds: uint64(time.Now().Unix()), ExpiresAtUnixSeconds: uint64(time.Now().Unix()) + 300,
	}
	desc := x.desc
	project, err := json.Marshal(map[string]string{"projectId": desc.ProjectID, "networkId": desc.NetworkID, "ownerTenantId": desc.TenantID, "ownerUserId": desc.OwnerUserID, "policyHash": desc.PolicyHash})
	if err != nil {
		t.Fatal(err)
	}
	binding := sdk.OwnerTextProjectBindingSnapshot{
		OwnerTextProjectStatus: sdk.OwnerTextProjectStatus{ProjectID: desc.ProjectID, NetworkID: desc.NetworkID, ProjectVersion: desc.ProjectVersion, Descriptor: project, DescriptorHash: desc.ProjectDescriptorHash,
			EndpointProof: &sdk.OwnerTextProjectEndpointProof{ProofID: desc.SenderProofID, PrincipalID: desc.SenderPrincipalID, InstallationID: desc.SenderInstallationID, ClaimID: desc.SenderClaimID, Generation: desc.SenderGeneration, EndpointID: desc.SenderEndpointID, CredentialID: desc.SenderEndpointCredentialID, EndpointStartedAt: desc.SenderEndpointStartedAt, DescriptorHash: desc.ProjectDescriptorHash},
			Roles:         []sdk.OwnerTextProjectRoleStatus{{Role: "sender", PrincipalID: desc.SenderPrincipalID, InstallationID: desc.SenderInstallationID}, {Role: "responder", PrincipalID: desc.ResponderPrincipalID, InstallationID: desc.ResponderInstallationID}}},
		InstallationID: desc.SenderInstallationID, ClaimID: desc.SenderClaimID, ProjectContract: desc.ProjectContract, PrincipalID: desc.SenderPrincipalID, EndpointID: desc.SenderEndpointID, PolicyHash: desc.PolicyHash, Generation: r.generation,
	}
	f.s.mu.Lock()
	r.profile.ProjectContract = textbridge.OwnerTextProjectContract
	r.consoleBinding = func(context.Context, string, string) (sdk.OwnerTextProjectBindingSnapshot, <-chan struct{}, error) {
		return binding, x.done, nil
	}
	f.s.mu.Unlock()
	p.ProtocolFeatures = append(p.ProtocolFeatures, transport.NativeObservationReceiptProtocol)
	x.n = NewNativeObservationConnection(d.ServerURL, p.HostID, p.BootID, func(context.Context, string, any) error { return nil })
	if err := x.n.Admit(p); err != nil {
		t.Fatal(err)
	}
	x.c = newOwnerTextConsoleConnection(d, x.n, func(typ string, payload any) error { x.messages <- consoleTestMessage{typ, payload}; return nil })
	t.Cleanup(x.n.Close)
	t.Cleanup(x.c.close)
	return x
}

func (f *consoleTestFixture) handle(t *testing.T, typ string, payload any) {
	t.Helper()
	env, err := transport.NewEnvelope(typ, payload)
	if err != nil {
		t.Fatal(err)
	}
	f.c.handle(env, 1024)
}
func (f *consoleTestFixture) next(t *testing.T, typ string) any {
	t.Helper()
	select {
	case m := <-f.messages:
		if m.typ != typ {
			t.Fatalf("got %s, want %s", m.typ, typ)
		}
		return m.payload
	case <-time.After(3 * time.Second):
		t.Fatalf("missing %s", typ)
	}
	return nil
}
func (f *consoleTestFixture) open(t *testing.T) {
	f.handle(t, transport.MsgOwnerTextConsoleOpen, transport.OwnerTextConsoleOpenPayload{Protocol: transport.OwnerTextConsoleProtocolV1, Descriptor: f.desc})
}
func (f *consoleTestFixture) confirmed(t *testing.T) *e2ee.OwnerTextConsoleSession {
	t.Helper()
	f.open(t)
	ready := f.next(t, transport.MsgOwnerTextConsoleReady).(transport.OwnerTextConsoleReadyPayload)
	keys, err := e2ee.VerifyOwnerTextConsoleBootstrap(f.desc, ready.Descriptor, ready.Bootstrap, f.browser)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := e2ee.NewOwnerTextConsoleSession(f.desc, ready.Bootstrap, keys, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(browser.Close)
	ct, err := browser.SealConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	f.frame(t, 0, ct)
	frame := f.next(t, transport.MsgOwnerTextConsoleFrame).(transport.OwnerTextConsoleFramePayload)
	if frame.Sequence != 0 {
		t.Fatal("host confirmation did not use sequence zero")
	}
	if err := browser.OpenConfirmation(frame.Sequence, frame.Ciphertext); err != nil {
		t.Fatal(err)
	}
	return browser
}
func (f *consoleTestFixture) frame(t *testing.T, seq uint64, ct []byte) {
	f.handle(t, transport.MsgOwnerTextConsoleFrame, transport.OwnerTextConsoleFramePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: f.desc.SessionID, Sequence: seq, Ciphertext: ct})
}
func (f *consoleTestFixture) request(t *testing.T, browser *e2ee.OwnerTextConsoleSession, req ownerTextConsoleRequest) (string, json.RawMessage) {
	t.Helper()
	req.Version, req.RequestID = 1, uuid.NewString()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	seq, ct, err := browser.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.frame(t, seq, ct)
	frame := f.next(t, transport.MsgOwnerTextConsoleFrame).(transport.OwnerTextConsoleFramePayload)
	plain, err := browser.Open(frame.Sequence, frame.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version               int
		Type, RequestID, Code string
		Data                  json.RawMessage
	}
	if err := json.Unmarshal(plain, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.Type != "result" || result.RequestID != req.RequestID {
		t.Fatal("uncorrelated operation result")
	}
	return result.Code, result.Data
}

func TestOwnerTextConsoleRoundtripAndIdempotence(t *testing.T) {
	f := newConsoleTestFixture(t)
	browser := f.confirmed(t)
	ask, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	submit := ownerTextConsoleRequest{Type: "submit", AskID: ask.String(), Text: "console question"}
	for i := 0; i < 2; i++ {
		code, data := f.request(t, browser, submit)
		var operation ownerTextConsoleOperation
		if err := json.Unmarshal(data, &operation); err != nil {
			t.Fatal(err)
		}
		if code != "ok" || operation.AskID != ask.String() {
			t.Fatalf("submit: %s %s", code, data)
		}
	}
	submit.Text = "changed question"
	if code, _ := f.request(t, browser, submit); code != "conflict" {
		t.Fatal("changed idempotent submit accepted", code)
	}
	if code, data := f.request(t, browser, ownerTextConsoleRequest{Type: "status", AskID: ask.String()}); code != "ok" || !bytes.Contains(data, []byte(ask.String())) {
		t.Fatalf("status: %s %s", code, data)
	}
	code, data := f.request(t, browser, ownerTextConsoleRequest{Type: "list", Limit: 100})
	var page struct{ Operations []ownerTextConsoleOperation }
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	if code != "ok" || len(page.Operations) != 2 {
		t.Fatalf("list: %s %s", code, data)
	}
	count := 0
	for _, operation := range page.Operations {
		if operation.AskID == ask.String() {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate submit created multiple operations")
	}
}

func TestOwnerTextConsoleRejectsWrongBindingAndPin(t *testing.T) {
	for _, name := range []string{"project", "pin", "proof", "generation"} {
		t.Run(name, func(t *testing.T) {
			f := newConsoleTestFixture(t)
			switch name {
			case "project":
				f.desc.ProjectID = uuid.NewString()
			case "pin":
				f.desc.HostEd25519Pub = bytes.Repeat([]byte{0x44}, 32)
			case "proof":
				f.desc.SenderProofID = uuid.NewString()
			case "generation":
				f.desc.SenderGeneration = "999"
			}
			f.open(t)
			f.next(t, transport.MsgOwnerTextConsoleClose)
			f.c.mu.Lock()
			defer f.c.mu.Unlock()
			if len(f.c.sessions) != 0 {
				t.Fatal("rejected open retained a session")
			}
		})
	}
}

func TestOwnerTextConsoleReplayAndClose(t *testing.T) {
	f := newConsoleTestFixture(t)
	f.confirmed(t)
	f.handle(t, transport.MsgOwnerTextConsoleClose, transport.OwnerTextConsoleClosePayload{Protocol: transport.OwnerTextConsoleProtocolV1, SessionID: f.desc.SessionID})
	f.c.mu.Lock()
	if len(f.c.sessions) != 0 {
		t.Fatal("explicit close retained session")
	}
	f.c.mu.Unlock()
	f.open(t)
	f.next(t, transport.MsgOwnerTextConsoleClose)
}

func TestOwnerTextConsoleRejectsSequenceOrder(t *testing.T) {
	for _, name := range []string{"confirmation", "gap", "replay"} {
		t.Run(name, func(t *testing.T) {
			f := newConsoleTestFixture(t)
			if name == "confirmation" {
				f.open(t)
				f.next(t, transport.MsgOwnerTextConsoleReady)
				f.frame(t, 1, bytes.Repeat([]byte{0}, 32))
			} else {
				browser := f.confirmed(t)
				raw, _ := json.Marshal(ownerTextConsoleRequest{Version: 1, Type: "list", RequestID: uuid.NewString(), Limit: 1})
				seq, ct, err := browser.Seal(raw)
				if err != nil {
					t.Fatal(err)
				}
				if name == "gap" {
					f.frame(t, seq+1, ct)
				} else {
					f.frame(t, seq, ct)
					f.next(t, transport.MsgOwnerTextConsoleFrame)
					f.frame(t, seq, ct)
				}
			}
			f.next(t, transport.MsgOwnerTextConsoleClose)
		})
	}
}

func TestOwnerTextConsoleInvalidation(t *testing.T) {
	for _, name := range []string{"binding", "connection", "authority", "runtime"} {
		t.Run(name, func(t *testing.T) {
			f := newConsoleTestFixture(t)
			browser := f.confirmed(t)
			switch name {
			case "binding":
				close(f.done)
			case "connection":
				f.n.Close()
			case "runtime":
				f.d.textServices.disconnect()
			case "authority":
				f.n.mu.Lock()
				f.n.session.HostCredentialID = uuid.NewString()
				f.n.mu.Unlock()
				seq, ct, err := browser.Seal([]byte(`{"version":1}`))
				if err != nil {
					t.Fatal(err)
				}
				f.frame(t, seq, ct)
			}
			f.next(t, transport.MsgOwnerTextConsoleClose)
		})
	}
}

func TestOwnerTextConsoleAdvertisementRequiresRuntimeAndHandler(t *testing.T) {
	d := &Daemon{}
	if d.ownerTextConsoleReady() {
		t.Fatal("console advertised without runtime")
	}
	n := NewNativeObservationConnection("https://example.test", uuid.NewString(), uuid.NewString(), nil)
	c := newOwnerTextConsoleConnection(d, n, func(string, any) error { return nil })
	t.Cleanup(c.close)
	if d.ownerTextConsoleReady() {
		t.Fatal("handler alone advertised console")
	}
	f := newConsoleTestFixture(t)
	if !f.d.ownerTextConsoleReady() {
		t.Fatal("proved runtime and handler not advertised")
	}
	f.c.close()
	if f.d.ownerTextConsoleReady() {
		t.Fatal("runtime alone advertised console")
	}
}

func TestOwnerTextConsoleRequestValidation(t *testing.T) {
	ask, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.NewString()
	encode := func(fields map[string]any) []byte {
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	submit := func(text string) map[string]any {
		return map[string]any{"version": 1, "type": "submit", "requestId": requestID, "askId": ask.String(), "text": text}
	}
	status := func() map[string]any {
		return map[string]any{"version": 1, "type": "status", "requestId": requestID, "askId": ask.String()}
	}
	list := func(limit int) map[string]any {
		return map[string]any{"version": 1, "type": "list", "requestId": requestID, "limit": limit}
	}
	tests := []struct {
		name   string
		fields map[string]any
		valid  bool
	}{
		{"submit", submit("question"), true},
		{"status", status(), true},
		{"list", list(1), true},
		{"max list", list(100), true},
		{"Unicode scalar limit", submit(strings.Repeat("😀", 16000)), true},
		{"empty text", submit(""), false},
		{"whitespace text", submit(" \n\t"), false},
		{"Unicode scalar overflow", submit(strings.Repeat("😀", 16001)), false},
		{"escaped plaintext overflow", submit(strings.Repeat("\x00", 16000)), false},
		{"zero limit", list(0), false},
		{"limit overflow", list(101), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, valid := consoleRequest(encode(test.fields)); valid != test.valid {
				t.Fatalf("valid = %v, want %v", valid, test.valid)
			}
		})
	}
	for _, test := range []struct {
		name   string
		fields map[string]any
		key    string
		value  any
		valid  bool
	}{
		{"unknown key", submit("question"), "unknown", true, false},
		{"submit extra limit", submit("question"), "limit", 0, false},
		{"status extra text", status(), "text", "", false},
		{"list extra ask", list(1), "askId", "", false},
		{"request UUID version", submit("question"), "requestId", ask.String(), false},
		{"ask UUID version", submit("question"), "askId", requestID, false},
		{"list cursor", list(1), "cursor", ask.String(), true},
		{"cursor UUID version", list(1), "cursor", requestID, false},
		{"empty cursor", list(1), "cursor", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.fields[test.key] = test.value
			if _, valid := consoleRequest(encode(test.fields)); valid != test.valid {
				t.Fatalf("valid = %v, want %v", valid, test.valid)
			}
		})
	}
	raw := encode(submit("question"))
	duplicate := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"text":"question"}`)...)
	malformed := bytes.Replace(raw, []byte("question"), []byte{0xff}, 1)
	missing := submit("question")
	delete(missing, "text")
	for name, raw := range map[string][]byte{"duplicate key": duplicate, "malformed UTF8": malformed, "missing field": encode(missing)} {
		t.Run(name, func(t *testing.T) {
			if _, valid := consoleRequest(raw); valid {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestOwnerTextConsoleRejectsExpiredOpen(t *testing.T) {
	f := newConsoleTestFixture(t)
	f.desc.IssuedAtUnixSeconds = uint64(time.Now().Unix()) - 10
	f.desc.ExpiresAtUnixSeconds = uint64(time.Now().Unix()) - 1
	f.open(t)
	f.next(t, transport.MsgOwnerTextConsoleClose)
}
