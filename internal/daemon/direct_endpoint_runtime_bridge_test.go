//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/pagnet-code/pagnet/transport"
)

type runtimeBridgeFake struct {
	receiptAdmitted                            bool
	t                                          *testing.T
	store                                      *directRuntimeStore
	handle                                     directRuntimeHandle
	binding                                    directRuntimeBinding
	delivery                                   transport.DirectDeliveryV2
	reply                                      transport.DirectChannelMessageV2
	admits, resumes, sends, seals              int
	uncertainAdmission, uncertainSend, revoked bool
	wires                                      [][]byte
	uncertainResume, skipStage                 bool
	callsMu                                    sync.Mutex
}

func (f *runtimeBridgeFake) stage(want string) {
	f.t.Helper()
	if f.skipStage {
		return
	}
	v, e := f.store.load(context.Background(), f.handle)
	if e != nil || v.Stage != want {
		f.t.Fatalf("wanted durable stage %s", want)
	}
}
func (f *runtimeBridgeFake) AdmitPrompt(context.Context, string, string) (runtimeconnect.PromptResult, error) {
	f.stage("started")
	f.callsMu.Lock()
	f.admits++
	f.callsMu.Unlock()
	if f.uncertainAdmission {
		return runtimeconnect.PromptResult{Uncertain: true}, errors.New("synthetic uncertainty")
	}
	return runtimeconnect.PromptResult{Accepted: true, Uncertain: true, PromptID: "prompt", EventEpoch: "epoch"}, nil
}
func (f *runtimeBridgeFake) ResumePrompt(_ context.Context, r runtimeconnect.PromptResult) (runtimeconnect.PromptResult, error) {
	f.stage("admitted")
	f.callsMu.Lock()
	f.resumes++
	f.callsMu.Unlock()
	if f.uncertainResume {
		r.Uncertain = true
		return r, errors.New("synthetic completion uncertainty")
	}
	r.Uncertain = false
	r.ResultText = "answer"
	return r, nil
}
func (f *runtimeBridgeFake) Inbox(context.Context, string, transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error) {
	return transport.DirectInboxPageV2{}, nil
}
func (f *runtimeBridgeFake) Ack(_ context.Context, _ string, q transport.DirectMessageAckV2) (transport.DirectMessageAckReceiptV2, error) {
	// Accept has not returned its owner yet: verify durable acceptance by claim replay.
	if _, _, e := f.store.claim(context.Background(), directRuntimeAcceptance{f.binding, f.delivery, "question"}); !errors.Is(e, errDirectRuntimeRecovery) {
		f.t.Fatal("ACK preceded durable claim")
	}
	return transport.DirectMessageAckReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/ack-receipt", Binding: q.Binding, DeliveryState: "acknowledged", AcknowledgedAt: "2030-01-01T00:01:00Z"}, nil
}
func (f *runtimeBridgeFake) Send(_ context.Context, _ string, w transport.DirectChannelMessageV2) (transport.DirectMessageAdmissionReceiptV2, error) {
	f.stage("outbox")
	f.sends++
	raw, _ := w.CanonicalBytes()
	f.wires = append(f.wires, raw)
	if f.uncertainSend {
		return transport.DirectMessageAdmissionReceiptV2{}, errors.New("synthetic uncertainty")
	}
	hash, _ := transport.DirectChannelMessageHashV2(w)
	old := f.delivery.Admission.Binding
	return transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", Binding: transport.DirectMessageBindingV2{Context: old.Context, MessageID: w.Header.MessageID, WireHash: hash, WireBytes: len(raw), Sender: old.Recipient, Recipient: old.Sender}, AdmissionState: "admitted", AdmittedAt: "2030-01-01T00:02:00Z", ExpiresAt: "2030-01-01T00:03:00Z"}, nil
}
func (f *runtimeBridgeFake) SenderReceipt(context.Context, string, transport.DirectSenderReceiptRequestV2) (transport.DirectSenderReceiptV2, error) {
	if f.receiptAdmitted {
		raw, _ := f.reply.CanonicalBytes()
		hash, _ := transport.DirectChannelMessageHashV2(f.reply)
		old := f.delivery.Admission.Binding
		receipt := transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", Binding: transport.DirectMessageBindingV2{Context: old.Context, MessageID: f.reply.Header.MessageID, WireHash: hash, WireBytes: len(raw), Sender: old.Recipient, Recipient: old.Sender}, AdmissionState: "admitted", AdmittedAt: "2030-01-01T00:02:00Z", ExpiresAt: "2030-01-01T00:03:00Z"}
		return transport.DirectSenderReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/sender-receipt", Status: "admitted", Admission: &receipt, DeliveryState: "pending", ObservedAt: "2030-01-01T00:02:30Z", ReconcileUntil: "2030-01-02T00:02:00Z"}, nil
	}
	return transport.DirectSenderReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/sender-receipt", Status: "not_found", ObservedAt: "2030-01-01T00:03:00Z", ReconcileUntil: "2030-01-02T00:02:00Z"}, nil
}
func runtimeBridgeFixture(t *testing.T) (*directRuntimeBridge, *runtimeBridgeFake) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	r, e := OpenNativeWorkerRegistry(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	id := func(n byte) string { return "00000000-0000-4000-8000-0000000000" + hex.EncodeToString([]byte{n}) }
	binary := func(n byte, size int) string {
		return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{n}, size))
	}
	point := func(n byte) string { b := make([]byte, 32); b[0] = n; return base64.RawURLEncoding.EncodeToString(b) }
	endpoint := func(n byte) transport.DirectChannelEndpointV2 {
		return transport.DirectChannelEndpointV2{TenantID: id(n), PrincipalID: id(n + 1), EndpointID: id(n + 2), PublicKey: point(n), CredentialID: id(n + 3), KeyEvidenceDigest: strings.Repeat("ab", 32)}
	}
	limits := transport.DirectChannelLimitsV2{MaxMessageWireBytes: 4096, MaxMessagesPerMinute: 5, MaxMessagesPerDay: 100, MaxWireBytesPerDay: 1048576, MaxInFlight: 2, MaxTurnsPerThread: 8}
	d := transport.DirectChannelDescriptorV2{Domain: transport.DirectChannelDomainV2, Suite: transport.DirectChannelSuiteV2, ParentGrantID: id(1), GrantGeneration: "1", ChannelGeneration: "2", DirectIntentID: id(2), NetworkID: id(3), AuthorizationDigest: strings.Repeat("cd", 32), S: endpoint(9), P: endpoint(10), EpochID: "01900000-0000-7000-8000-000000000001", ExpiresAt: "2030-01-01T01:00:00Z", Budget: transport.DirectChannelBudgetV2{AgreementID: id(4), AcceptedRevision: "3", TermsDigest: strings.Repeat("ef", 32), ExpiresAt: "2030-01-01T02:00:00Z", CountingVersion: transport.DirectChannelCountingVersionV2, GrantLimits: limits}, Limits: limits}
	p := transport.DirectChannelPublicationV2{Descriptor: d, Enc: point(11), Ciphertext: binary(7, 48)}
	channel, _ := transport.DirectChannelIDV2(d)
	dh, _ := transport.DescriptorHashV2(d)
	ph, _ := transport.PublicationHashV2(p)
	party := func(role string, e transport.DirectChannelEndpointV2) transport.DirectDeliveryPartyV2 {
		return transport.DirectDeliveryPartyV2{Role: role, PrincipalID: e.PrincipalID, EndpointID: e.EndpointID, CredentialID: e.CredentialID}
	}
	dc := transport.DirectDeliveryContextV2{ChannelID: channel, DescriptorHash: dh, PublicationHash: ph, ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration}
	ask := transport.DirectChannelMessageV2{Header: transport.DirectChannelMessageHeaderV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/message", Kind: "ASK", ChannelID: channel, DescriptorHash: dh, EpochID: d.EpochID, MessageID: id(40), RootID: id(40), SenderRole: "S"}, Nonce: binary(1, 12), Ciphertext: binary(2, 16)}
	raw, e := ask.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := transport.DirectChannelMessageHashV2(ask)
	reply := ask
	reply.Header.Kind = "REPLY"
	reply.Header.SenderRole = "P"
	reply.Header.MessageID = id(41)
	reply.Header.AskID = ask.Header.MessageID
	reply.Header.AskWireHash = hash
	binding := directRuntimeBinding{Publication: p, Context: dc, Recipient: party("P", d.P), NativeSession: "native-session", NativeGeneration: "generation", ConsentRevision: 1}
	delivery := transport.DirectDeliveryV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/item", Admission: transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", Binding: transport.DirectMessageBindingV2{Context: dc, MessageID: ask.Header.MessageID, WireHash: hash, WireBytes: len(raw), Sender: party("S", d.S), Recipient: binding.Recipient}, AdmissionState: "admitted", AdmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T00:20:00Z"}, DeliveryState: "pending", Wire: raw}
	f := &runtimeBridgeFake{t: t, store: &directRuntimeStore{registry: r}, binding: binding, delivery: delivery, reply: reply}
	b, e := newDirectRuntimeBridge(f.store, directRuntimeDependencies{Now: func() time.Time { return time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC) }, Client: f, Qwen: func(directRuntimeBinding) (directRuntimeQwen, error) { return f, nil }, Authority: func(ctx context.Context, _ directRuntimeBinding, use func(context.Context, string) error) error {
		if f.revoked {
			return errDirectRuntimeRejected
		}
		return use(ctx, "synthetic")
	}, OpenASK: func(context.Context, directRuntimeBinding, transport.DirectChannelMessageV2) (string, error) {
		return "question", nil
	}, SealReply: func(context.Context, directRuntimeBinding, transport.DirectChannelMessageV2, string) (transport.DirectChannelMessageV2, error) {
		f.seals++
		return f.reply, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	return b, f
}
func runtimeAccept(t *testing.T, b *directRuntimeBridge, f *runtimeBridgeFake) {
	t.Helper()
	h, done, e := b.Accept(context.Background(), f.binding, f.delivery)
	if e != nil || done {
		t.Fatalf("accept failed: %v", e)
	}
	f.handle = h
}
func TestDirectRuntimeOrderingAndIdenticalReplyRetry(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.uncertainSend = true
	if e := b.Process(context.Background(), f.handle); e == nil {
		t.Fatal("missing uncertainty")
	}
	f.uncertainSend = false
	if e := b.Process(context.Background(), f.handle); e != nil {
		t.Fatal(e)
	}
	if f.admits != 1 || f.resumes != 1 || f.seals != 1 || f.sends != 2 || !bytes.Equal(f.wires[0], f.wires[1]) {
		t.Fatal("repeated native submission or changed encrypted reply")
	}
	if _, done, e := f.store.claim(context.Background(), directRuntimeAcceptance{f.binding, f.delivery, "question"}); e != nil || !done {
		t.Fatal("completed duplicate rejected")
	}
	changed := f.binding
	changed.ConsentRevision++
	if _, _, e := f.store.claim(context.Background(), directRuntimeAcceptance{changed, f.delivery, "question"}); !errors.Is(e, errDirectRuntimeRejected) {
		t.Fatal("binding conflict accepted")
	}
}
func TestDirectRuntimeUncertainAdmissionAndReopenParked(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.uncertainAdmission = true
	for range 2 {
		if e := b.Process(context.Background(), f.handle); !errors.Is(e, errDirectRuntimeRecovery) {
			t.Fatal("uncertain admission resumed")
		}
	}
	if f.admits != 1 || f.resumes != 0 {
		t.Fatal("uncertain admission repeated")
	}
	stateDir := filepath.Dir(f.store.registry.root)
	if e := f.store.registry.Close(); e != nil {
		t.Fatal(e)
	}
	r, e := OpenNativeWorkerRegistry(stateDir)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := &directRuntimeStore{registry: r}
	if _, _, e = s.claim(context.Background(), directRuntimeAcceptance{f.binding, f.delivery, "question"}); !errors.Is(e, errDirectRuntimeRecovery) {
		t.Fatal("reopened owner stolen")
	}
}
func TestDirectRuntimeRevocationAndOwnerFence(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.revoked = true
	if e := b.Process(context.Background(), f.handle); e == nil || f.admits != 0 {
		t.Fatal("revoked prompt dispatched")
	}
	wrong := f.handle
	wrong.owner = "wrong"
	if _, e := f.store.load(context.Background(), wrong); !errors.Is(e, errDirectRuntimeRecovery) {
		t.Fatal("wrong owner accepted")
	}
	wrong = f.handle
	wrong.session = "wrong-generation"
	if _, e := f.store.load(context.Background(), wrong); !errors.Is(e, errDirectRuntimeRecovery) {
		t.Fatal("wrong session accepted")
	}
	f.revoked = false
	f.uncertainSend = true
	if e := b.Process(context.Background(), f.handle); e == nil {
		t.Fatal("send uncertainty missing")
	}
	sent := f.sends
	f.revoked = true
	if e := b.Process(context.Background(), f.handle); e == nil || f.sends != sent {
		t.Fatal("revoked reply dispatched")
	}
}
func TestDirectRuntimeTwoRegistryClaims(t *testing.T) {
	_, f := runtimeBridgeFixture(t)
	r, e := OpenNativeWorkerRegistry(filepath.Dir(f.store.registry.root))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	stores := []*directRuntimeStore{f.store, {registry: r}}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, s := range stores {
		wg.Add(1)
		go func(s *directRuntimeStore) {
			defer wg.Done()
			_, _, e := s.claim(context.Background(), directRuntimeAcceptance{f.binding, f.delivery, "question"})
			errs <- e
		}(s)
	}
	wg.Wait()
	close(errs)
	success := 0
	for e := range errs {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("parallel registry handles admitted multiple owners")
	}
}

func TestDirectRuntimeMessageExpiry(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	b.deps.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 20, 0, 0, time.UTC) }
	if _, _, e := b.Accept(context.Background(), f.binding, f.delivery); e == nil {
		t.Fatal("expired delivery accepted")
	}
	b.deps.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC) }
	runtimeAccept(t, b, f)
	b.deps.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 20, 0, 0, time.UTC) }
	if e := b.Process(context.Background(), f.handle); e == nil || f.admits != 0 {
		t.Fatal("expired accepted ASK admitted")
	}
}

func TestDirectRuntimeReplyRetentionDeadline(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.uncertainSend = true
	if e := b.Process(context.Background(), f.handle); e == nil {
		t.Fatal("missing send uncertainty")
	}
	saved, e := f.store.load(context.Background(), f.handle)
	if e != nil || saved.ReconcileUntil.IsZero() {
		t.Fatal("missing durable first-send deadline")
	}
	b.deps.Now = func() time.Time { return saved.ReconcileUntil }
	sent := f.sends
	if e := b.Process(context.Background(), f.handle); !errors.Is(e, errDirectRuntimeRecovery) || f.sends != sent {
		t.Fatal("expired reconciliation resubmitted reply")
	}
}
func TestDirectRuntimeAdmissionExpiryAfterPreparation(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	b.deps.Qwen = func(directRuntimeBinding) (directRuntimeQwen, error) {
		b.deps.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 20, 0, 0, time.UTC) }
		return f, nil
	}
	if e := b.Process(context.Background(), f.handle); e == nil || f.admits != 0 {
		t.Fatal("preparation crossed TTL and admitted prompt")
	}
}

func TestDirectRuntimeSavedReceiptRetry(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.uncertainResume = true
	if e := b.Process(context.Background(), f.handle); e == nil {
		t.Fatal("missing completion uncertainty")
	}
	f.stage("admitted")
	f.uncertainResume = false
	if e := b.Process(context.Background(), f.handle); e != nil {
		t.Fatal(e)
	}
	if f.admits != 1 || f.resumes != 2 {
		t.Fatal("saved receipt resubmitted prompt")
	}
}
func TestDirectRuntimeParallelProcessors(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.skipStage = true
	second, e := newDirectRuntimeBridge(f.store, b.deps)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, p := range []*directRuntimeBridge{b, second} {
		wg.Add(1)
		go func(p *directRuntimeBridge) { defer wg.Done(); errs <- p.Process(context.Background(), f.handle) }(p)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if f.admits != 1 || f.resumes != 1 || f.sends != 1 {
		t.Fatal("parallel processors repeated native execution or send")
	}
}
func TestDirectRuntimeAdmittedSenderReceiptPreventsResend(t *testing.T) {
	b, f := runtimeBridgeFixture(t)
	runtimeAccept(t, b, f)
	f.uncertainSend = true
	if e := b.Process(context.Background(), f.handle); e == nil {
		t.Fatal("missing send uncertainty")
	}
	f.receiptAdmitted = true
	if e := b.Process(context.Background(), f.handle); e != nil {
		t.Fatal(e)
	}
	if f.sends != 1 || f.admits != 1 {
		t.Fatal("admitted sender receipt caused resubmission")
	}
}
