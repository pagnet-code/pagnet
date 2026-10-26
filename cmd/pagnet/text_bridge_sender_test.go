package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

const textBridgeSenderProject = "22222222-2222-4222-8222-222222222222"
const textBridgeSenderRecipient = "33333333-3333-4333-8333-333333333333"

func textBridgeSenderExecute(t *testing.T, deps textBridgeDependencies, input string, args ...string) (string, error) {
	t.Helper()
	cmd := textBridgeCmdWithDependencies(deps)
	var output bytes.Buffer
	cmd.SetIn(strings.NewReader(input))
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return output.String(), err
}

func textBridgeSenderSetup(t *testing.T) (string, string, textBridgeSenderProfile) {
	t.Helper()
	state := textBridgeTestDir(t)
	dir := filepath.Join(state, "text-bridge", "senders", textBridgeTestService)
	if err := textBridgePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	p := textBridgeSenderProfile{Service: textBridgeTestService, Server: "https://example.com", Credential: "pgn_act_v1_private-sender-credential"}
	if err := textBridgeSaveJSON(dir, "profile.json", p); err != nil {
		t.Fatal(err)
	}
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	return state, dir, p
}

type textBridgeSenderFake struct {
	t                   *testing.T
	dir                 string
	principal           string
	prepared            sdk.PreparedSharingProjectMessage
	receipt             *sdk.SharingProjectMessageReceipt
	prepareErr, sendErr error
	prepares, sends     int
	statusCalls         int
	handler             func(context.Context, sdk.SharingProjectMessage) error
	ready               func(string)
	replyOnSend         bool
	replyOnEnable       bool
	closed              bool
	messageErr          error
	onEnable            func()
}

func (f *textBridgeSenderFake) WhoAmI(context.Context) (*sdk.Identity, error) {
	principal := f.principal
	if principal == "" {
		principal = textBridgeTestService
	}
	return &sdk.Identity{PrincipalID: principal, Kind: "service"}, nil
}
func (f *textBridgeSenderFake) SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error) {
	f.statusCalls++
	return sdk.SharingProjectStatus{ProjectID: textBridgeSenderProject, State: "active", EndpointProved: true}, nil
}
func (f *textBridgeSenderFake) PrepareSharingProjectMessageWithID(project, recipient, kind, id string, input, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	f.prepares++
	store, err := sender.Open(filepath.Join(f.dir, "operations"), sender.Binding{ServiceOrigin: "https://example.com", PrincipalID: textBridgeTestService})
	if err != nil {
		f.t.Fatal(err)
	}
	defer store.Close()
	o, err := store.Get(context.Background(), project, id)
	if err != nil || o.Phase != sender.Preparing || o.RecipientID != recipient || kind != "ASK" || string(input) != "test prompt" || len(predecessor) != 0 {
		f.t.Fatalf("preparation before durable reservation: %+v %v", o, err)
	}
	if f.prepareErr != nil {
		return sdk.PreparedSharingProjectMessage{ID: id}, f.prepareErr
	}
	f.prepared = sdk.PreparedSharingProjectMessage{ID: id, Wire: []byte("immutable SDK ciphertext")}
	return f.prepared, nil
}
func (f *textBridgeSenderFake) LoadPreparedSharingProjectMessage(project, id string) (sdk.PreparedSharingProjectMessage, error) {
	if f.prepared.ID != id || len(f.prepared.Wire) == 0 {
		return sdk.PreparedSharingProjectMessage{}, os.ErrNotExist
	}
	return f.prepared, nil
}
func (f *textBridgeSenderFake) SharingProjectMessageReceipt(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error) {
	if f.receipt == nil {
		return sdk.SharingProjectMessageReceipt{}, os.ErrNotExist
	}
	return *f.receipt, nil
}
func (f *textBridgeSenderFake) SendPreparedSharingProjectMessage(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	f.sends++
	if f.sendErr != nil {
		return sdk.SharingProjectMessageReceipt{}, f.sendErr
	}
	if f.prepared.ID != id {
		f.t.Fatal("send used a different ID")
	}
	sum := sha256.Sum256(f.prepared.Wire)
	f.receipt = &sdk.SharingProjectMessageReceipt{MessageID: id, AdmissionSeq: 1, RequestDigest: sum[:], CreatedAt: time.Now().UTC(), Status: "pending"}
	if f.replyOnSend {
		f.deliver(ctx)
	}
	return *f.receipt, nil
}
func (f *textBridgeSenderFake) OnSharingProjectMessage(h func(context.Context, sdk.SharingProjectMessage) error) {
	f.handler = h
}
func (f *textBridgeSenderFake) OnSharingProjectReady(h func(string)) { f.ready = h }
func (f *textBridgeSenderFake) EnableSharingProjects() {
	if f.onEnable != nil {
		f.onEnable()
		return
	}
	f.ready(textBridgeSenderProject)
	if f.replyOnEnable {
		f.deliver(context.Background())
	}
}

func TestTextBridgeSenderUnrelatedASKDoesNotEndWait(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir}
	f.onEnable = func() {
		if err := f.handler(context.Background(), sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "ASK", ProjectID: textBridgeSenderRecipient}}); err != nil {
			t.Fatalf("sender did not ACK-discard ASK: %v", err)
		}
	}
	_, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "50ms")
	if !errors.Is(err, context.DeadlineExceeded) || f.prepares != 0 || f.sends != 0 {
		t.Fatalf("unrelated ASK ended foreground wait or dispatched work: %v", err)
	}
}

func TestTextBridgeSenderUnrelatedInvalidReplyDoesNotEndWait(t *testing.T) {
	for _, otherProject := range []bool{false, true} {
		t.Run(map[bool]string{false: "other ASK", true: "other project"}[otherProject], func(t *testing.T) {
			state, dir, p := textBridgeSenderSetup(t)
			f := &textBridgeSenderFake{t: t, dir: dir}
			f.onEnable = func() {
				store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				operations, err := store.List(context.Background())
				if err != nil || len(operations) != 1 {
					t.Fatalf("reservation missing: %v", err)
				}
				ask, project := operations[0].AskID, textBridgeSenderProject
				if otherProject {
					project = textBridgeSenderRecipient
				} else {
					id, _ := uuid.NewV7()
					ask = id.String()
				}
				id, _ := uuid.NewV7()
				m := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: project, ID: id.String(), ThreadID: ask, CorrelationID: &ask, SenderPrincipalID: textBridgeSenderRecipient, RecipientPrincipalID: p.Service}, Plaintext: []byte("answer"), Wire: []byte("authenticated reply")}
				if err := f.handler(context.Background(), m); err == nil {
					t.Fatal("invalid unrelated REPLY silently ACKed")
				}
			}
			_, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "50ms")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unrelated REPLY ended foreground wait: %v", err)
			}
		})
	}
}
func (f *textBridgeSenderFake) Done() <-chan struct{} { return nil }
func (f *textBridgeSenderFake) Close() error          { f.closed = true; return nil }
func (f *textBridgeSenderFake) deliver(ctx context.Context) {
	id, _ := uuid.NewV7()
	ask := f.prepared.ID
	m := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: textBridgeSenderProject, ID: id.String(), ThreadID: ask, CorrelationID: &ask, SenderPrincipalID: textBridgeSenderRecipient, RecipientPrincipalID: textBridgeTestService}, Plaintext: []byte("saved answer"), Wire: []byte("authenticated reply ciphertext")}
	f.messageErr = f.handler(ctx, m)
	if f.messageErr != nil {
		f.t.Fatal(f.messageErr)
	}
	// A nil callback return authorizes ACK, so commit must already be readable.
	store, err := sender.Open(filepath.Join(f.dir, "operations"), sender.Binding{ServiceOrigin: "https://example.com", PrincipalID: textBridgeTestService})
	if err != nil {
		f.t.Fatal(err)
	}
	defer store.Close()
	o, err := store.Get(ctx, textBridgeSenderProject, ask)
	if err != nil || o.Reply == nil || o.Reply.Text != "saved answer" {
		f.t.Fatalf("callback ACK before durable reply: %+v %v", o, err)
	}
}

func textBridgeSenderDeps(f *textBridgeSenderFake) textBridgeDependencies {
	return textBridgeDependencies{senderConnect: func(_ context.Context, c sdk.Config) (textBridgeSenderConnection, error) {
		if c.ExpectedPrincipalID != textBridgeTestService || c.StateDir != filepath.Join(f.dir, "sdk") || !strings.HasPrefix(c.Credential, "pgn_act_v1_") {
			f.t.Fatal("sender connection binding missing")
		}
		return f, nil
	}}
}

func TestTextBridgeSenderCreatePrivateProfile(t *testing.T) {
	state := textBridgeTestDir(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/service-recipes" || r.Header.Get("Authorization") != "Bearer private-owner-token" {
			t.Fatal("unexpected service creation request")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["name"] != "sender" {
			t.Fatal("sender must create a standard personal service")
		}
		json.NewEncoder(w).Encode(map[string]string{"id": textBridgeTestService, "activationCredential": "pgn_act_v1_private-sender-credential"})
	}))
	defer server.Close()
	deps := textBridgeDependencies{owner: func() (*cliCtx, error) { return &cliCtx{base: server.URL, token: "private-owner-token"}, nil }}
	out, err := textBridgeSenderExecute(t, deps, "", "--state-dir", state, "sender", "create", "--name", "sender")
	if err != nil || out != textBridgeTestService+"\n" || calls != 1 {
		t.Fatalf("create: %q %v calls=%d", out, err, calls)
	}
	dir := filepath.Join(state, "text-bridge", "senders", textBridgeTestService)
	if _, err := textBridgeSenderLoadProfile(dir, textBridgeTestService); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "profile.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("profile is not private")
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sender initialized responder ledger")
	}
}

func TestTextBridgeSenderAskPersistsBeforePrepareAndACK(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir, replyOnSend: true}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s")
	if err != nil || out != f.prepared.ID+"\nsaved answer\n" || f.prepares != 1 || f.sends != 1 || !f.closed {
		t.Fatalf("ask: %q %v prepare=%d send=%d", out, err, f.prepares, f.sends)
	}
	// Result is entirely local and does not connect or disclose the prompt.
	out, err = textBridgeSenderExecute(t, textBridgeDependencies{}, "", "--state-dir", state, "sender", "result", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--ask", f.prepared.ID)
	if err != nil || !strings.Contains(out, "saved answer") || strings.Contains(out, "test prompt") || strings.Contains(out, "credential") {
		t.Fatalf("result: %q %v", out, err)
	}
}

func TestTextBridgeSenderResumeNeverRepreparesPreparing(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir, prepareErr: errors.New("uncertain preparation")}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s")
	ask := strings.TrimSpace(out)
	if err == nil || !textBridgeUUID(ask) || f.prepares != 1 || f.sends != 0 {
		t.Fatalf("reservation not exposed on failure: %q %v", out, err)
	}
	_, err = textBridgeSenderExecute(t, textBridgeSenderDeps(f), "", "--state-dir", state, "sender", "resume", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--ask", ask, "--wait", "1s")
	if err == nil || f.prepares != 1 || f.sends != 0 {
		t.Fatalf("resume regenerated ciphertext: %v", err)
	}
}

func TestTextBridgeSenderResumeReservedAfterConnectionFailure(t *testing.T) {
	state, dir, p := textBridgeSenderSetup(t)
	failed := textBridgeDependencies{senderConnect: func(context.Context, sdk.Config) (textBridgeSenderConnection, error) {
		return nil, errors.New("offline")
	}}
	out, err := textBridgeSenderExecute(t, failed, "test prompt", "--state-dir", state, "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s")
	ask := strings.TrimSpace(out)
	if err == nil || !textBridgeUUID(ask) {
		t.Fatalf("connection failure lost ASK: %q %v", out, err)
	}
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	o, err := store.Get(context.Background(), textBridgeSenderProject, ask)
	if err != nil || o.Phase != sender.Reserved {
		t.Fatalf("preparation was entered before connection: %+v %v", o, err)
	}
	store.Close()
	f := &textBridgeSenderFake{t: t, dir: dir, replyOnSend: true}
	out, err = textBridgeSenderExecute(t, textBridgeSenderDeps(f), "", "--state-dir", state, "sender", "resume", "--service", p.Service, "--project", textBridgeSenderProject, "--ask", ask, "--wait", "1s")
	if err != nil || out != "saved answer\n" || f.prepares != 1 || f.sends != 1 || f.prepared.ID != ask {
		t.Fatalf("reserved resume: %q %v prepares=%d sends=%d", out, err, f.prepares, f.sends)
	}
}

func TestTextBridgeSenderResumePreparingRequiresSpoolEvidence(t *testing.T) {
	for _, spooled := range []bool{false, true} {
		t.Run(map[bool]string{false: "crash before SDK call", true: "crash after SDK prepare"}[spooled], func(t *testing.T) {
			state, dir, p := textBridgeSenderSetup(t)
			store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
			if err != nil {
				t.Fatal(err)
			}
			o, err := store.Reserve(context.Background(), textBridgeSenderProject, textBridgeSenderRecipient, "test prompt")
			if err != nil {
				t.Fatal(err)
			}
			o, err = store.MarkPreparing(context.Background(), o.ProjectID, o.AskID)
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			f := &textBridgeSenderFake{t: t, dir: dir, replyOnSend: true}
			if spooled {
				f.prepared = sdk.PreparedSharingProjectMessage{ID: o.AskID, Wire: []byte("existing SDK ciphertext")}
			}
			out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "", "--state-dir", state, "sender", "resume", "--service", p.Service, "--project", o.ProjectID, "--ask", o.AskID, "--wait", "1s")
			if f.prepares != 0 {
				t.Fatal("resumed ambiguous preparation by preparing again")
			}
			if spooled {
				if err != nil || out != "saved answer\n" || f.sends != 1 {
					t.Fatalf("spool reconciliation: %q %v sends=%d", out, err, f.sends)
				}
			} else if err == nil || f.sends != 0 {
				t.Fatalf("missing spool was not left unresolved: %v", err)
			}
		})
	}
}

func TestTextBridgeSenderResumeReconcilesSamePreparedID(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir, sendErr: errors.New("uncertain admission")}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s")
	if err == nil || strings.TrimSpace(out) != f.prepared.ID {
		t.Fatalf("ask: %q %v", out, err)
	}
	f.sendErr = nil
	f.replyOnSend = true
	out, err = textBridgeSenderExecute(t, textBridgeSenderDeps(f), "", "--state-dir", state, "sender", "resume", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--ask", f.prepared.ID, "--wait", "1s")
	if err != nil || out != "saved answer\n" || f.prepares != 1 || f.sends != 2 {
		t.Fatalf("resume: %q %v prepares=%d sends=%d", out, err, f.prepares, f.sends)
	}
}

func TestTextBridgeSenderIdentityMismatchDoesNotPrepare(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir, principal: textBridgeSenderRecipient}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s")
	if err == nil || !textBridgeUUID(strings.TrimSpace(out)) || f.prepares != 0 || f.sends != 0 {
		t.Fatalf("identity mismatch dispatched: %q %v", out, err)
	}
}

func TestTextBridgeSenderResumeReceiptAfterSDKRetiresCiphertext(t *testing.T) {
	state, dir, p := textBridgeSenderSetup(t)
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	o, err := store.Reserve(context.Background(), textBridgeSenderProject, textBridgeSenderRecipient, "test prompt")
	if err != nil {
		t.Fatal(err)
	}
	wire := []byte("ciphertext retired after admission")
	o, err = store.MarkPreparing(context.Background(), o.ProjectID, o.AskID)
	if err != nil {
		t.Fatal(err)
	}
	o, err = store.MarkPrepared(context.Background(), o.ProjectID, o.AskID, sdk.PreparedSharingProjectMessage{ID: o.AskID, Wire: wire})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	sum := sha256.Sum256(wire)
	f := &textBridgeSenderFake{t: t, dir: dir, prepared: sdk.PreparedSharingProjectMessage{ID: o.AskID}, replyOnEnable: true, receipt: &sdk.SharingProjectMessageReceipt{MessageID: o.AskID, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "", "--state-dir", state, "sender", "resume", "--service", p.Service, "--project", o.ProjectID, "--ask", o.AskID, "--wait", "1s")
	if err != nil || out != "saved answer\n" || f.prepares != 0 || f.sends != 0 || f.statusCalls != 0 {
		t.Fatalf("historical admission recovery: %q %v prepares=%d sends=%d status=%d", out, err, f.prepares, f.sends, f.statusCalls)
	}
}

func TestTextBridgeSenderWaitIsBoundedWithoutPolling(t *testing.T) {
	state, dir, _ := textBridgeSenderSetup(t)
	f := &textBridgeSenderFake{t: t, dir: dir}
	out, err := textBridgeSenderExecute(t, textBridgeSenderDeps(f), "test prompt", "--state-dir", state, "sender", "ask", "--service", textBridgeTestService, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "200ms")
	if !errors.Is(err, context.DeadlineExceeded) || strings.TrimSpace(out) != f.prepared.ID || f.prepares != 1 || f.sends != 1 || f.statusCalls != 1 || !f.closed {
		t.Fatalf("bounded wait: %q %v prepares=%d sends=%d status=%d", out, err, f.prepares, f.sends, f.statusCalls)
	}
}

func TestTextBridgeSenderInputLimits(t *testing.T) {
	for _, input := range []string{"", "  \n", string([]byte{0xff}), strings.Repeat("a", sender.MaxPromptChars+1), strings.Repeat("🦊", sender.MaxPromptChars+1)} {
		if _, err := textBridgeSenderInput(strings.NewReader(input), "-"); err == nil {
			t.Fatal("accepted invalid prompt")
		}
	}
	path := filepath.Join(t.TempDir(), "prompt.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("🦊", sender.MaxPromptChars)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := textBridgeSenderInput(nil, path); err != nil {
		t.Fatal(err)
	}
}

func TestTextBridgeSenderReplyRejectsMismatchedCorrelation(t *testing.T) {
	_, dir, p := textBridgeSenderSetup(t)
	store, err := sender.Open(filepath.Join(dir, "operations"), sender.Binding{ServiceOrigin: p.Server, PrincipalID: p.Service})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	o, err := store.Reserve(context.Background(), textBridgeSenderProject, textBridgeSenderRecipient, "test prompt")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.NewV7()
	ask := o.AskID
	valid := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: o.ProjectID, ID: id.String(), ThreadID: ask, CorrelationID: &ask, SenderPrincipalID: textBridgeSenderRecipient, RecipientPrincipalID: p.Service}, Plaintext: []byte("answer"), Wire: []byte("authenticated")}
	for _, change := range []func(*sdk.SharingProjectMessage){
		func(m *sdk.SharingProjectMessage) { m.Header.Kind = "ASK" },
		func(m *sdk.SharingProjectMessage) { m.Header.CorrelationID = nil },
		func(m *sdk.SharingProjectMessage) { m.Header.ThreadID = id.String() },
		func(m *sdk.SharingProjectMessage) { m.Header.SenderPrincipalID = p.Service },
		func(m *sdk.SharingProjectMessage) { m.Header.RecipientPrincipalID = textBridgeSenderRecipient },
		func(m *sdk.SharingProjectMessage) { m.Header.ProjectID = textBridgeSenderRecipient },
	} {
		bad := valid
		change(&bad)
		if _, err := textBridgeSenderReply(context.Background(), store, p.Service, bad); err == nil {
			t.Fatal("accepted mismatched REPLY")
		}
	}
	stored, _ := store.Get(context.Background(), o.ProjectID, o.AskID)
	if stored.Reply != nil {
		t.Fatal("rejected REPLY persisted")
	}
}
