package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/internal/textbridge/senderipc"
	"github.com/pagnet-code/pagnet/sdk"
)

func registeredSenderFixture(t *testing.T) (string, string, textbridge.Profile) {
	t.Helper()
	state, dir, p := textBridgeSenderSetup(t)
	p.Role = "sender"
	p.Registration = &textbridge.ProfileRegistration{InstallationID: uuid.NewString(), HostID: uuid.NewString(), Role: "sender", ProfileVersion: 1, TenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), Generation: 1, DesiredState: "enabled"}
	if err := textbridge.SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	return state, dir, p
}
func TestTextBridgeSenderRegisteredOfflineFailsClosedAndPrintsID(t *testing.T) {
	state, dir, p := registeredSenderFixture(t)
	deps := textBridgeDependencies{senderConnect: func(context.Context, sdk.Config) (textBridgeSenderConnection, error) {
		t.Fatal("registered sender connected foreground SDK")
		return nil, errors.New("unexpected")
	}}
	out, err := textBridgeSenderExecute(t, deps, "test prompt", "--state-dir", state, "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "50ms")
	ask := strings.TrimSpace(out)
	if !errors.Is(err, senderipc.ErrUnavailable) || !textBridgeSenderAskUUID(ask) {
		t.Fatalf("offline ask: %q %v", out, err)
	}
	if _, err := textbridge.ReadPrivate(filepath.Join(state, "text-bridge", "sender-requests", ask, "intent.json"), 16384); err != nil {
		t.Fatal("ID was not durable before unavailable result", err)
	}
	store, err := textbridge.OpenSenderStore(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Get(context.Background(), textBridgeSenderProject, ask); !errors.Is(err, sender.ErrNotFound) {
		t.Fatal("offline CLI opened or reserved daemon operation", err)
	}
	out, err = textBridgeSenderExecute(t, deps, "test prompt", "--state-dir", state, "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--ask", ask, "--wait", "50ms")
	if out != ask+"\n" || !errors.Is(err, senderipc.ErrUnavailable) {
		t.Fatalf("offline retry replaced ID: %q %v", out, err)
	}
	_, err = textBridgeSenderExecute(t, deps, "", "--state-dir", state, "sender", "resume", "--service", p.Service, "--project", textBridgeSenderProject, "--ask", ask, "--wait", "50ms")
	if !errors.Is(err, senderipc.ErrUnavailable) {
		t.Fatal("offline registered resume did not fail closed", err)
	}
}
func TestTextBridgeSenderIntentConcurrentConflictAndUnsafePaths(t *testing.T) {
	state, _, p := registeredSenderFixture(t)
	id, _ := uuid.NewV7()
	req := senderipc.Request{Version: 1, Binding: textBridgeSenderBinding(p), Action: "ask", ProjectID: textBridgeSenderProject, RecipientID: textBridgeSenderRecipient, AskID: id.String(), Prompt: "test prompt", WaitMillis: 50}
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- textBridgeSenderSaveIntent(state, req) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent identical retry conflicted", err)
		}
	}
	for _, mutate := range []func(*senderipc.Request){func(r *senderipc.Request) { r.Binding.ServiceID = uuid.NewString() }, func(r *senderipc.Request) { r.Binding.TenantID = uuid.NewString() }, func(r *senderipc.Request) { r.Binding.OwnerUserID = uuid.NewString() }, func(r *senderipc.Request) { r.Binding.HostID = uuid.NewString() }, func(r *senderipc.Request) { r.Binding.InstallationID = uuid.NewString() }, func(r *senderipc.Request) { r.Binding.Server = "https://elsewhere.example" }, func(r *senderipc.Request) { r.ProjectID = uuid.NewString() }, func(r *senderipc.Request) { r.RecipientID = uuid.NewString() }, func(r *senderipc.Request) { r.Prompt = "changed" }} {
		bad := req
		mutate(&bad)
		if err := textBridgeSenderSaveIntent(state, bad); !errors.Is(err, sender.ErrConflict) {
			t.Fatal("changed intent binding did not conflict", err)
		}
	}
	raw, err := textbridge.ReadPrivate(filepath.Join(state, "text-bridge", "sender-requests", req.AskID, "intent.json"), 16384)
	if err != nil || strings.Contains(string(raw), "test prompt") {
		t.Fatal("intent leaked plaintext prompt or was missing", err)
	}
	if textBridgeSenderAskUUID("00000000-0000-7000-0000-000000000001") {
		t.Fatal("non-RFC ASK UUID accepted")
	}
	bad := req
	bad.AskID = "../escape"
	if err := textBridgeSenderSaveIntent(state, bad); !errors.Is(err, sender.ErrInvalid) {
		t.Fatal("invalid ASK path accepted", err)
	}
	// An incomplete unpublished temporary file cannot claim the ASK ID.
	fresh, _ := uuid.NewV7()
	req.AskID = fresh.String()
	dir := filepath.Join(state, "text-bridge", "sender-requests", req.AskID)
	if err := textbridge.PrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".intent-crashed"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := textBridgeSenderSaveIntent(state, req); err != nil {
		t.Fatal("crash before publication blocked retry", err)
	}
	for _, unsafe := range []string{"symlink directory", "symlink file", "public file"} {
		t.Run(unsafe, func(t *testing.T) {
			fresh, _ := uuid.NewV7()
			bad := req
			bad.AskID = fresh.String()
			dir := filepath.Join(state, "text-bridge", "sender-requests", bad.AskID)
			if unsafe == "symlink directory" {
				target := filepath.Join(state, "target")
				if err := textbridge.PrivateDir(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := textbridge.PrivateDir(dir); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "intent.json")
				if unsafe == "symlink file" {
					target := filepath.Join(state, "external")
					if err := os.WriteFile(target, []byte("external"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := textBridgeSenderSaveIntent(state, bad); err == nil {
				t.Fatal("unsafe intent path accepted")
			}
		})
	}
}

func TestTextBridgeSenderRegisteredOfflineResultLocksStore(t *testing.T) {
	state, dir, p := registeredSenderFixture(t)
	store, err := textbridge.OpenSenderStore(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	op, err := store.Reserve(context.Background(), textBridgeSenderProject, textBridgeSenderRecipient, "test prompt")
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	args := []string{"--state-dir", state, "sender", "result", "--service", p.Service, "--project", textBridgeSenderProject, "--ask", op.AskID}
	out, err := textBridgeSenderExecute(t, textBridgeDependencies{}, "", args...)
	if err != nil || !strings.Contains(out, op.AskID) {
		t.Fatalf("offline result: %q %v", out, err)
	}
	unlock, err := textbridge.LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := textBridgeSenderExecute(t, textBridgeDependencies{}, "", args...); !errors.Is(err, senderipc.ErrUnavailable) {
		t.Fatal("result bypassed live profile lock", err)
	}
}

type cliManagedSenderEndpoint struct{ *textBridgeSenderFake }

func (e *cliManagedSenderEndpoint) PrepareSharingProjectMessageWithID(project, to, kind, id string, input, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	intent := filepath.Join(filepath.Dir(filepath.Dir(e.dir)), "sender-requests", id, "intent.json")
	if _, err := textbridge.ReadPrivate(intent, 16384); err != nil {
		e.t.Fatal("RPC preparation preceded durable CLI intent", err)
	}
	return e.textBridgeSenderFake.PrepareSharingProjectMessageWithID(project, to, kind, id, input, predecessor)
}

func (e *cliManagedSenderEndpoint) deliver(ctx context.Context) {
	id, _ := uuid.NewV7()
	ask := e.prepared.ID
	m := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: textBridgeSenderProject, ID: id.String(), ThreadID: ask, CorrelationID: &ask, SenderPrincipalID: textBridgeSenderRecipient, RecipientPrincipalID: textBridgeTestService}, Plaintext: []byte("saved answer"), Wire: []byte("authenticated reply ciphertext")}
	if err := e.handler(ctx, m); err != nil {
		e.t.Error(err)
	}
}
func (e *cliManagedSenderEndpoint) SendPreparedSharingProjectMessage(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	e.sends++
	sum := sha256.Sum256(e.prepared.Wire)
	e.receipt = &sdk.SharingProjectMessageReceipt{MessageID: id, AdmissionSeq: 1, RequestDigest: sum[:], CreatedAt: time.Now().UTC(), Status: "pending"}
	e.deliver(ctx)
	return *e.receipt, nil
}
func TestTextBridgeSenderRegisteredOnlineAskResumeResult(t *testing.T) {
	state, dir, p := registeredSenderFixture(t)
	server, err := senderipc.Listen(state)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	unlock, err := textbridge.LockProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	store, err := textbridge.OpenSenderStore(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fake := &cliManagedSenderEndpoint{&textBridgeSenderFake{t: t, dir: dir}}
	published := make(chan struct{})
	controller := sender.NewController(store, fake, p.Service, sender.ControllerConfig{Enabled: func(string) bool { return true }, OnReady: func(c *sender.Controller) func() {
		cleanup, err := server.Publish(textBridgeSenderBinding(p), c)
		if err != nil {
			t.Error(err)
		}
		close(published)
		return cleanup
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	defer func() { cancel(); <-done }()
	<-published
	deps := textBridgeDependencies{senderConnect: func(context.Context, sdk.Config) (textBridgeSenderConnection, error) {
		t.Fatal("online registered sender opened foreground SDK")
		return nil, errors.New("unexpected")
	}}
	args := []string{"--state-dir", state, "sender", "ask", "--service", p.Service, "--project", textBridgeSenderProject, "--to", textBridgeSenderRecipient, "--wait", "1s"}
	out, err := textBridgeSenderExecute(t, deps, "test prompt", args...)
	fields := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil || len(fields) != 2 || !textBridgeSenderAskUUID(fields[0]) || fields[1] != "saved answer" {
		t.Fatalf("online ask: %q %v", out, err)
	}
	ask := fields[0]
	out, err = textBridgeSenderExecute(t, deps, "test prompt", append(args, "--ask", ask)...)
	if err != nil || out != ask+"\nsaved answer\n" {
		t.Fatalf("same-ID retry: %q %v", out, err)
	}
	out, err = textBridgeSenderExecute(t, deps, "", "--state-dir", state, "sender", "resume", "--service", p.Service, "--project", textBridgeSenderProject, "--ask", ask, "--wait", "1s")
	if err != nil || out != "saved answer\n" {
		t.Fatalf("online resume: %q %v", out, err)
	}
	out, err = textBridgeSenderExecute(t, deps, "", "--state-dir", state, "sender", "result", "--service", p.Service, "--project", textBridgeSenderProject, "--ask", ask)
	if err != nil || !strings.Contains(out, "saved answer") {
		t.Fatalf("online result under daemon lock: %q %v", out, err)
	}
	var retries sync.WaitGroup
	retryErrors := make(chan error, 8)
	for range 8 {
		retries.Add(1)
		go func() {
			defer retries.Done()
			out, err := textBridgeSenderExecute(t, deps, "test prompt", append(append([]string{}, args...), "--ask", ask)...)
			if err == nil && out != ask+"\nsaved answer\n" {
				err = errors.New("concurrent retry changed saved operation")
			}
			retryErrors <- err
		}()
	}
	retries.Wait()
	close(retryErrors)
	for err := range retryErrors {
		if err != nil {
			t.Fatal("concurrent CLI retry failed", err)
		}
	}
	if fake.prepares != 1 || fake.sends != 1 {
		t.Fatal("online retry generated duplicate work")
	}
}
