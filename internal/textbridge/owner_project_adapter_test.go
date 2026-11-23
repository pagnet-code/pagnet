package textbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/textbridge/ledger"
	"github.com/pagnet-code/pagnet/internal/textbridge/provider"
	"github.com/pagnet-code/pagnet/internal/textbridge/sender"
	"github.com/pagnet-code/pagnet/sdk"
)

type ownerAdapterEndpoint struct {
	*runtimeConnection
	mu                                     sync.Mutex
	endpoint                               string
	session                                chan struct{}
	status                                 sdk.OwnerTextProjectStatus
	proof                                  bool
	events                                 []string
	listErr, enrollErr, enableErr, sendErr error
	ownerMessage                           func(context.Context, sdk.OwnerTextProjectMessage) error
	ownerReady                             func(string)
	onEnable                               func()
	prepared                               map[string]sdk.PreparedOwnerTextProjectMessage
	headers                                map[string]sdk.OwnerTextProjectMessageHeader
	receipts                               map[string]sdk.OwnerTextProjectMessageReceipt
	beforeSend                             func(string) error
}

func ownerAdapterProfile(role string) Profile {
	registration := &ProfileRegistration{InstallationID: uuid.NewString(), HostID: uuid.NewString(), Role: role, ProfileVersion: 1, TenantID: uuid.NewString(), OwnerUserID: uuid.NewString(), Generation: 1, DesiredState: "enabled"}
	return Profile{ProjectContract: OwnerTextProjectContract, Role: role, Service: uuid.NewString(), Server: "https://control.example", Credential: "pgn_act_v1_test", Registration: registration}
}
func newOwnerAdapterEndpoint(p Profile, peer, peerInstallation, project string) *ownerAdapterEndpoint {
	roles := []sdk.OwnerTextProjectRoleStatus{{Role: "sender", PrincipalID: p.Service, InstallationID: p.Registration.InstallationID, Ready: true}, {Role: "responder", PrincipalID: peer, InstallationID: peerInstallation}}
	if p.ServiceRole() == "responder" {
		roles[0], roles[1] = sdk.OwnerTextProjectRoleStatus{Role: "sender", PrincipalID: peer, InstallationID: peerInstallation}, sdk.OwnerTextProjectRoleStatus{Role: "responder", PrincipalID: p.Service, InstallationID: p.Registration.InstallationID, Ready: true}
	}
	return &ownerAdapterEndpoint{runtimeConnection: &runtimeConnection{identity: &sdk.Identity{Kind: "service", PrincipalID: p.Service, TenantID: p.Registration.TenantID}, terminal: make(chan struct{}), closed: make(chan struct{})}, endpoint: uuid.NewString(), session: make(chan struct{}), status: sdk.OwnerTextProjectStatus{ProjectID: project, NetworkID: uuid.NewString(), State: "active", EndpointProved: true, RosterSize: 2, Roles: roles, PrincipalsProved: 1}, prepared: map[string]sdk.PreparedOwnerTextProjectMessage{}, headers: map[string]sdk.OwnerTextProjectMessageHeader{}, receipts: map[string]sdk.OwnerTextProjectMessageReceipt{}}
}
func (f *ownerAdapterEndpoint) WhoAmI(context.Context) (*sdk.Identity, error) {
	f.events = append(f.events, "auth")
	return f.identity, nil
}
func (f *ownerAdapterEndpoint) TextServiceEndpointSession() (string, <-chan struct{}, error) {
	return f.endpoint, f.session, nil
}
func (f *ownerAdapterEndpoint) ListOwnerTextProjects(context.Context) ([]sdk.OwnerTextProjectStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "list")
	if !f.proof {
		return nil, errors.New("enrollment before proof")
	}
	return []sdk.OwnerTextProjectStatus{f.status}, f.listErr
}
func (f *ownerAdapterEndpoint) EnrollOwnerTextProject(context.Context, string, string) (sdk.OwnerTextProjectEnrollment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "enroll")
	if !f.proof {
		return sdk.OwnerTextProjectEnrollment{}, errors.New("enrollment before proof")
	}
	return sdk.OwnerTextProjectEnrollment{Status: f.status, Pending: !f.status.Ready}, f.enrollErr
}
func (f *ownerAdapterEndpoint) EnableOwnerTextProjects(string) error {
	f.mu.Lock()
	f.events = append(f.events, "enable")
	err := f.enableErr
	hook := f.onEnable
	f.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	return err
}
func (f *ownerAdapterEndpoint) OnOwnerTextProjectMessage(handler func(context.Context, sdk.OwnerTextProjectMessage) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "handler")
	f.ownerMessage = handler
}
func (f *ownerAdapterEndpoint) OnOwnerTextProjectReady(handler func(string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "ready handler")
	f.ownerReady = handler
}
func (f *ownerAdapterEndpoint) PrepareOwnerTextProjectMessageWithID(project, to, kind, id string, input, previous []byte) (sdk.PreparedOwnerTextProjectMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	header := sdk.OwnerTextProjectMessageHeader{Version: 1, Domain: "pagnet/owner-text-project/message/v1", ProjectID: project, NetworkID: f.status.NetworkID, ID: id, ThreadID: id, Kind: kind, SenderPrincipalID: f.identity.PrincipalID, RecipientPrincipalID: to, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if kind == "REPLY" {
		var root struct {
			Header sdk.OwnerTextProjectMessageHeader `json:"header"`
		}
		if json.Unmarshal(previous, &root) != nil {
			return sdk.PreparedOwnerTextProjectMessage{}, errors.New("bad predecessor")
		}
		header.ThreadID = root.Header.ID
		header.CorrelationID = &root.Header.ID
	}
	wire, _ := json.Marshal(struct {
		Header     sdk.OwnerTextProjectMessageHeader `json:"header"`
		Ciphertext string                            `json:"ciphertext"`
	}{header, "opaque-owner-ciphertext:" + id})
	prepared := sdk.PreparedOwnerTextProjectMessage{ID: id, Wire: wire, LocalEvidence: []byte("persisted owner evidence")}
	f.prepared[id] = prepared
	f.headers[id] = header
	return prepared, nil
}
func (f *ownerAdapterEndpoint) LoadPreparedOwnerTextProjectMessage(_, id string) (sdk.PreparedOwnerTextProjectMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prepared, ok := f.prepared[id]
	if !ok {
		return prepared, os.ErrNotExist
	}
	return prepared, nil
}
func (f *ownerAdapterEndpoint) OwnerTextProjectMessageReceipt(_ context.Context, _, id string) (sdk.OwnerTextProjectMessageReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	receipt, ok := f.receipts[id]
	if !ok {
		return receipt, os.ErrNotExist
	}
	return receipt, nil
}
func (f *ownerAdapterEndpoint) SendPreparedOwnerTextProjectMessage(_ context.Context, _, id string) (sdk.OwnerTextProjectMessageReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beforeSend != nil {
		if err := f.beforeSend(id); err != nil {
			return sdk.OwnerTextProjectMessageReceipt{}, err
		}
	}
	if f.sendErr != nil {
		return sdk.OwnerTextProjectMessageReceipt{}, f.sendErr
	}
	prepared := f.prepared[id]
	sum := sha256.Sum256(prepared.Wire)
	receipt := sdk.OwnerTextProjectMessageReceipt{MessageID: id, AdmissionSeq: 1, RequestDigest: sum[:], Status: "pending", CreatedAt: time.Now().UTC()}
	f.receipts[id] = receipt
	return receipt, nil
}
func (f *ownerAdapterEndpoint) EnableSharingProjects() { panic("wrong contract enable") }
func ownerAdapterForTest(t *testing.T, p Profile, f *ownerAdapterEndpoint) *ownerProjectAdapter {
	t.Helper()
	f.proof = true
	a, err := selectOwnerProjectAdapter(context.Background(), f, p, f.identity, f.endpoint, f.session)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestOwnerProjectAdapterExactMappingAndDirection(t *testing.T) {
	p := ownerAdapterProfile("sender")
	project, peer := uuid.NewString(), uuid.NewString()
	f := newOwnerAdapterEndpoint(p, peer, uuid.NewString(), project)
	a := ownerAdapterForTest(t, p, f)
	id, _ := uuid.NewV7()
	prepared, err := a.PrepareSharingProjectMessageWithID(project, peer, "ASK", id.String(), []byte("question"), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.prepared[id.String()]
	loaded, err := a.LoadPreparedSharingProjectMessage(project, id.String())
	if err != nil || !bytes.Equal(prepared.Wire, raw.Wire) || !bytes.Equal(loaded.Wire, raw.Wire) || string(f.prepared[id.String()].LocalEvidence) != "persisted owner evidence" {
		t.Fatal("owner bytes or evidence changed")
	}
	receipt, err := a.SendPreparedSharingProjectMessage(context.Background(), project, id.String())
	if err != nil {
		t.Fatal(err)
	}
	want := f.receipts[id.String()]
	if receipt.MessageID != want.MessageID || receipt.AdmissionSeq != want.AdmissionSeq || !bytes.Equal(receipt.RequestDigest, want.RequestDigest) || !receipt.CreatedAt.Equal(want.CreatedAt) || receipt.Status != want.Status {
		t.Fatal("receipt projection lost binding")
	}
	if _, err = a.PrepareSharingProjectMessageWithID(project, uuid.NewString(), "ASK", id.String(), nil, nil); err == nil {
		t.Fatal("wrong target accepted")
	}
	if _, err = a.PrepareSharingProjectMessageWithID(project, peer, "REPLY", id.String(), nil, nil); err == nil {
		t.Fatal("wrong role accepted")
	}
	for _, kind := range []string{"role", "installation", "service", "proof"} {
		t.Run(kind, func(t *testing.T) {
			original := f.status
			f.status.Roles = append([]sdk.OwnerTextProjectRoleStatus(nil), original.Roles...)
			defer func() { f.status = original }()
			switch kind {
			case "role":
				f.status.Roles[0].Role = "responder"
			case "installation":
				f.status.Roles[0].InstallationID = uuid.NewString()
			case "service":
				f.status.Roles[0].PrincipalID = uuid.NewString()
			case "proof":
				f.status.EndpointProved = false
			}
			if _, err = a.SharingProjectStatus(context.Background(), project); err == nil {
				t.Fatal("bad owner authority accepted")
			}
		})
	}
	q := &sdk.OwnerTextProjectMessageQuotaError{Limit: "maxInFlight", Maximum: 1, RetryAfter: "3", StatusCode: 429}
	var projected *sdk.SharingProjectMessageQuotaError
	if !errors.As(ownerProjectError(q), &projected) || projected.Limit != q.Limit || projected.RetryAfter != q.RetryAfter || projected.Maximum != q.Maximum {
		t.Fatal("quota projection changed")
	}
	close(f.session)
	if _, err = a.LoadPreparedSharingProjectMessage(project, id.String()); err == nil || a.Ready(project) {
		t.Fatal("disconnect did not fence adapter")
	}
}
func TestOwnerProfileRuntimeStartupOrderingAndFailure(t *testing.T) {
	for _, failure := range []string{"none", "pending", "identity", "tenant", "proof", "list", "enroll", "enable", "session"} {
		t.Run(failure, func(t *testing.T) {
			p := ownerAdapterProfile("sender")
			f := newOwnerAdapterEndpoint(p, uuid.NewString(), uuid.NewString(), uuid.NewString())
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			store, err := sender.Open(filepath.Join(root, "operations"), p.SenderBinding())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			published := false
			switch failure {
			case "identity":
				f.identity.PrincipalID = uuid.NewString()
			case "tenant":
				f.identity.TenantID = uuid.NewString()
			case "list":
				f.listErr = errors.New("list failed")
			case "enroll":
				f.enrollErr = errors.New("enroll failed")
			case "enable":
				f.enableErr = errors.New("enable failed")
			case "pending":
				f.status.State = "enrolling"
				f.status.EndpointProved = false
			}
			config := RuntimeConfig{Connect: func(context.Context, sdk.Config) (RuntimeConnection, error) { return f, nil }, Authorize: func(context.Context, RuntimeConnection) error {
				f.events = append(f.events, "proof")
				if failure == "proof" {
					return errors.New("proof failed")
				}
				f.proof = true
				if failure == "session" {
					close(f.session)
					f.session = make(chan struct{})
					f.endpoint = uuid.NewString()
				}
				return nil
			}, Enabled: func(string) bool { return true }, OnSenderReady: func(*sender.Controller) func() {
				published = true
				f.events = append(f.events, "publish")
				cancel()
				return nil
			}}
			err = RunSenderProfile(ctx, root, p, store, config)
			success := failure == "none" || failure == "pending"
			if published != success || (!success && err == nil) {
				t.Fatalf("failure=%s published=%v err=%v events=%v", failure, published, err, f.events)
			}
			if success {
				events := strings.Join(f.events, ",")
				if !strings.HasPrefix(events, "auth,proof,handler,ready handler,list,enroll,enable,publish") {
					t.Fatalf("startup order: %s", events)
				}
			}
			if f.message != nil || f.ready != nil {
				t.Fatal("owner runtime registered legacy callbacks")
			}
			if (failure == "identity" || failure == "tenant") && strings.Join(f.events, ",") != "auth" {
				t.Fatal("wrong raw identity reached proof")
			}
		})
	}
}
func TestOwnerAdapterASKLedgerReplySenderPostACK(t *testing.T) {
	senderProfile, responderProfile := ownerAdapterProfile("sender"), ownerAdapterProfile("responder")
	project := uuid.NewString()
	senderRaw := newOwnerAdapterEndpoint(senderProfile, responderProfile.Service, responderProfile.Registration.InstallationID, project)
	responderRaw := newOwnerAdapterEndpoint(responderProfile, senderProfile.Service, senderProfile.Registration.InstallationID, project)
	senderAdapter, responderAdapter := ownerAdapterForTest(t, senderProfile, senderRaw), ownerAdapterForTest(t, responderProfile, responderRaw)
	senderStore, err := sender.Open(filepath.Join(t.TempDir(), "operations"), senderProfile.SenderBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer senderStore.Close()
	ledgerStore, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"), responderProfile.LedgerBinding(), ledger.Limits{CallsPerDay: 2, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ledgerStore.Close()
	provider := &fakeProvider{}
	bridge := New(ledgerStore, responderAdapter, provider, Config{ProviderConfigFingerprint: "fixed", DeferMessageWake: true, Enabled: responderAdapter.Ready})
	responderAdapter.OnSharingProjectMessage(bridge.HandleMessage)
	responderAdapter.OnSharingProjectReady(func(string) { bridge.Wake() })
	senderAdapter.OnSharingProjectMessage(func(ctx context.Context, m sdk.SharingProjectMessage) error {
		_, err := sender.RecordReply(ctx, senderStore, senderProfile.Service, m)
		return err
	})
	operation, err := senderStore.Reserve(context.Background(), project, responderProfile.Service, "question")
	if err != nil {
		t.Fatal(err)
	}
	operation, err = sender.Reconcile(context.Background(), senderAdapter, senderStore, operation)
	if err != nil || operation.Phase != sender.Admitted {
		t.Fatalf("ASK admission: %v", err)
	}
	ask := senderRaw.prepared[operation.AskID]
	askHeader := senderRaw.headers[operation.AskID]
	if err = responderRaw.ownerMessage(context.Background(), sdk.OwnerTextProjectMessage{Header: askHeader, Plaintext: []byte("question"), Wire: ask.Wire}); err != nil {
		t.Fatal(err)
	}
	job, err := ledgerStore.Get(context.Background(), project, operation.AskID)
	if err != nil || !bytes.Equal(job.Data.PredecessorWire, ask.Wire) || job.Data.WireDigest != digest(ask.Wire) || len(bridge.wake) != 0 {
		t.Fatal("ASK not durably stored before ACK or eager wake")
	}
	if err = bridge.process(context.Background(), job); err != nil || provider.calls != 0 {
		t.Fatal("provider dispatched before ASK ACK")
	}
	askACKed := false
	responderRaw.beforeSend = func(string) error {
		if !askACKed {
			return &sdk.OwnerTextProjectMessageQuotaError{Limit: "maxInFlight", Maximum: 1, StatusCode: 429}
		}
		return nil
	}
	askACKed = true
	responderRaw.ownerReady(project)
	if err = bridge.process(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	job, err = ledgerStore.Get(context.Background(), project, operation.AskID)
	if err != nil || job.Phase != ledger.Admitted || provider.calls != 1 {
		t.Fatalf("REPLY ledger: %+v %v", job, err)
	}
	reply := responderRaw.prepared[job.Data.ReplyID]
	if err = senderRaw.ownerMessage(context.Background(), sdk.OwnerTextProjectMessage{Header: responderRaw.headers[job.Data.ReplyID], Plaintext: []byte("answer"), Wire: reply.Wire}); err != nil {
		t.Fatal(err)
	}
	operation, err = senderStore.Get(context.Background(), project, operation.AskID)
	if err != nil || operation.Reply == nil || operation.Reply.Text != "answer" {
		t.Fatal("sender reply not committed before callback ACK")
	}
}
func TestOwnerResponderRuntimeEnrollmentBeforeRun(t *testing.T) {
	_, dir, p := savedTestProfile(t)
	p.ProjectContract = OwnerTextProjectContract
	p.Role = "responder"
	registration := ownerAdapterProfile("responder").Registration
	p.Registration = registration
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"), p.LedgerBinding(), p.Limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f := newOwnerAdapterEndpoint(p, uuid.NewString(), uuid.NewString(), uuid.NewString())
	f.enrollErr = errors.New("enrollment rejected")
	err = RunProfile(context.Background(), dir, p, store, RuntimeConfig{Connect: func(context.Context, sdk.Config) (RuntimeConnection, error) { return f, nil }, NewProvider: func(provider.Config) (Provider, error) { return &fakeProvider{}, nil }, Authorize: func(context.Context, RuntimeConnection) error { f.proof = true; return nil }, Enabled: func(string) bool { return true }})
	if err == nil || f.ownerMessage == nil || f.ownerReady == nil || f.message != nil || f.ready != nil {
		t.Fatal("owner responder startup order/contract failure")
	}
}

func TestOwnerAdapterLegacySelectionDoesNotCallOwnerAPIs(t *testing.T) {
	for _, contract := range []string{"", SharingProjectContract} {
		raw := &runtimeConnection{}
		adapter, err := selectOwnerProjectAdapter(context.Background(), raw, Profile{ProjectContract: contract}, nil, "", nil)
		if err != nil || adapter != nil {
			t.Fatal("legacy profile selected owner adapter")
		}
	}
}
