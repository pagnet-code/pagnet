package sender

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/sdk"
)

type engineConnection struct {
	t                         *testing.T
	store                     *Store
	operation                 Operation
	prepared                  sdk.PreparedSharingProjectMessage
	receipt                   *sdk.SharingProjectMessageReceipt
	prepareErr, sendErr       error
	prepares, sends, statuses int
	handler                   func(context.Context, sdk.SharingProjectMessage) error
	ready                     func(string)
	deliverOnEnable           bool
}

func (f *engineConnection) WhoAmI(context.Context) (*sdk.Identity, error) {
	return &sdk.Identity{Kind: "service", PrincipalID: binding().PrincipalID}, nil
}
func (f *engineConnection) SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error) {
	f.statuses++
	return sdk.SharingProjectStatus{ProjectID: project, State: "active", EndpointProved: true}, nil
}
func (f *engineConnection) PrepareSharingProjectMessageWithID(p, to, kind, id string, input, predecessor []byte) (sdk.PreparedSharingProjectMessage, error) {
	f.prepares++
	o, err := f.store.Get(ctx, p, id)
	if err != nil || o.Phase != Preparing || id != f.operation.AskID || to != recipient || kind != "ASK" || string(input) != "sensitive prompt 🦊" || len(predecessor) != 0 {
		f.t.Fatalf("preparation without durable identity and prompt: %+v %v", o, err)
	}
	if f.prepareErr != nil {
		return sdk.PreparedSharingProjectMessage{}, f.prepareErr
	}
	f.prepared = preparedFor(o)
	return f.prepared, nil
}
func (f *engineConnection) LoadPreparedSharingProjectMessage(p, id string) (sdk.PreparedSharingProjectMessage, error) {
	if p != project || id != f.prepared.ID || len(f.prepared.Wire) == 0 {
		return sdk.PreparedSharingProjectMessage{}, os.ErrNotExist
	}
	return f.prepared, nil
}
func (f *engineConnection) SharingProjectMessageReceipt(context.Context, string, string) (sdk.SharingProjectMessageReceipt, error) {
	if f.receipt == nil {
		return sdk.SharingProjectMessageReceipt{}, os.ErrNotExist
	}
	return *f.receipt, nil
}
func (f *engineConnection) SendPreparedSharingProjectMessage(_ context.Context, p, id string) (sdk.SharingProjectMessageReceipt, error) {
	f.sends++
	if p != project || id != f.operation.AskID || id != f.prepared.ID {
		f.t.Fatal("changed ASK identity")
	}
	if f.sendErr != nil {
		return sdk.SharingProjectMessageReceipt{}, f.sendErr
	}
	sum := sha256.Sum256(f.prepared.Wire)
	f.receipt = &sdk.SharingProjectMessageReceipt{MessageID: id, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	if f.handler != nil {
		f.deliver()
	}
	return *f.receipt, nil
}
func (f *engineConnection) OnSharingProjectMessage(h func(context.Context, sdk.SharingProjectMessage) error) {
	f.handler = h
}
func (f *engineConnection) OnSharingProjectReady(h func(string)) { f.ready = h }
func (f *engineConnection) EnableSharingProjects() {
	f.ready(project)
	if f.deliverOnEnable {
		f.deliver()
	}
}
func (f *engineConnection) Done() <-chan struct{} { return nil }
func (f *engineConnection) deliver() {
	r := replyFor(f.operation)
	m := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: project, ID: r.ReplyID, ThreadID: r.AskID, CorrelationID: &r.AskID, SenderPrincipalID: recipient, RecipientPrincipalID: binding().PrincipalID}, Plaintext: []byte(r.Text), Wire: []byte("reply wire")}
	if err := f.handler(ctx, m); err != nil {
		f.t.Fatal(err)
	}
	o, err := f.store.Get(ctx, project, r.AskID)
	if err != nil || o.Reply == nil || o.Reply.Text != r.Text {
		f.t.Fatalf("ACK before durable reply: %+v %v", o, err)
	}
}

func TestEngineRunPersistsBeforePrepareAndACK(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := &engineConnection{t: t, store: s, operation: o}
	runCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	got, err := Run(runCtx, f, s, binding().PrincipalID, o)
	if err != nil || got.AskID != o.AskID || got.Phase != Admitted || got.Reply == nil || f.prepares != 1 || f.sends != 1 {
		t.Fatalf("run: %+v %v prepares=%d sends=%d", got, err, f.prepares, f.sends)
	}
}

func TestEngineReconcilePreparingRequiresCiphertext(t *testing.T) {
	for _, spooled := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "spooled"}[spooled], func(t *testing.T) {
			s, _ := openTest(t)
			defer s.Close()
			o := reserveTest(t, s)
			o, err := s.MarkPreparing(ctx, project, o.AskID)
			if err != nil {
				t.Fatal(err)
			}
			f := &engineConnection{t: t, store: s, operation: o}
			if spooled {
				f.prepared = preparedFor(o)
			}
			got, err := Reconcile(ctx, f, s, o)
			if f.prepares != 0 {
				t.Fatal("reprepared ambiguous ASK")
			}
			if spooled {
				if err != nil || got.Phase != Admitted || f.sends != 1 {
					t.Fatalf("recovery: %+v %v", got, err)
				}
			} else if err == nil || got.Phase != Preparing || f.sends != 0 {
				t.Fatalf("lost unresolved state: %+v %v", got, err)
			}
		})
	}
}

func TestEngineReconcileRetriesSameCiphertext(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := &engineConnection{t: t, store: s, operation: o, sendErr: errors.New("uncertain admission")}
	got, err := Reconcile(ctx, f, s, o)
	if err == nil || got.Phase != Prepared {
		t.Fatalf("uncertain admission: %+v %v", got, err)
	}
	wire := string(f.prepared.Wire)
	f.sendErr = nil
	got, err = Reconcile(ctx, f, s, got)
	if err != nil || got.Phase != Admitted || got.AskID != o.AskID || string(f.prepared.Wire) != wire || f.prepares != 1 || f.sends != 2 {
		t.Fatalf("retry: %+v %v prepares=%d sends=%d", got, err, f.prepares, f.sends)
	}
}

func TestEngineRunRecoversReceiptWithoutCiphertextOrAuthority(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	o, err := s.MarkPreparing(ctx, project, o.AskID)
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedFor(o)
	o, err = s.MarkPrepared(ctx, project, o.AskID, prepared)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(prepared.Wire)
	receipt := &sdk.SharingProjectMessageReceipt{MessageID: o.AskID, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	f := &engineConnection{t: t, store: s, operation: o, receipt: receipt, deliverOnEnable: true}
	runCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	got, err := Run(runCtx, f, s, binding().PrincipalID, o)
	if err != nil || got.Reply == nil || f.prepares != 0 || f.sends != 0 || f.statuses != 0 {
		t.Fatalf("receipt recovery: %+v %v", got, err)
	}
}

func TestEngineRecordReplyRequiresAuthenticatedCorrelation(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	r := replyFor(o)
	valid := sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: project, ID: r.ReplyID, ThreadID: o.AskID, CorrelationID: &o.AskID, SenderPrincipalID: recipient, RecipientPrincipalID: binding().PrincipalID}, Plaintext: []byte("answer"), Wire: []byte("reply wire")}
	for _, change := range []func(*sdk.SharingProjectMessage){
		func(m *sdk.SharingProjectMessage) { m.Header.CorrelationID = nil },
		func(m *sdk.SharingProjectMessage) { m.Header.ThreadID = r.ReplyID },
		func(m *sdk.SharingProjectMessage) { m.Header.SenderPrincipalID = binding().PrincipalID },
		func(m *sdk.SharingProjectMessage) { m.Header.RecipientPrincipalID = recipient },
		func(m *sdk.SharingProjectMessage) { m.Header.ProjectID = recipient },
		func(m *sdk.SharingProjectMessage) { m.Wire = nil },
	} {
		bad := valid
		change(&bad)
		if _, err := RecordReply(ctx, s, binding().PrincipalID, bad); err == nil {
			t.Fatal("accepted mismatched reply")
		}
	}
	got, err := s.Get(ctx, project, o.AskID)
	if err != nil || got.Reply != nil {
		t.Fatalf("persisted rejected reply: %+v %v", got, err)
	}
	if _, err := RecordReply(ctx, s, binding().PrincipalID, valid); err != nil {
		t.Fatal(err)
	}
}
