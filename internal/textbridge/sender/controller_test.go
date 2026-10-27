package sender

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/sdk"
)

type controllerEndpoint struct {
	Connection
	mu                        sync.Mutex
	wires                     map[string]sdk.PreparedSharingProjectMessage
	receipts                  map[string]sdk.SharingProjectMessageReceipt
	prepares, sends, statuses int
	uncertain                 bool
	ready                     func(string)
	message                   func(context.Context, sdk.SharingProjectMessage) error
	started                   chan struct{}
	sent                      chan string
}

func newControllerEndpoint() *controllerEndpoint {
	return &controllerEndpoint{wires: map[string]sdk.PreparedSharingProjectMessage{}, receipts: map[string]sdk.SharingProjectMessageReceipt{}, started: make(chan struct{}), sent: make(chan string, 10)}
}
func (f *controllerEndpoint) WhoAmI(context.Context) (*sdk.Identity, error) {
	return &sdk.Identity{Kind: "service", PrincipalID: binding().PrincipalID}, nil
}
func (f *controllerEndpoint) SharingProjectStatus(context.Context, string) (sdk.SharingProjectStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses++
	return sdk.SharingProjectStatus{ProjectID: project, State: "active", EndpointProved: true}, nil
}
func (f *controllerEndpoint) PrepareSharingProjectMessageWithID(_, _, _, id string, _, _ []byte) (sdk.PreparedSharingProjectMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepares++
	p := sdk.PreparedSharingProjectMessage{ID: id, Wire: []byte("ciphertext:" + id)}
	f.wires[id] = p
	return p, nil
}
func (f *controllerEndpoint) LoadPreparedSharingProjectMessage(_, id string) (sdk.PreparedSharingProjectMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.wires[id]; ok {
		return p, nil
	}
	return sdk.PreparedSharingProjectMessage{}, os.ErrNotExist
}
func (f *controllerEndpoint) SharingProjectMessageReceipt(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.receipts[id]; ok {
		return r, nil
	}
	return sdk.SharingProjectMessageReceipt{}, os.ErrNotExist
}
func (f *controllerEndpoint) SendPreparedSharingProjectMessage(_ context.Context, _, id string) (sdk.SharingProjectMessageReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	f.sent <- id
	if f.uncertain {
		return sdk.SharingProjectMessageReceipt{}, errors.New("uncertain admission")
	}
	sum := sha256.Sum256(f.wires[id].Wire)
	r := sdk.SharingProjectMessageReceipt{MessageID: id, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	f.receipts[id] = r
	return r, nil
}
func (f *controllerEndpoint) OnSharingProjectMessage(h func(context.Context, sdk.SharingProjectMessage) error) {
	f.message = h
}
func (f *controllerEndpoint) OnSharingProjectReady(h func(string)) { f.ready = h }
func (f *controllerEndpoint) EnableSharingProjects()               { f.ready(project); close(f.started) }
func (f *controllerEndpoint) Done() <-chan struct{}                { return nil }
func controllerAwait(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case id := <-ch:
		return id
	case <-time.After(time.Second):
		t.Fatal("controller did not send")
		return ""
	}
}

func TestControllerMultiplexesStartupAndReserveWithoutPolling(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := newControllerEndpoint()
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return true }})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	if id := controllerAwait(t, f.sent); id != o.AskID {
		t.Fatal("startup recovery changed identity")
	}
	added, err := c.Reserve(ctx, project, recipient, "new prompt")
	if err != nil {
		t.Fatal(err)
	}
	if id := controllerAwait(t, f.sent); id != added.AskID {
		t.Fatal("reserve wake lost")
	}
	if err := c.Run(ctx); err == nil {
		t.Fatal("duplicate controller runtime")
	}
	r := replyFor(o)
	if err := f.message(ctx, sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: project, ID: r.ReplyID, ThreadID: o.AskID, CorrelationID: &o.AskID, SenderPrincipalID: recipient, RecipientPrincipalID: binding().PrincipalID}, Plaintext: []byte("answer"), Wire: []byte("reply wire")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, project, o.AskID)
	if err != nil || got.Reply == nil {
		t.Fatalf("reply not durable before ACK: %+v %v", got, err)
	}
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepares != 2 || f.sends != 2 || f.statuses != 2 {
		t.Fatalf("duplicate work or idle polling: prepare=%d send=%d status=%d", f.prepares, f.sends, f.statuses)
	}
}

func TestControllerReconnectReusesAmbiguousASK(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := newControllerEndpoint()
	f.uncertain = true
	errorsSeen := make(chan error, 1)
	config := ControllerConfig{Enabled: func(string) bool { return true }, OnError: func(err error) { errorsSeen <- err }}
	c := NewController(s, f, binding().PrincipalID, config)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	controllerAwait(t, f.sent)
	select {
	case <-errorsSeen:
	case <-time.After(time.Second):
		t.Fatal("ambiguous outcome not reported")
	}
	cancel()
	<-done
	f.mu.Lock()
	wire := f.wires[o.AskID]
	f.mu.Unlock()
	next := newControllerEndpoint()
	next.wires[o.AskID] = wire
	resumed := NewController(s, next, binding().PrincipalID, config)
	runCtx, cancel = context.WithCancel(ctx)
	go func() { done <- resumed.Run(runCtx) }()
	if id := controllerAwait(t, next.sent); id != o.AskID {
		t.Fatal("reconnect replaced ASK")
	}
	cancel()
	<-done
	next.mu.Lock()
	defer next.mu.Unlock()
	if next.prepares != 0 || string(next.wires[o.AskID].Wire) != string(wire.Wire) {
		t.Fatal("reconnect regenerated ciphertext")
	}
}

func TestControllerAndStoreDisableFenceDispatch(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	var enabled atomic.Bool
	enabled.Store(false)
	f := newControllerEndpoint()
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return enabled.Load() }})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	<-f.started
	if _, err := c.Reserve(ctx, project, recipient, "blocked"); !errors.Is(err, ErrDisabled) {
		t.Fatal("closed gate reserved work", err)
	}
	if err := s.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	enabled.Store(true)
	c.Wake()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	f.mu.Lock()
	if f.prepares != 0 || f.sends != 0 {
		t.Fatal("disabled sender dispatched")
	}
	f.mu.Unlock()
	s.Close()
	reopened, err := Open(dir, binding())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Reserve(ctx, project, recipient, "blocked"); !errors.Is(err, ErrDisabled) {
		t.Fatal("disable did not survive reopen", err)
	}
	if _, err := Reconcile(ctx, f, reopened, o); !errors.Is(err, ErrDisabled) {
		t.Fatal("standalone engine bypassed disable", err)
	}
}
