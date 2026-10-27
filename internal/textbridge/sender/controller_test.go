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
	sendErr                   error
	uncertain                 bool
	ready                     func(string)
	message                   func(context.Context, sdk.SharingProjectMessage) error
	started                   chan struct{}
	done                      chan struct{}
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
	if f.sendErr != nil {
		return sdk.SharingProjectMessageReceipt{}, f.sendErr
	}
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
func (f *controllerEndpoint) Done() <-chan struct{}                { return f.done }
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

func TestControllerRetriesTransientAdmissionWithoutWake(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := newControllerEndpoint()
	f.uncertain = true
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return true }})
	c.retryDelay = time.Millisecond
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	if id := controllerAwait(t, f.sent); id != o.AskID {
		t.Fatal("changed ASK")
	}
	f.mu.Lock()
	wire := string(f.wires[o.AskID].Wire)
	f.uncertain = false
	f.mu.Unlock()
	if id := controllerAwait(t, f.sent); id != o.AskID {
		t.Fatal("retry replaced ASK")
	}
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepares != 1 || f.sends != 2 || string(f.wires[o.AskID].Wire) != wire {
		t.Fatal("retry regenerated ciphertext or polled after admission")
	}
	got, err := s.Get(ctx, project, o.AskID)
	if err != nil || got.Phase != Admitted {
		t.Fatalf("transient admission unresolved: %+v %v", got, err)
	}
}

type receiptFailureEndpoint struct {
	*controllerEndpoint
	calls atomic.Int32
}

func (f *receiptFailureEndpoint) SharingProjectMessageReceipt(ctx context.Context, project, id string) (sdk.SharingProjectMessageReceipt, error) {
	if f.calls.Add(1) <= 2 {
		return sdk.SharingProjectMessageReceipt{}, errors.New("temporary receipt read failure")
	}
	return f.controllerEndpoint.SharingProjectMessageReceipt(ctx, project, id)
}

// Receipt evidence must recover before project readiness, even after the SDK
// retired ciphertext. Successful recovery leaves no outstanding retry timer.
func (f *receiptFailureEndpoint) EnableSharingProjects() { close(f.started) }
func TestControllerRetriesTransientReceiptWithoutReadiness(t *testing.T) {
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
	f := &receiptFailureEndpoint{controllerEndpoint: newControllerEndpoint()}
	f.receipts[o.AskID] = sdk.SharingProjectMessageReceipt{MessageID: o.AskID, RequestDigest: sum[:], AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return true }})
	c.retryDelay = time.Millisecond
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(time.Second)
	for f.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if f.calls.Load() != 3 {
		t.Fatal("receipt recovery lost bounded retry or polled while idle", f.calls.Load())
	}
	got, err := s.Get(ctx, project, o.AskID)
	if err != nil || got.Phase != Admitted {
		t.Fatalf("receipt recovery: %+v %v", got, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepares != 0 || f.sends != 0 {
		t.Fatal("receipt retry prepared or resent retired ciphertext")
	}
}

func TestControllerRetriesLongOutageAndStopsForAmbiguousPreparation(t *testing.T) {
	for _, preparing := range []bool{false, true} {
		t.Run(map[bool]string{false: "outage beyond five attempts", true: "missing ciphertext"}[preparing], func(t *testing.T) {
			s, _ := openTest(t)
			defer s.Close()
			o := reserveTest(t, s)
			if preparing {
				if _, err := s.MarkPreparing(ctx, project, o.AskID); err != nil {
					t.Fatal(err)
				}
			}
			f := newControllerEndpoint()
			f.uncertain = true
			c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return true }})
			c.retryDelay, c.retryMaxDelay = time.Millisecond, 2*time.Millisecond
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- c.Run(runCtx) }()
			defer func() { cancel(); <-done }()
			if preparing {
				<-f.started
				time.Sleep(60 * time.Millisecond)
			} else {
				for range 7 {
					if id := controllerAwait(t, f.sent); id != o.AskID {
						t.Fatal("retry changed ASK")
					}
				}
				f.mu.Lock()
				f.uncertain = false
				f.mu.Unlock()
				if id := controllerAwait(t, f.sent); id != o.AskID {
					t.Fatal("recovery changed ASK")
				}
				time.Sleep(50 * time.Millisecond)
			}
			f.mu.Lock()
			sends, prepares, statuses := f.sends, f.prepares, f.statuses
			f.mu.Unlock()
			if preparing {
				if sends != 0 || prepares != 0 || statuses != 1 {
					t.Fatal("ambiguous preparation retried or regenerated", sends, prepares, statuses)
				}
			} else if sends != 8 || prepares != 1 {
				t.Fatal("long outage recovery stopped or polled after admission", sends, prepares)
			}
		})
	}
}

func TestControllerStopsRetryOnDisableOrTerminalAdmission(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "terminal credential"}[terminal], func(t *testing.T) {
			s, _ := openTest(t)
			defer s.Close()
			reserveTest(t, s)
			f := newControllerEndpoint()
			f.uncertain = true
			if terminal {
				f.sendErr = sdk.ErrCredentialDead
			}
			var enabled atomic.Bool
			enabled.Store(true)
			c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return enabled.Load() }})
			c.retryDelay, c.retryMaxDelay = time.Millisecond, 2*time.Millisecond
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- c.Run(runCtx) }()
			defer func() { cancel(); <-done }()
			controllerAwait(t, f.sent)
			if !terminal {
				enabled.Store(false)
			}
			time.Sleep(60 * time.Millisecond)
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.sends != 1 || f.prepares != 1 {
				t.Fatal("disabled or terminal sender kept retrying", f.sends, f.prepares)
			}
		})
	}
}

func TestControllerWaitReplyAndShutdownCleanup(t *testing.T) {
	for _, reply := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "reply"}[reply], func(t *testing.T) {
			s, _ := openTest(t)
			defer s.Close()
			o := reserveTest(t, s)
			f := newControllerEndpoint()
			waitResult := make(chan error, 1)
			cleanupDone := make(chan struct{})
			c := NewController(s, f, binding().PrincipalID, ControllerConfig{
				Enabled: func(string) bool { return true },
				OnReady: func(c *Controller) func() {
					go func() {
						got, err := c.Wait(ctx, project, o.AskID)
						if err == nil && (got.Phase != Admitted || got.Reply == nil) {
							err = errors.New("incomplete wait result")
						}
						waitResult <- err
					}()
					return func() { <-cleanupDone }
				},
			})
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- c.Run(runCtx) }()
			controllerAwait(t, f.sent)
			if reply {
				r := replyFor(o)
				err := f.message(ctx, sdk.SharingProjectMessage{Header: sdk.SharingProjectMessageHeader{Kind: "REPLY", ProjectID: project, ID: r.ReplyID, ThreadID: o.AskID, CorrelationID: &o.AskID, SenderPrincipalID: recipient, RecipientPrincipalID: binding().PrincipalID}, Plaintext: []byte("answer"), Wire: []byte("reply wire")})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-waitResult:
				if reply && err != nil || !reply && !errors.Is(err, ErrDisabled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("wait missed change or blocked cleanup")
			}
			close(cleanupDone)
			cancel()
			<-done
			if _, err := c.Get(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
				t.Fatal("stopped controller read store", err)
			}
		})
	}
}

func TestControllerSuppliedIDAndReadGates(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	f := newControllerEndpoint()
	var enabled atomic.Bool
	enabled.Store(true)
	published := make(chan *Controller, 1)
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return enabled.Load() }, OnReady: func(c *Controller) func() { published <- c; return nil }})
	o := reserveTest(t, s)
	if _, err := c.Get(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	<-published
	repeated, err := c.ReserveWithID(ctx, project, recipient, o.AskID, "sensitive prompt 🦊")
	if err != nil || repeated.AskID != o.AskID {
		t.Fatal(repeated, err)
	}
	if _, err := c.Resume(ctx, project, "019abcdef000-7000-8000-000000000000"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := c.Resume(ctx, project, "019abcde-f000-7000-8000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatal("resume created missing operation", err)
	}
	enabled.Store(false)
	if _, err := c.Get(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := c.Wait(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := c.ReserveWithID(ctx, project, recipient, o.AskID, "sensitive prompt 🦊"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	enabled.Store(true)
	if err := s.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReserveWithID(ctx, project, recipient, o.AskID, "sensitive prompt 🦊"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
}

func TestControllerWaitCancellationAndConnectionGate(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	o := reserveTest(t, s)
	f := newControllerEndpoint()
	f.done = make(chan struct{})
	published := make(chan struct{})
	c := NewController(s, f, binding().PrincipalID, ControllerConfig{Enabled: func(string) bool { return true }, OnReady: func(*Controller) func() { close(published); return nil }})
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	<-published
	waitCtx, stopWait := context.WithCancel(ctx)
	stopWait()
	if _, err := c.Wait(waitCtx, project, o.AskID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(f.done)
	if _, err := c.Get(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
		t.Fatal("ended connection retained read authority", err)
	}
	if _, err := c.Wait(ctx, project, o.AskID); !errors.Is(err, ErrDisabled) {
		t.Fatal("ended connection retained wait authority", err)
	}
}
