package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

func outboundInput() sharingOutboundInput {
	return sharingOutboundInput{OperationID: uuid.NewString(), GrantID: "grant", ExpectedGeneration: 1, Text: "private outbound text"}
}
func TestSharingOutboundConcurrentDedupeRestart(t *testing.T) {
	m, dir, binding, _ := mailboxFixture(t)
	ctx := context.Background()
	in := outboundInput()
	const n = 20
	ids := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() { defer wg.Done(); r, err := m.submitOutbound(ctx, in); ids <- r.MessageID; errs <- err }()
	}
	wg.Wait()
	close(ids)
	close(errs)
	var id string
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for current := range ids {
		if id != "" && id != current {
			t.Fatal("duplicate operation allocated multiple messages")
		}
		id = current
	}
	if parsed, err := uuid.Parse(id); err != nil || parsed.Version() != 7 {
		t.Fatal("message is not UUIDv7")
	}
	in.Text = "changed"
	if _, err := m.submitOutbound(ctx, in); err == nil {
		t.Fatal("changed input accepted")
	}
	m.db.Close()
	reopened, err := openSharingMailbox(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	r, err := reopened.outboundStatus(ctx, in.OperationID)
	if err != nil || r.MessageID != id || r.Phase != "queued" || r.Input.Text != "private outbound text" {
		t.Fatalf("restart status: %+v %v", r, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "inbound.sqlite"))
	if err != nil || bytes.Contains(raw, []byte(r.Input.Text)) {
		t.Fatal("journal contains plaintext")
	}
}
func TestSharingOutboundValidationTamperCapacity(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"operation", "generation", "utf8", "reply", "ciphertext", "message binding", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _, _ := mailboxFixture(t)
			in := outboundInput()
			switch kind {
			case "operation":
				in.OperationID = "not-uuid"
			case "generation":
				in.ExpectedGeneration = 0
			case "utf8":
				in.Text = string([]byte{255})
			case "reply":
				in.ReplyToID = "invalid"
			}
			r, err := m.submitOutbound(ctx, in)
			switch kind {
			case "operation", "generation", "utf8", "reply":
				if err == nil {
					t.Fatal("invalid input accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ciphertext":
				_, err = m.db.Exec("UPDATE outbound SET sealed=zeroblob(length(sealed))")
			case "message binding":
				_, err = m.db.Exec("UPDATE outbound SET message_id=?", uuid.NewString())
			case "capacity":
				_, err = m.db.Exec("WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<9999) INSERT INTO outbound SELECT 'op-'||n,'message-'||n,x'00' FROM ids")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = m.submitOutbound(ctx, outboundInput()); err == nil {
					t.Fatal("journal cap exceeded")
				}
				// Full capacity still allows an exact retry of an existing operation.
				if _, err = m.submitOutbound(ctx, in); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.outboundStatus(ctx, in.OperationID); err == nil {
				t.Fatal("tamper accepted")
			}
			if _, err = m.submitOutbound(ctx, r.Input); err == nil {
				t.Fatal("tampered duplicate accepted")
			}
		})
	}
}

type outboundFake struct {
	calls       atomic.Int32
	pair        sdk.SharingPairStatus
	prepareErr  error
	importReply sdk.SharingMessage
}

func (f *outboundFake) LookupSharingMessage(string) (sdk.SharingMessageLocalState, bool, error) {
	f.calls.Add(1)
	return sdk.SharingMessageLocalState{}, false, nil
}
func (*outboundFake) AbortPreparedSharingMessage(sdk.PreparedSharingMessage) error {
	panic("unexpected abort")
}
func (f *outboundFake) PrepareSharingMessage(_ context.Context, r sdk.SharingMessageRequest) (sdk.PreparedSharingMessage, error) {
	f.calls.Add(1)
	if r.MessageID == "" || r.ExpectedGeneration != 1 {
		panic("missing stable binding")
	}
	return sdk.PreparedSharingMessage{}, f.prepareErr
}
func (*outboundFake) SendPreparedSharingMessage(context.Context, sdk.PreparedSharingMessage) (sdk.SharingMessageReceipt, error) {
	panic("unexpected send")
}
func (f *outboundFake) ImportReceivedSharingMessage(context.Context, string, []byte) (sdk.SharingMessage, error) {
	f.calls.Add(1)
	return f.importReply, nil
}
func (f *outboundFake) ListSharingPairs(context.Context, string) ([]sdk.SharingPairStatus, string, error) {
	f.calls.Add(1)
	return []sdk.SharingPairStatus{f.pair}, "", nil
}
func (*outboundFake) OnSharingPairReady(func()) {}
func outboundFixture(t *testing.T) (*sharingOutboundWorker, *outboundFake, sharingOutboundRecord) {
	m, _, _, _ := mailboxFixture(t)
	w := newSharingOutboundWorker(m)
	f := &outboundFake{pair: sdk.SharingPairStatus{GrantID: "grant", Generation: 1, State: "active", IssuerPrincipalID: "service", RecipientPrincipalID: "peer", Limits: sdk.SharingPairLimits{MaxMessageWireBytes: 4096}}, prepareErr: errors.New("sensitive plaintext must not escape")}
	r, err := m.submitOutbound(context.Background(), outboundInput())
	if err != nil {
		t.Fatal(err)
	}
	return w, f, r
}
func TestSharingOutboundUncertainPrepareRetainsQueued(t *testing.T) {
	w, f, r := outboundFixture(t)
	if delay, err := w.advance(context.Background(), f, r); err == nil || delay != 0 || bytes.Contains([]byte(err.Error()), []byte("sensitive")) {
		t.Fatal("ambiguous prepare was not sanitized")
	}
	saved, err := w.mailbox.outboundStatus(context.Background(), r.Input.OperationID)
	if err != nil || saved.Phase != "queued" || saved.MessageID != r.MessageID {
		t.Fatal("ambiguous prepare lost stable intent")
	}
	// A daemon prepared phase whose SDK spool vanished must never prepare anew.
	r.Phase = "prepared"
	before := f.calls.Load()
	if _, err = w.advance(context.Background(), f, r); err == nil || f.calls.Load() != before+1 {
		t.Fatal("missing prepared spool was recreated")
	}
}
func TestSharingOutboundRevocationAndReplyBinding(t *testing.T) {
	for _, kind := range []string{"revoked", "generation", "limit", "reply"} {
		t.Run(kind, func(t *testing.T) {
			w, f, r := outboundFixture(t)
			switch kind {
			case "revoked":
				f.pair.State = "revoked"
			case "generation":
				f.pair.Generation++
			case "limit":
				f.pair.Limits.MaxMessageWireBytes = 1
			case "reply":
				in := outboundInput()
				in.ReplyToID = uuid.NewString()
				var err error
				r, err = w.mailbox.submitOutbound(context.Background(), in)
				if err != nil {
					t.Fatal(err)
				}
				record := sharingMailboxRecord{Message: sdk.SharingMessage{GrantID: "grant", Generation: 1, Message: sdk.Message{ID: r.Input.ReplyToID, RecipientPrincipalID: "service"}}, ReplyMaterial: []byte("authenticated material")}
				if err := w.mailbox.put(context.Background(), record); err != nil {
					t.Fatal(err)
				}
				f.importReply = sdk.SharingMessage{GrantID: "grant", Generation: 1, Message: sdk.Message{ID: r.Input.ReplyToID, SenderPrincipalID: "wrong peer", RecipientPrincipalID: "service"}}
			}
			if _, err := w.advance(context.Background(), f, r); err != nil {
				t.Fatal(err)
			}
			saved, err := w.mailbox.outboundStatus(context.Background(), r.Input.OperationID)
			if err != nil || saved.Phase != "failed" || saved.Receipt != nil {
				t.Fatalf("unsafe failure: %+v %v", saved, err)
			}
		})
	}
}
func TestSharingOutboundWorkerIdleAndRetry(t *testing.T) {
	w, f, r := outboundFixture(t)
	w.endpoint = f
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	if f.calls.Load() != 0 {
		t.Fatal("idle worker touched SDK")
	}
	if _, err := w.retry(ctx, r.Input.OperationID); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for f.calls.Load() < 4 {
		select {
		case <-deadline:
			t.Fatal("explicit retry did not wake worker")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(30 * time.Millisecond)
	before := f.calls.Load()
	time.Sleep(30 * time.Millisecond)
	if f.calls.Load() != before {
		t.Fatal("generic error caused idle polling")
	}
	cancel()
	<-done
}
func TestSharingOutboundQuotaBackoff(t *testing.T) {
	if delay, _ := outboundRetryDelay(&sdk.SharingMessageQuotaError{StatusCode: 429, RetryAfter: "2"}); delay != 2*time.Second {
		t.Fatal(delay)
	}
	if delay, _ := outboundRetryDelay(errors.New("retry-after: 2")); delay != 0 {
		t.Fatal("untyped quota caused retry")
	}
}

func TestSharingOutboundPreparedAndReceiptRestart(t *testing.T) {
	for _, phase := range []string{"prepared", "admitted", "acknowledged"} {
		t.Run(phase, func(t *testing.T) {
			m, dir, binding, _ := mailboxFixture(t)
			ctx := context.Background()
			r, err := m.submitOutbound(ctx, outboundInput())
			if err != nil {
				t.Fatal(err)
			}
			r.Phase = phase
			if phase != "prepared" {
				r.Receipt = &sdk.SharingMessageReceipt{MessageID: r.MessageID, RequestDigest: []byte("opaque wire digest"), Status: "pending"}
				if phase == "acknowledged" {
					now := time.Now().UTC()
					r.Receipt.Status = "acknowledged"
					r.Receipt.AcknowledgedAt = &now
				}
			}
			if err = m.saveOutbound(ctx, r); err != nil {
				t.Fatal(err)
			}
			m.db.Close()
			restarted, err := openSharingMailbox(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.db.Close()
			got, err := restarted.outboundStatus(ctx, r.Input.OperationID)
			if err != nil || got.Phase != phase || got.MessageID != r.MessageID || got.Digest != r.Digest {
				t.Fatalf("lost committed phase: %+v %v", got, err)
			}
			if phase != "prepared" && (got.Receipt == nil || got.Receipt.Status != r.Receipt.Status) {
				t.Fatal("lost observed receipt")
			}
		})
	}
}
func TestSharingOutboundPrepareSizeRejection(t *testing.T) {
	w, f, r := outboundFixture(t)
	f.prepareErr = &sdk.SharingMessageQuotaError{Limit: "maxMessageWireBytes", StatusCode: 413}
	if _, err := w.advance(context.Background(), f, r); err != nil {
		t.Fatal(err)
	}
	got, err := w.mailbox.outboundStatus(context.Background(), r.Input.OperationID)
	if err != nil || got.Phase != "failed" || got.Error != "text_exceeds_pair_limit" {
		t.Fatalf("size rejection: %+v %v", got, err)
	}
}

func (*outboundFake) PrincipalID() string                                              { return "service" }
func (*outboundFake) OnSharingMessage(func(context.Context, sdk.SharingMessage) error) {}
func (*outboundFake) Close() error                                                     { return nil }
func (*outboundFake) Done() <-chan struct{}                                            { return nil }

type blockingOutboundFake struct {
	*outboundFake
	started chan struct{}
	stopped chan struct{}
}

func (f *blockingOutboundFake) ListSharingPairs(ctx context.Context, _ string) ([]sdk.SharingPairStatus, string, error) {
	close(f.started)
	<-ctx.Done()
	close(f.stopped)
	return nil, "", ctx.Err()
}
func TestSharingOutboundEndpointRetirementDrainsAction(t *testing.T) {
	w, base, _ := outboundFixture(t)
	ep := &blockingOutboundFake{outboundFake: base, started: make(chan struct{}), stopped: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	w.setEndpoint(ep)
	select {
	case <-ep.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	w.setEndpoint(nil)
	select {
	case <-ep.stopped:
	default:
		t.Fatal("endpoint retired before journal action stopped")
	}
	cancel()
	<-done
}

func TestSharingOutboundConcurrentChangedOperation(t *testing.T) {
	m, _, _, _ := mailboxFixture(t)
	in := outboundInput()
	type result struct {
		record sharingOutboundRecord
		err    error
	}
	results := make(chan result, 20)
	start := make(chan struct{})
	for i := range 20 {
		go func(i int) {
			<-start
			candidate := in
			if i%2 == 1 {
				candidate.Text = "different exact input"
			}
			r, err := m.submitOutbound(context.Background(), candidate)
			results <- result{r, err}
		}(i)
	}
	close(start)
	var winner sharingOutboundRecord
	successes, conflicts := 0, 0
	for range 20 {
		got := <-results
		if got.err != nil {
			conflicts++
			continue
		}
		successes++
		if winner.MessageID != "" && (winner.MessageID != got.record.MessageID || winner.Input != got.record.Input) {
			t.Fatal("conflicting input shared an operation")
		}
		winner = got.record
	}
	if successes != 10 || conflicts != 10 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}
