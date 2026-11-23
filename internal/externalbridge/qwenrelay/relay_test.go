package qwenrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/externalbridge/inbox"
	"github.com/pagnet-code/pagnet/internal/runtimeconnect"
	"github.com/pagnet-code/pagnet/sdk"
)

type fakeInbox struct {
	mu      sync.Mutex
	m       *sdk.Message
	done    bool
	scans   int
	wake    chan struct{}
	markErr error
}

func (f *fakeInbox) PendingIDs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scans++
	if f.done {
		return nil, nil
	}
	return []string{f.m.ID}, nil
}
func (f *fakeInbox) GetSaved(string) (*sdk.Message, error) { return f.m, nil }
func (f *fakeInbox) Notifications() <-chan struct{}        { return f.wake }
func (f *fakeInbox) MarkReplied(string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	f.done = true
	return nil
}

type fakeStore struct {
	data map[inbox.Key][]byte
	fail string
}

func (f *fakeStore) Get(k inbox.Key) ([]byte, error) {
	v, ok := f.data[k]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(v), nil
}
func (f *fakeStore) Put(k inbox.Key, b []byte) (bool, error) {
	if strings.HasPrefix(k.MessageID, f.fail) && f.fail != "" {
		return false, errors.New("simulated persistence failure")
	}
	if old, ok := f.data[k]; ok {
		if !bytes.Equal(old, b) {
			return false, inbox.ErrConflict
		}
		return false, nil
	}
	f.data[k] = bytes.Clone(b)
	return true, nil
}

type fakeQwen struct {
	admissions, resumes       int
	receipt                   runtimeconnect.PromptResult
	admitErr, resumeErr       error
	terminalError             bool
	text                      string
	beforeAdmit, beforeResume func()
}

func (f *fakeQwen) AdmitPrompt(_ context.Context, _, text string) (runtimeconnect.PromptResult, error) {
	f.admissions++
	f.text = text
	if f.beforeAdmit != nil {
		f.beforeAdmit()
	}
	return f.receipt, f.admitErr
}
func (f *fakeQwen) ResumePrompt(_ context.Context, receipt runtimeconnect.PromptResult) (runtimeconnect.PromptResult, error) {
	f.resumes++
	if f.beforeResume != nil {
		f.beforeResume()
	}
	if receipt.PromptID != "prompt" {
		panic("wrong saved receipt")
	}
	if f.resumeErr != nil {
		if f.terminalError {
			receipt.Uncertain = false
		}
		return receipt, f.resumeErr
	}
	receipt.Uncertain = false
	receipt.ResultText = "answer"
	return receipt, nil
}

type fakeReplies struct {
	calls      int
	err        error
	beforeSend func()
}

func (f *fakeReplies) SendDurableReply(_ context.Context, _ *sdk.Message, text string) (string, error) {
	f.calls++
	if text != "answer" {
		panic("different reply content")
	}
	if f.beforeSend != nil {
		f.beforeSend()
	}
	return "stable-reply-id", f.err
}

func fixture(t *testing.T) (*Relay, *fakeInbox, *fakeStore, *fakeQwen, *fakeReplies) {
	t.Helper()
	f := &fakeInbox{m: &sdk.Message{ID: "ask", NetworkID: "network", RecipientPrincipalID: "principal", Kind: "ASK", Parts: []sdk.MessagePart{domain.TextPart("untrusted ASK")}}, wake: make(chan struct{}, 1)}
	s := &fakeStore{data: map[inbox.Key][]byte{}}
	q := &fakeQwen{receipt: runtimeconnect.PromptResult{Accepted: true, Uncertain: true, PromptID: "prompt", LastEventID: 7, EventEpoch: "epoch"}}
	p := &fakeReplies{}
	r, err := New(f, s, q, p)
	if err != nil {
		t.Fatal(err)
	}
	return r, f, s, q, p
}

func scan(t *testing.T, r *Relay) {
	t.Helper()
	if err := r.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func save(t *testing.T, s *fakeStore, m *sdk.Message, stage string, value []byte) {
	t.Helper()
	if _, err := s.Put(key(m, stage), value); err != nil {
		t.Fatal(err)
	}
}
func savedReceipt(t *testing.T, s *fakeStore, m *sdk.Message, q *fakeQwen) {
	t.Helper()
	save(t, s, m, "started", []byte("started"))
	raw, err := json.Marshal(q.receipt)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, m, "accepted", raw)
}

func TestDurableOrderingAndDuplicateWake(t *testing.T) {
	r, f, s, q, p := fixture(t)
	q.beforeAdmit = func() {
		if _, err := s.Get(key(f.m, "started")); err != nil {
			t.Fatal("POST before started persisted")
		}
	}
	q.beforeResume = func() {
		if _, err := s.Get(key(f.m, "accepted")); err != nil {
			t.Fatal("observation before accepted persisted")
		}
	}
	p.beforeSend = func() {
		if _, err := s.Get(key(f.m, "result")); err != nil {
			t.Fatal("reply before result persisted")
		}
	}
	scan(t, r)
	scan(t, r)
	if q.admissions != 1 || q.resumes != 1 || p.calls != 1 || !f.done {
		t.Fatalf("calls: admit=%d resume=%d reply=%d done=%v", q.admissions, q.resumes, p.calls, f.done)
	}
	if q.text != "untrusted ASK" {
		t.Fatalf("unexpected native text: %q", q.text)
	}
	if r.Status(f.m.ID).State != "replied" {
		t.Fatal(r.Status(f.m.ID))
	}
}

func TestCrashRecoveryStages(t *testing.T) {
	for _, stage := range []string{"started", "accepted", "result", "replied"} {
		t.Run(stage, func(t *testing.T) {
			r, f, s, q, p := fixture(t)
			if stage == "started" {
				save(t, s, f.m, stage, []byte("started"))
			} else {
				savedReceipt(t, s, f.m, q)
			}
			if stage == "result" || stage == "replied" {
				save(t, s, f.m, "result", []byte("answer"))
			}
			if stage == "replied" {
				save(t, s, f.m, "replied", []byte("stable-reply-id"))
			}
			scan(t, r)
			if q.admissions != 0 {
				t.Fatal("reposted native prompt")
			}
			if stage == "started" {
				if p.calls != 0 || q.resumes != 0 || f.done || r.Status(f.m.ID).State != "admission-uncertain" {
					t.Fatal("started-only ASK was not held")
				}
			} else if stage == "accepted" && q.resumes != 1 {
				t.Fatal("accepted receipt not resumed")
			} else if stage != "accepted" && q.resumes != 0 {
				t.Fatal("completed native prompt observed again")
			}
			if stage == "replied" && p.calls != 0 {
				t.Fatal("confirmed reply sent again")
			}
		})
	}
}

func TestPersistenceFailureWindows(t *testing.T) {
	for _, stage := range []string{"started", "accepted", "result", "replied"} {
		t.Run(stage, func(t *testing.T) {
			r, f, s, q, p := fixture(t)
			s.fail = "native-" + stage + ":"
			scan(t, r)
			if f.done {
				t.Fatal("marked replied despite failed persistence")
			}
			if stage == "started" && q.admissions != 0 {
				t.Fatal("POST without durable started marker")
			}
			if stage == "accepted" && q.resumes != 0 {
				t.Fatal("observed without durable accepted receipt")
			}
			if stage == "result" && p.calls != 0 {
				t.Fatal("replied without durable result")
			}
			// Simulate reopening after the failed operation. The started marker
			// fences a second POST, including when the accepted write failed.
			s.fail = ""
			r, _ = New(f, s, q, p)
			scan(t, r)
			if q.admissions > 1 {
				t.Fatal("POST retried after crash")
			}
		})
	}
}

func TestUncertainAdmissionNeverResubmitted(t *testing.T) {
	r, f, _, q, p := fixture(t)
	q.receipt = runtimeconnect.PromptResult{Uncertain: true}
	q.admitErr = errors.New("connection lost")
	scan(t, r)
	scan(t, r)
	if q.admissions != 1 || q.resumes != 0 || p.calls != 0 || f.done {
		t.Fatal("uncertain admission retried or replied")
	}
}

func TestInterruptedObservationReplaysReceipt(t *testing.T) {
	r, f, s, q, p := fixture(t)
	q.resumeErr = errors.New("stream interrupted")
	scan(t, r)
	q.resumeErr = nil
	r, _ = New(f, s, q, p)
	scan(t, r)
	if q.admissions != 1 || q.resumes != 2 || p.calls != 1 {
		t.Fatal("restart did not resume saved receipt")
	}
}

type orderedInbox struct {
	*fakeInbox
	messages []*sdk.Message
}

func (f *orderedInbox) PendingIDs() ([]string, error) {
	var ids []string
	for _, m := range f.messages {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

func (f *orderedInbox) GetSaved(id string) (*sdk.Message, error) {
	for _, m := range f.messages {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, os.ErrNotExist
}

func TestExistingTurnBlocksNewAdmission(t *testing.T) {
	for _, stage := range []string{"started", "accepted"} {
		t.Run(stage, func(t *testing.T) {
			r, f, s, q, _ := fixture(t)
			fresh := *f.m
			fresh.ID = "fresh-ask-listed-first"
			r.inbox = &orderedInbox{fakeInbox: f, messages: []*sdk.Message{&fresh, f.m}}
			if stage == "accepted" {
				savedReceipt(t, s, f.m, q)
				q.resumeErr = errors.New("native turn still active")
			} else {
				save(t, s, f.m, "started", []byte("started"))
			}
			scan(t, r)
			if q.admissions != 0 {
				t.Fatal("new prompt bypassed an unresolved native turn")
			}
		})
	}
}

func TestEncryptedStoreRestart(t *testing.T) {
	r, f, _, q, p := fixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := inbox.Open(dir, inbox.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	r.store = s
	q.resumeErr = errors.New("stream interrupted")
	scan(t, r)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = inbox.Open(dir, inbox.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q.resumeErr = nil
	r, err = New(f, s, q, p)
	if err != nil {
		t.Fatal(err)
	}
	scan(t, r)
	if q.admissions != 1 || q.resumes != 2 || p.calls != 1 || !f.done {
		t.Fatal("encrypted store did not recover admission")
	}
}

func TestReplyUncertaintyAndMarkFailure(t *testing.T) {
	r, f, s, q, p := fixture(t)
	p.err = errors.New("reply timeout")
	scan(t, r)
	if f.done {
		t.Fatal("uncertain reply marked successful")
	}
	p.err = nil
	f.markErr = errors.New("mark persistence failed")
	scan(t, r)
	if f.done {
		t.Fatal("failed mark succeeded")
	}
	f.markErr = nil
	r, _ = New(f, s, q, p)
	scan(t, r)
	if q.admissions != 1 || q.resumes != 1 || p.calls != 2 || !f.done {
		t.Fatal("confirmed reply was resent after mark failure")
	}
}

func TestTextBoundsBeforeAdmission(t *testing.T) {
	for _, body := range []string{"", strings.Repeat("x", 65537), string([]byte{0xff})} {
		r, f, _, q, _ := fixture(t)
		f.m.Parts = []sdk.MessagePart{domain.TextPart(body)}
		scan(t, r)
		if q.admissions != 0 || r.Status(f.m.ID).State != "rejected" {
			t.Fatal("invalid text admitted")
		}
	}
}

func TestRunAutomaticallyResumesAcceptedTurn(t *testing.T) {
	r, f, _, q, p := fixture(t)
	r.retryMin, r.retryMax = time.Millisecond, 4*time.Millisecond
	q.resumeErr = errors.New("transient SSE loss")
	q.beforeResume = func() {
		if q.resumes == 2 {
			q.resumeErr = nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.beforeSend = cancel
	finished := make(chan error, 1)
	go func() { finished <- r.Run(ctx) }()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted turn did not resume without inbound notification")
	}
	if q.admissions != 1 || q.resumes != 2 || p.calls != 1 || !f.done {
		t.Fatal("automatic recovery repeated admission or failed to reply")
	}
}

func TestRunAutomaticallyRetriesSavedReply(t *testing.T) {
	r, f, _, q, p := fixture(t)
	r.retryMin, r.retryMax = time.Millisecond, 4*time.Millisecond
	p.err = errors.New("transient reply timeout")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.beforeSend = func() {
		if p.calls == 2 {
			p.err = nil
			cancel()
		}
	}
	finished := make(chan error, 1)
	go func() { finished <- r.Run(ctx) }()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("saved reply did not retry without inbound notification")
	}
	if q.admissions != 1 || q.resumes != 1 || p.calls != 2 || !f.done {
		t.Fatal("reply recovery repeated native work")
	}
}

func TestTerminalNativeErrorIsDurableAndNotRetried(t *testing.T) {
	r, f, s, q, p := fixture(t)
	q.resumeErr, q.terminalError = errors.New("native turn failed"), true
	pending, err := r.scanPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("terminal native error scheduled recovery")
	}
	r, _ = New(f, s, q, p)
	scan(t, r)
	if q.admissions != 1 || q.resumes != 1 || p.calls != 0 || r.Status(f.m.ID).State != "terminal-error" {
		t.Fatal("terminal native turn retried")
	}
}

func TestDefiniteNonAdmissionRequiresOperator(t *testing.T) {
	r, f, s, q, p := fixture(t)
	q.receipt = runtimeconnect.PromptResult{}
	q.admitErr = errors.New("queue full")
	pending, err := r.scanPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending || r.Status(f.m.ID).State != "not-admitted" {
		t.Fatal("definite non-admission misclassified")
	}
	r, _ = New(f, s, q, p)
	scan(t, r)
	if q.admissions != 1 || r.Status(f.m.ID).State != "not-admitted" {
		t.Fatal("non-admitted ASK automatically posted again")
	}
}

func TestDefiniteNonAdmissionDoesNotBlockQueuedASK(t *testing.T) {
	r, f, s, q, p := fixture(t)
	fresh := *f.m
	fresh.ID = "fresh"
	r.inbox = &orderedInbox{fakeInbox: f, messages: []*sdk.Message{f.m, &fresh}}
	accepted := q.receipt
	q.beforeAdmit = func() {
		if q.admissions == 1 {
			q.receipt = runtimeconnect.PromptResult{}
			q.admitErr = errors.New("queue full")
		} else {
			q.receipt, q.admitErr = accepted, nil
		}
	}
	scan(t, r)
	if q.admissions != 2 || q.resumes != 1 || p.calls != 1 || r.Status(f.m.ID).State != "not-admitted" || r.Status(fresh.ID).State != "replied" {
		t.Fatalf("admissions=%d resumes=%d replies=%d first=%+v second=%+v", q.admissions, q.resumes, p.calls, r.Status(f.m.ID), r.Status(fresh.ID))
	}
	r, _ = New(r.inbox, s, q, p)
	scan(t, r)
	if q.admissions != 2 || q.resumes != 1 || p.calls != 1 || r.Status(fresh.ID).State != "replied" {
		t.Fatal("restart retried rejected admission or completed queued ASK")
	}
}

func TestRunRecoversThenAdmitsQueuedASK(t *testing.T) {
	r, f, _, q, p := fixture(t)
	fresh := *f.m
	fresh.ID = "fresh"
	r.inbox = &orderedInbox{fakeInbox: f, messages: []*sdk.Message{f.m, &fresh}}
	r.retryMin, r.retryMax = time.Millisecond, 4*time.Millisecond
	q.resumeErr = errors.New("stream interrupted")
	q.beforeResume = func() {
		if q.resumes >= 2 {
			q.resumeErr = nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.beforeSend = func() {
		if p.calls == 2 {
			cancel()
		}
	}
	finished := make(chan error, 1)
	go func() { finished <- r.Run(ctx) }()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued ASK not admitted after native recovery")
	}
	if q.admissions != 2 || q.resumes != 3 || p.calls != 2 {
		t.Fatal("queued recovery failed or repeated POST for started ASK")
	}
}

func TestRunHasNoIdlePolling(t *testing.T) {
	r, f, _, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- r.Run(ctx) }()
	waitScans := func(want int) {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			f.mu.Lock()
			n := f.scans
			f.mu.Unlock()
			if n == want {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("scans=%d, want=%d", n, want)
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitScans(1)
	time.Sleep(30 * time.Millisecond)
	f.mu.Lock()
	n := f.scans
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("idle scans=%d", n)
	}
	f.wake <- struct{}{}
	waitScans(2)
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
