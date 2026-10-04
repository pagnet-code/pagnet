package durable

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
)

type blockedPublisher struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
	fail    bool
}

func (p *blockedPublisher) Publish(ctx context.Context, e event.Event) (Receipt, error) {
	n := p.calls.Add(1)
	if n == 1 {
		close(p.entered)
		select {
		case <-p.release:
		case <-ctx.Done():
			return Receipt{}, ctx.Err()
		}
	}
	if p.fail {
		return Receipt{}, errors.New("private provider failure must not be logged")
	}
	return Receipt{ID: e.ID()}, nil
}
func waitUntil(t *testing.T, f func() bool) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for !f() {
		if time.Now().After(until) {
			t.Fatal("bounded fixture condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestIngressFiniteVolatileAdmissionDoesNotWaitForWriterAndAccountsFailure(t *testing.T) {
	p := &blockedPublisher{entered: make(chan struct{}), release: make(chan struct{}), fail: true}
	i, err := NewIngress(t.Context(), p, IngressConfig{QueueDepth: 1, MaxBytes: 128 << 10, MaxEventBytes: 65536, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close(t.Context())
	if i.TryPublish(t.Context(), fixtureEvent(t, "first")) != nil {
		t.Fatal("volatile admission")
	}
	<-p.entered
	accepted := make(chan error, 1)
	go func() { accepted <- i.TryPublish(t.Context(), fixtureEvent(t, "second")) }()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("invocation waited for durable writer")
	}
	if i.TryPublish(t.Context(), fixtureEvent(t, "overflow")) == nil {
		t.Fatal("finite volatile queue exceeded")
	}
	stats := i.Stats()
	if stats.VolatileAccepted != 2 || stats.DurableCommitted != 0 || stats.Pending != 2 || stats.Bytes <= 0 || stats.Rejected != 1 {
		t.Fatal("volatile acceptance mislabeled durable", stats)
	}
	close(p.release)
	waitUntil(t, func() bool { return i.Stats().WriteFailed == 2 })
	stats = i.Stats()
	if stats.Pending != 0 || stats.Bytes != 0 || stats.DurableCommitted != 0 {
		t.Fatal("failed writer leaked reservation", stats)
	}
	if err := i.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if i.TryPublish(t.Context(), fixtureEvent(t, "closed")) == nil {
		t.Fatal("closed ingress admitted event")
	}
}
func TestIngressDurableReceiptIsSeparateAndShutdownReleasesQueuedBytes(t *testing.T) {
	s, _, _, _ := fixtureStore(t, fixtureConfig())
	i, err := NewIngress(t.Context(), s, IngressConfig{QueueDepth: 2, MaxBytes: 1 << 20, MaxEventBytes: 65536, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e := fixtureEvent(t, "committed")
	if i.TryPublish(t.Context(), e) != nil {
		t.Fatal("volatile")
	}
	waitUntil(t, func() bool { return i.Stats().DurableCommitted == 1 })
	if r := requirePublish(t, s, e); !r.Duplicate {
		t.Fatal("writer metric not backed by genuine durable receipt")
	}
	if err := i.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	p := &blockedPublisher{entered: make(chan struct{}), release: make(chan struct{})}
	i, err = NewIngress(t.Context(), p, IngressConfig{QueueDepth: 2, MaxBytes: 1 << 20, MaxEventBytes: 65536, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if i.TryPublish(t.Context(), fixtureEvent(t, "inflight")) != nil {
		t.Fatal("volatile")
	}
	<-p.entered
	if i.TryPublish(t.Context(), fixtureEvent(t, "queued")) != nil {
		t.Fatal("queue")
	}
	if err := i.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	stats := i.Stats()
	if stats.Pending != 0 || stats.Bytes != 0 || stats.WriteFailed+stats.ShutdownDiscarded != 2 || stats.DurableCommitted != 0 {
		t.Fatal("shutdown hid lost volatile events", stats)
	}
}
func TestWorkerRetrySameOriginalAndPanicFailureIsFinite(t *testing.T) {
	c := fixtureConfig()
	c.MaxAttempts = 2
	s, _, _, _ := fixtureStore(t, c)
	e := fixtureEvent(t, "worker-original")
	requirePublish(t, s, e)
	var calls atomic.Int32
	observed := make(chan event.Event, 2)
	w, err := StartWorkers(t.Context(), s, WorkerConfig{Handlers: map[string]Handler{"fixture.observer": func(_ context.Context, got event.Event) error {
		observed <- got.Clone()
		if calls.Add(1) == 1 {
			got.SetID("mutated")
			got.DataEncoded[0] = 'x'
			return errors.New("private error")
		}
		return nil
	}}, Timeout: 50 * time.Millisecond, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return w.Stats().Delivered == 1 })
	if err := w.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, second := <-observed, <-observed
	if first.ID() != e.ID() || second.ID() != e.ID() || string(first.Data()) != string(second.Data()) || w.Stats().Retried != 1 {
		t.Fatal("retry changed original event")
	}
	requirePublish(t, s, fixtureEvent(t, "panics"))
	w, err = StartWorkers(t.Context(), s, WorkerConfig{Handlers: map[string]Handler{"fixture.observer": func(context.Context, event.Event) error { panic("private-panic") }}, Timeout: 50 * time.Millisecond, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { st, _ := s.State(t.Context()); return st.Failed == 1 })
	if err := w.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w.Stats().Retried != 2 {
		t.Fatal("panic retries not bounded")
	}
}
func TestIgnoringHandlerOccupiesOnlyOwnWorkerAndCloseHasDeadline(t *testing.T) {
	s, _, _, _ := fixtureStore(t, fixtureConfig())
	requirePublish(t, s, fixtureEvent(t, "slow"))
	entered, release := make(chan struct{}), make(chan struct{})
	w, err := StartWorkers(t.Context(), s, WorkerConfig{Handlers: map[string]Handler{"fixture.observer": func(context.Context, event.Event) error { close(entered); <-release; return nil }}, Timeout: time.Millisecond, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := w.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("claimed arbitrary handler was forcibly closed", err)
	}
	close(release)
	if err := w.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	st, _ := s.State(t.Context())
	if st.Acknowledged != 0 || st.Claimed != 1 {
		t.Fatal("canceled/late handler fabricated acknowledgement", st)
	}
}

type lostReceiptPublisher struct{ s *Store }

func (p lostReceiptPublisher) Publish(ctx context.Context, e event.Event) (Receipt, error) {
	if _, err := p.s.Publish(ctx, e); err != nil {
		return Receipt{}, err
	}
	return Receipt{}, errors.New("genuine committed reply lost")
}
func TestLostReceiptDoesNotEraseCommittedEventOrRecreateDelivery(t *testing.T) {
	s, dir, scope, p := fixtureStore(t, fixtureConfig())
	i, err := NewIngress(t.Context(), lostReceiptPublisher{s}, IngressConfig{QueueDepth: 1, MaxBytes: 128 << 10, MaxEventBytes: 65536, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e := fixtureEvent(t, "lost-receipt")
	if i.TryPublish(t.Context(), e) != nil {
		t.Fatal("volatile")
	}
	waitUntil(t, func() bool { return i.Stats().WriteFailed == 1 })
	if i.Stats().DurableCommitted != 0 {
		t.Fatal("lost receipt claimed committed delivery to producer")
	}
	if err := i.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	reopened, err := Open(t.Context(), dir, scope, fixtureConfig(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if r := requirePublish(t, reopened, e); !r.Duplicate {
		t.Fatal("lost reply retry created new admission")
	}
	st, err := reopened.State(t.Context())
	if err != nil || st.Rows != 2 || st.Pending != 1 {
		t.Fatal("ambiguous response recreated deliveries", st, err)
	}
}
