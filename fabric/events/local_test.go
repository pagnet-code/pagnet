package events

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric"
)

func config(subs ...Subscription) LocalConfig {
	return LocalConfig{Subscriptions: subs, MaxSubscriptions: 500, QueueDepth: 2, MaxQueueBytes: 1 << 20, MaxEventBytes: 65536, Timeout: time.Second, RetryDelay: time.Millisecond, Retention: time.Hour, MaxAttempts: 3}
}
func example(t *testing.T) event.Event {
	t.Helper()
	e, err := Lifecycle("pagnet://local/node/test", "", LifecycleMetadata{InvocationID: "original-invocation", Operation: fabric.OperationInvoke, Disposition: "completed"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func closeBus(t *testing.T, b *Local) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for observer")
		var zero T
		return zero
	}
}

func TestSlowObserverNeverBlocksPublicationAndAdmissionIsAtomic(t *testing.T) {
	e := example(t)
	started, release := make(chan struct{}, 1), make(chan struct{})
	var fast atomic.Int64
	b, err := NewLocal(config(
		Subscription{ID: "test.slow", Types: []string{e.Type()}, Handler: func(context.Context, event.Event) error { started <- struct{}{}; <-release; return nil }},
		Subscription{ID: "test.fast", Types: []string{e.Type()}, Handler: func(context.Context, event.Event) error { fast.Add(1); return nil }},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer closeBus(t, b)
	if err = b.TryPublish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	receive(t, started)
	if err = b.TryPublish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err = b.TryPublish(context.Background(), e); err == nil {
		t.Fatal("accepted beyond slow subscriber capacity")
	}
	if s := b.Stats(); s.Accepted != 2 || s.Rejected != 1 {
		t.Fatalf("wrong atomic admission stats: %+v", s)
	}
	close(release)
}

func TestRetryUsesSameEventWithIndependentOwnedData(t *testing.T) {
	e := example(t)
	original := e.ID()
	observed := make(chan event.Event, 3)
	var attempt atomic.Int32
	b, err := NewLocal(config(Subscription{ID: "test.retry", Types: []string{e.Type()}, Handler: func(_ context.Context, got event.Event) error {
		observed <- got.Clone()
		if attempt.Add(1) == 1 {
			got.SetID("mutated-by-observer")
			got.DataEncoded[0] = 'x'
			return errors.New("provider-secret-must-not-escape")
		}
		return nil
	}}))
	if err != nil {
		t.Fatal(err)
	}
	defer closeBus(t, b)
	if err = b.TryPublish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e.SetID("mutated-by-publisher")
	e.DataEncoded[0] = 'y'
	first, second := receive(t, observed), receive(t, observed)
	if first.ID() != original || second.ID() != original || string(first.Data()) != string(second.Data()) {
		t.Fatal("queue ownership/retry identity changed")
	}
}

func TestObserverPanicIsBoundedAndOtherObserverContinues(t *testing.T) {
	e := example(t)
	panics, good := make(chan struct{}, 3), make(chan struct{}, 1)
	b, err := NewLocal(config(
		Subscription{ID: "test.panic", Types: []string{e.Type()}, Handler: func(context.Context, event.Event) error { panics <- struct{}{}; panic("secret") }},
		Subscription{ID: "test.good", Types: []string{e.Type()}, Handler: func(context.Context, event.Event) error { good <- struct{}{}; return nil }},
	))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.TryPublish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	receive(t, good)
	for range 3 {
		receive(t, panics)
	}
	closeBus(t, b)
	if s := b.Stats(); s.Pending != 0 || s.Bytes != 0 || s.Retries != 2 || s.Delivered != 1 {
		t.Fatalf("wrong terminal queue state: %+v", s)
	}
}

func TestCloseRespectsDeadlineForUncooperativeObserver(t *testing.T) {
	e := example(t)
	started, release := make(chan struct{}), make(chan struct{})
	b, err := NewLocal(config(Subscription{ID: "test.block", Types: []string{e.Type()}, Handler: func(context.Context, event.Event) error { close(started); <-release; return nil }}))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.TryPublish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	receive(t, started)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = b.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unbounded close: %v", err)
	}
	if err = b.TryPublish(context.Background(), e); err == nil {
		t.Fatal("closed bus admitted event")
	}
	close(release)
	closeBus(t, b)
}

func TestCloudEventsGrammarPrivacyAndDataPrecision(t *testing.T) {
	e := example(t)
	raw, err := Encode(e, 65536)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"payload", "credential", "principal", "resume", "password"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("lifecycle content leak: %s", forbidden)
		}
	}
	if _, err = Decode([]byte(`{"specversion":"1.0","id":"a","i\u0064":"b","source":"/","type":"test.event"}`), 65536); err == nil {
		t.Fatal("duplicate escaped event field accepted")
	}
	precise := []byte(`{"specversion":"1.0","id":"a","source":"/","type":"test.event","datacontenttype":"application/json","data":{"integer":9007199254740993}}`)
	decoded, err := Decode(precise, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded.Data()), "9007199254740993") {
		t.Fatal("application integer precision lost")
	}
	if _, err = Encode(decoded, 20); err == nil {
		t.Fatal("oversized event accepted")
	}
}
