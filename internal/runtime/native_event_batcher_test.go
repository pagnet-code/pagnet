package runtime

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/session"
)

func nativeBatchEvent(turn, text string) session.SessionEvent {
	return session.SessionEvent{Type: session.EventTurnOutput, NativeOutput: true, TurnID: turn, SessionID: "native", Output: text}
}

func TestNativeBatchDoesNotPublishBeforeSynchronousCommit(t *testing.T) {
	entered, commit := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var published []string
	b := &nativeEventBatcher{batch: func(events []session.SessionEvent) error {
		if len(events) != 3 {
			t.Error("merged/dropped original frames")
		}
		close(entered)
		<-commit
		return nil
	}, publish: func(e session.SessionEvent) error {
		mu.Lock()
		published = append(published, e.Output)
		mu.Unlock()
		return nil
	}}
	for _, text := range []string{"one", "two", "three"} {
		if err := b.push(nativeBatchEvent("A", text)); err != nil {
			t.Fatal(err)
		}
	}
	finished := make(chan error, 1)
	go func() { finished <- b.flush() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("batch capture not reached")
	}
	mu.Lock()
	n := len(published)
	mu.Unlock()
	if n != 0 {
		t.Fatal("published uncommitted original source")
	}
	close(commit)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(published, []string{"one", "two", "three"}) {
		t.Fatal("original fanout order changed", published)
	}
}

func TestNativeBatchResolutionFlushesOriginalOutputAndRejectsFailure(t *testing.T) {
	var order []string
	b := &nativeEventBatcher{observe: func(e session.SessionEvent) error { order = append(order, "capture:"+e.Type); return nil }, batch: func(events []session.SessionEvent) error {
		for _, e := range events {
			order = append(order, "capture:"+e.Output)
		}
		return nil
	}, publish: func(e session.SessionEvent) error { order = append(order, "publish:"+e.Type); return nil }}
	_ = b.push(nativeBatchEvent("A", "one"))
	_ = b.push(nativeBatchEvent("A", "two"))
	done := make(chan error, 1)
	go func() {
		done <- b.push(session.SessionEvent{Type: session.EventInteractionResolved, SessionID: "native"})
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	expected := []string{"capture:one", "capture:two", "publish:" + session.EventTurnOutput, "publish:" + session.EventTurnOutput, "capture:" + session.EventInteractionResolved, "publish:" + session.EventInteractionResolved}
	if !reflect.DeepEqual(order, expected) {
		t.Fatal("resolution overtook original source", order)
	}
	injected := errors.New("durable batch rejection")
	published := 0
	rejected := &nativeEventBatcher{batch: func([]session.SessionEvent) error { return injected }, publish: func(session.SessionEvent) error { published++; return nil }}
	_ = rejected.push(nativeBatchEvent("A", "one"))
	_ = rejected.push(nativeBatchEvent("A", "two"))
	if err := rejected.flush(); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if err := rejected.push(session.SessionEvent{Type: session.EventTurnCompleted}); !errors.Is(err, injected) || published != 0 {
		t.Fatal("failed capture invented completion/fanout", err, published)
	}
}
