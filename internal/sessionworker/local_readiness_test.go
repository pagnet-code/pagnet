package sessionworker

import (
	"context"
	"testing"
	"time"
)

func TestLocalReadinessChangeBeforeWaitAndCancellation(t *testing.T) {
	n, e := newLocalReadiness()
	if e != nil {
		t.Fatal(e)
	}
	defer n.close()
	old := n.snapshot()
	n.pulse()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, e := n.wait(ctx, old)
	if e != nil || got.Boot != old.Boot || got.Counter != old.Counter+1 {
		t.Fatal("Change before registration was lost", e)
	}
	ready := make(chan error, 1)
	waiting, stop := context.WithCancel(ctx)
	go func() { _, e := n.wait(waiting, got); ready <- e }()
	stop()
	select {
	case e := <-ready:
		if e != context.Canceled {
			t.Fatal("Wrong cancellation", e)
		}
	case <-ctx.Done():
		t.Fatal("Cancelled readiness was stranded")
	}
}
func TestLocalReadinessShutdownOverflowAndNewBoot(t *testing.T) {
	n, e := newLocalReadiness()
	if e != nil {
		t.Fatal(e)
	}
	old := n.snapshot()
	n.mu.Lock()
	n.token.Counter = maxReadinessCounter
	n.mu.Unlock()
	n.pulse()
	if _, e = n.wait(t.Context(), old); e == nil {
		t.Fatal("Overflow was wrapped")
	}
	newer, e := newLocalReadiness()
	if e != nil {
		t.Fatal(e)
	}
	defer newer.close()
	if newer.snapshot().Boot == old.Boot {
		t.Fatal("Worker restart reused old notification boot")
	}
	before := newer.snapshot()
	newer.close()
	if _, e = newer.wait(t.Context(), before); e == nil {
		t.Fatal("Shutdown wait remained active")
	}
}
