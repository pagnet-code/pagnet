package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func waitWakeAbortSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wake abort cancellation blocked")
	}
}

func TestDirectEndpointWakeAbortCancelsBeforeCleanup(t *testing.T) {
	d, lane, handle := wakeAttachmentFixture(t, true)
	proxy := &NativeWorkerProxy{abortDone: make(chan struct{})}
	handle.binding.proxy = proxy
	fresh := d.directSubscriptions.add(handle.binding)
	fresh.binding.proxy = &NativeWorkerProxy{abortDone: make(chan struct{})}
	started, canceled := make(chan struct{}), make(chan struct{})
	entry, err := lane.attach(handle, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	freshEntry, err := lane.attach(fresh, noopWakeReconcile)
	if err != nil {
		t.Fatal(err)
	}
	waitWakeAbortSignal(t, started)
	lane.mu.Lock()
	handle.owner.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(func() { handle.owner.mu.Unlock(); lane.mu.Unlock() }) }
	t.Cleanup(unlock)
	proxy.abort()
	waitWakeAbortSignal(t, entry.Done())
	waitWakeAbortSignal(t, canceled)
	if entry.TerminalError() != context.Canceled {
		t.Fatal("abort lost local cancellation outcome")
	}
	select {
	case <-handle.Done():
		t.Fatal("abort test bypassed ordered owner cleanup")
	default:
	}
	if lane.byHandle[handle] != entry {
		t.Fatal("attachment removed while connection lock held")
	}
	select {
	case <-freshEntry.Done():
		t.Fatal("stale abort canceled fresh attachment")
	default:
	}
	unlock()
	waitWakeAttachmentRemoved(t, lane, entry)
}

func TestDirectEndpointWakeAbortedAttachRejectsBeforeOwnerLock(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	proxy := &NativeWorkerProxy{abortDone: make(chan struct{})}
	handle.binding.proxy = proxy
	handle.owner.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(handle.owner.mu.Unlock) }
	t.Cleanup(unlock)
	proxy.abort()
	result := make(chan error, 1)
	go func() {
		_, err := lane.attach(handle, noopWakeReconcile)
		result <- err
	}()
	select {
	case err := <-result:
		if err != ErrNativeObservationConflict {
			t.Fatal("aborted attachment accepted", err)
		}
	case <-time.After(time.Second):
		t.Fatal("aborted attachment waited on owner lock")
	}
	unlock()
	if len(lane.usedIDs) != 0 {
		t.Fatal("aborted attachment consumed an ID")
	}
}

func TestDirectEndpointWakeAbortedWriteRejectsBeforeLocks(t *testing.T) {
	d, lane, handle := wakeAttachmentFixture(t, true)
	proxy := &NativeWorkerProxy{abortDone: make(chan struct{})}
	handle.binding.proxy = proxy
	entry, err := lane.attach(handle, noopWakeReconcile)
	if err != nil {
		t.Fatal(err)
	}
	d.connMu.Lock()
	lane.mu.Lock()
	handle.owner.mu.Lock()
	var release sync.Once
	unlock := func() {
		release.Do(func() { handle.owner.mu.Unlock(); lane.mu.Unlock(); d.connMu.Unlock() })
	}
	t.Cleanup(unlock)
	proxy.abort()
	for _, typ := range []string{transport.MsgDirectEndpointWakeSubscribe, transport.MsgDirectEndpointWakeACK} {
		job := &directEndpointWakeWrite{entry: entry, typ: typ, deadline: time.Now().Add(time.Second)}
		if current, retry := lane.writeCurrent(job); current || retry {
			t.Fatalf("aborted %s write accepted or retried", typ)
		}
	}
	unlock()
	waitWakeAbortSignal(t, entry.Done())
}

func TestDirectEndpointWakeAbortDuringAttachmentInsertion(t *testing.T) {
	_, lane, handle := wakeAttachmentFixture(t, true)
	proxy := &NativeWorkerProxy{abortDone: make(chan struct{})}
	handle.binding.proxy = proxy
	lane.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(lane.mu.Unlock) }
	t.Cleanup(unlock)
	result := make(chan error, 1)
	go func() {
		_, err := lane.attach(handle, noopWakeReconcile)
		result <- err
	}()
	// Holding lane.mu stops insertion after the initial Valid check. Once
	// attach owns native.mu, abort must still reject its final admission.
	deadline := time.Now().Add(time.Second)
	for lane.native.mu.TryLock() {
		lane.native.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("attachment did not reach insertion fence")
		}
		time.Sleep(time.Millisecond)
	}
	proxy.abort()
	unlock()
	select {
	case err := <-result:
		if err != ErrNativeObservationConflict {
			t.Fatal("abort during attachment insertion accepted", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attachment insertion did not finish")
	}
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if len(lane.usedIDs) != 0 || len(lane.byHandle) != 0 {
		t.Fatal("aborted insertion retained state")
	}
}
