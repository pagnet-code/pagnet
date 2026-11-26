//go:build linux || darwin

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"
)

func waitNativeProxySignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy lifecycle did not complete")
	}
}

func TestNativeWorkerProxyAbortDuringPublication(t *testing.T) {
	for _, action := range []string{"abort", "close"} {
		t.Run(action, func(t *testing.T) {
			_, token, _, admit := subscriptionFixture(t)
			p := token.proxy
			subscription, err := admit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if p.AbortDone() == nil || p.aborted() {
				t.Fatal("fixture missing open abort signal")
			}
			watcherDone := make(chan struct{})
			go func() { defer close(watcherDone); p.watchLifecycle() }()
			p.publicationMu.RLock()
			var release sync.Once
			unlock := func() { release.Do(p.publicationMu.RUnlock) }
			t.Cleanup(unlock)
			actionDone := make(chan struct{})
			go func() {
				defer close(actionDone)
				if action == "abort" {
					p.abort()
				} else {
					_ = p.Close()
				}
			}()
			waitNativeProxySignal(t, p.AbortDone())
			if !p.aborted() {
				t.Fatal("abort did not become irreversible")
			}
			if action == "abort" {
				waitNativeProxySignal(t, actionDone)
			}
			select {
			case <-p.done:
				t.Fatal("ordered cleanup bypassed publication fence")
			default:
			}
			select {
			case <-subscription.Done():
				t.Fatal("subscription revoked before publication released")
			default:
			}
			unlock()
			waitNativeProxySignal(t, p.done)
			select {
			case <-subscription.Done():
			default:
				t.Fatal("done published before subscription revocation")
			}
			waitNativeProxySignal(t, actionDone)
			waitNativeProxySignal(t, watcherDone)
			p.abort()
			_ = p.Close()
		})
	}
}

func TestNativeWorkerProxyConcurrentAbortClose(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		p := &NativeWorkerProxy{connection: &NativeObservationConnection{closed: make(chan struct{})}, done: make(chan struct{}), abortDone: make(chan struct{})}
		watcherDone := make(chan struct{})
		go func() { defer close(watcherDone); p.watchLifecycle() }()
		start := make(chan struct{})
		var callers sync.WaitGroup
		for caller := 0; caller < 32; caller++ {
			callers.Add(1)
			go func(closeProxy bool) {
				defer callers.Done()
				<-start
				if closeProxy {
					_ = p.Close()
				} else {
					p.abort()
				}
			}(caller%2 == 0)
		}
		close(start)
		callersDone := make(chan struct{})
		go func() { defer close(callersDone); callers.Wait() }()
		waitNativeProxySignal(t, callersDone)
		waitNativeProxySignal(t, watcherDone)
		waitNativeProxySignal(t, p.done)
		if !p.aborted() {
			t.Fatal("concurrent close did not signal abort")
		}
	}
}
