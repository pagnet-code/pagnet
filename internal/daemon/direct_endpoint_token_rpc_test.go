//go:build linux || darwin

package daemon

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func directEndpointTokenRPCFixture(t *testing.T, serve func(net.Conn, *managedPrepareVerifierFixture)) (*managedPrepareVerifierFixture, *NativeWorkerProxy) {
	t.Helper()
	f := newManagedPrepareVerifierFixture(t)
	f.d.ServerURL = "https://example.test"
	p := f.d.nativeWorkers[f.command.Subject.InstanceID.String()].proxy
	p.controller = endpointRPCController(t, p.scope, p.connection, func(server net.Conn, _ *NativeObservationConnection) { serve(server, f) })
	watcherDone := make(chan struct{})
	go func() { defer close(watcherDone); p.watchLifecycle() }()
	t.Cleanup(func() {
		_ = p.Close()
		waitNativeProxySignal(t, watcherDone)
	})
	return f, p
}

func directEndpointTokenRPCVerify(ctx context.Context, f *managedPrepareVerifierFixture) (*nativeWorkerPublicationToken, error) {
	return f.d.verifyDirectEndpointToken(ctx, f.captured, "https://example.test", nativeManagedSubjectFromEndpoint(f.command.Subject))
}

func directEndpointTokenRPCReply(t *testing.T, server net.Conn, f *managedPrepareVerifierFixture) {
	t.Helper()
	if err := swWriteFrame(server, sessionworker.Response{OwnershipVerify: &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}}); err != nil {
		t.Error("fake worker response failed")
	}
}

func directEndpointTokenRPCWaitForClose(server net.Conn) {
	var b [1]byte
	_, _ = server.Read(b[:])
}

func assertDirectEndpointTokenRPCPinned(t *testing.T, f *managedPrepareVerifierFixture, p *NativeWorkerProxy, token *nativeWorkerPublicationToken, err error) {
	t.Helper()
	link := f.d.nativeWorkers[f.command.Subject.InstanceID.String()]
	if err != nil || token == nil {
		t.Fatal("healthy endpoint verification did not return a token")
	}
	if token.proxy != p || token.link != link || token.instanceID != p.scope.InstanceID || !sameManagedPrepareOwnership(token.ownership, link.ownership) || !reflect.DeepEqual(token.subject, nativeManagedSubjectFromEndpoint(f.command.Subject)) || p.aborted() {
		t.Fatal("endpoint token did not pin the verified authority")
	}
}

func TestDirectEndpointTokenRPCSuccess(t *testing.T) {
	f, p := directEndpointTokenRPCFixture(t, func(server net.Conn, f *managedPrepareVerifierFixture) {
		if endpointRPCRequest(t, server) {
			directEndpointTokenRPCReply(t, server, f)
		}
		directEndpointTokenRPCWaitForClose(server)
	})
	token, err := directEndpointTokenRPCVerify(t.Context(), f)
	assertDirectEndpointTokenRPCPinned(t, f, p, token, err)
}

func TestDirectEndpointTokenRPCPreflightPreservesProxy(t *testing.T) {
	for _, kind := range []string{"nil-context", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			f, p := directEndpointTokenRPCFixture(t, func(server net.Conn, f *managedPrepareVerifierFixture) {
				if endpointRPCRequest(t, server) {
					directEndpointTokenRPCReply(t, server, f)
				}
				directEndpointTokenRPCWaitForClose(server)
			})
			var ctx context.Context
			want := ErrManagedEndpointPrepareRejected
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(t.Context())
				cancel()
				want = ErrManagedEndpointPrepareRetryable
			}
			if token, err := directEndpointTokenRPCVerify(ctx, f); token != nil || err != want || p.aborted() {
				t.Fatal("preflight failure changed endpoint authority or disposition")
			}
			token, err := directEndpointTokenRPCVerify(t.Context(), f)
			assertDirectEndpointTokenRPCPinned(t, f, p, token, err)
		})
	}
}

func TestDirectEndpointTokenRPCControllerBusyPreservesProxy(t *testing.T) {
	dispatched, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	f, p := directEndpointTokenRPCFixture(t, func(server net.Conn, f *managedPrepareVerifierFixture) {
		if !endpointRPCRequest(t, server) {
			return
		}
		close(dispatched)
		<-release
		directEndpointTokenRPCReply(t, server, f)
		if endpointRPCRequest(t, server) {
			directEndpointTokenRPCReply(t, server, f)
		}
		directEndpointTokenRPCWaitForClose(server)
	})
	type result struct {
		token *nativeWorkerPublicationToken
		err   error
	}
	first := make(chan result, 1)
	go func() {
		token, err := directEndpointTokenRPCVerify(t.Context(), f)
		first <- result{token, err}
	}()
	waitNativeProxySignal(t, dispatched)
	if token, err := directEndpointTokenRPCVerify(t.Context(), f); token != nil || err != ErrManagedEndpointPrepareRetryable || p.aborted() {
		t.Fatal("busy controller changed endpoint authority or disposition")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case got := <-first:
		assertDirectEndpointTokenRPCPinned(t, f, p, got.token, got.err)
	case <-time.After(time.Second):
		t.Fatal("original endpoint verification did not finish")
	}
	token, err := directEndpointTokenRPCVerify(t.Context(), f)
	assertDirectEndpointTokenRPCPinned(t, f, p, token, err)
}

func TestDirectEndpointTokenRPCPostDispatchCancelBeforeCleanup(t *testing.T) {
	dispatched := make(chan struct{})
	f, p := directEndpointTokenRPCFixture(t, func(server net.Conn, _ *managedPrepareVerifierFixture) {
		if !endpointRPCRequest(t, server) {
			return
		}
		close(dispatched)
		directEndpointTokenRPCWaitForClose(server)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan bool, 1)
	go func() {
		token, err := directEndpointTokenRPCVerify(ctx, f)
		finished <- token == nil && err == ErrManagedEndpointPrepareRetryable
	}()
	waitNativeProxySignal(t, dispatched)
	p.publicationMu.Lock()
	var unlock sync.Once
	defer unlock.Do(p.publicationMu.Unlock)
	cancel()
	select {
	case valid := <-finished:
		if !valid || !p.aborted() {
			t.Fatal("post-dispatch cancellation did not revoke endpoint authority")
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint cancellation waited for publication cleanup")
	}
	select {
	case <-p.done:
		t.Fatal("endpoint cancellation skipped ordered cleanup")
	default:
	}
	unlock.Do(p.publicationMu.Unlock)
	waitNativeProxySignal(t, p.done)
}

func TestDirectEndpointTokenRPCSanitizesRejection(t *testing.T) {
	for _, retryable := range []bool{false, true} {
		name := "terminal-conflict"
		if retryable {
			name = "retryable"
		}
		t.Run(name, func(t *testing.T) {
			f, p := directEndpointTokenRPCFixture(t, func(server net.Conn, f *managedPrepareVerifierFixture) {
				if !endpointRPCRequest(t, server) {
					return
				}
				if swWriteFrame(server, sessionworker.Response{Error: "private worker diagnostic", Retryable: retryable}) != nil {
					t.Error("fake worker rejection failed")
					return
				}
				if endpointRPCRequest(t, server) {
					directEndpointTokenRPCReply(t, server, f)
				}
				directEndpointTokenRPCWaitForClose(server)
			})
			want := ErrManagedEndpointPrepareRejected
			if retryable {
				want = ErrManagedEndpointPrepareRetryable
			}
			if token, err := directEndpointTokenRPCVerify(t.Context(), f); token != nil || err != want || p.aborted() {
				t.Fatal("worker rejection changed endpoint authority or exposed diagnostics")
			}
			token, err := directEndpointTokenRPCVerify(t.Context(), f)
			assertDirectEndpointTokenRPCPinned(t, f, p, token, err)
		})
	}
}
