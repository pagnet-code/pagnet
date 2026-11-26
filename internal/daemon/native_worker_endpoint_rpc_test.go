//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func endpointRPCFixture(t *testing.T, serve func(net.Conn, *NativeObservationConnection)) (*NativeWorkerProxy, *DirectEndpointSubscription) {
	t.Helper()
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: "tenant", AccountID: "account", HostID: "host", InstanceID: "instance", Generation: "generation"}
	native := &NativeObservationConnection{serverURL: scope.ServerURL, hostID: scope.HostID, closed: make(chan struct{}), session: &transport.HostSessionPayload{TenantID: scope.TenantID, AccountID: scope.AccountID}}
	dir := t.TempDir()
	path, err := sessionworker.SocketPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	key := make([]byte, 32)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		server, err := listener.Accept()
		if err != nil {
			return
		}
		defer server.Close()
		nonce, err := swFreshNonce()
		if err != nil {
			t.Error("fake worker nonce unavailable")
			return
		}
		hello := swHandshake{Protocol: sessionworker.Protocol, Scope: scope, ServerNonce: nonce, Ownership: sessionworker.NativeOwnershipProtocol}
		if swWriteFrame(server, hello) != nil {
			return
		}
		var auth swHandshake
		if swReadFrame(server, &auth) != nil || auth.Proof != swProof(key, "controller", auth) {
			t.Error("fake worker authentication failed")
			return
		}
		auth.Lease = 1
		auth.Proof = swProof(key, "worker", auth)
		if swWriteFrame(server, auth) != nil {
			return
		}
		serve(server, native)
	}()
	controller, err := sessionworker.DialOwnerController(t.Context(), dir, scope, key, "endpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	p := &NativeWorkerProxy{connection: native, controller: controller, scope: scope, bootstrap: sessionworker.Bootstrap{Native: sessionworker.NativeSpec{NetworkID: "network", Kind: "worker"}}, done: make(chan struct{}), abortDone: make(chan struct{})}
	owner := &directEndpointSubscriptions{}
	s := owner.add(directEndpointBinding{proxy: p, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
	p.directInvalidations.register(owner)
	watcherDone := make(chan struct{})
	go func() { defer close(watcherDone); p.watchLifecycle() }()
	t.Cleanup(func() {
		_ = p.Close()
		waitNativeProxySignal(t, watcherDone)
		waitNativeProxySignal(t, serverDone)
	})
	return p, s
}

func endpointRPCRequest(t *testing.T, server net.Conn) bool {
	t.Helper()
	var req sessionworker.Request
	if swReadFrame(server, &req) != nil {
		return false
	}
	if req.Type != "ownership_verify" || req.OwnershipVerify == nil {
		t.Error("endpoint RPC used a different request")
		return false
	}
	return true
}

func endpointRPCSuccess(t *testing.T, server net.Conn) {
	t.Helper()
	if err := swWriteFrame(server, sessionworker.Response{OwnershipVerify: &sessionworker.NativeOwnershipVerifyResult{}}); err != nil {
		t.Error("fake worker response failed")
	}
}

func TestNativeWorkerEndpointRPCFailureBeforeOrderedCleanup(t *testing.T) {
	for _, failure := range []string{"EOF", "timeout", "explicit-cancel", "unknown-response"} {
		t.Run(failure, func(t *testing.T) {
			dispatched := make(chan struct{})
			p, s := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
				if !endpointRPCRequest(t, server) {
					return
				}
				close(dispatched)
				switch failure {
				case "timeout", "explicit-cancel":
					var b [1]byte
					_, _ = server.Read(b[:]) // controller closes after its deadline
				case "unknown-response":
					_ = swWriteFrame(server, sessionworker.Response{})
				}
			})
			p.publicationMu.Lock()
			s.owner.mu.Lock()
			var release sync.Once
			unlock := func() { release.Do(func() { s.owner.mu.Unlock(); p.publicationMu.Unlock() }) }
			defer unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			if failure == "explicit-cancel" {
				cancel()
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			finished := make(chan error, 1)
			go func() { _, err := p.verifyEndpointOwnership(ctx, transport.NativeWorkerOwnership{}); finished <- err }()
			waitNativeProxySignal(t, dispatched)
			if failure == "explicit-cancel" {
				cancel()
			}
			select {
			case err := <-finished:
				if err != errDirectEndpointRPCUnknown {
					t.Fatalf("post-dispatch result = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("RPC failure waited for cleanup locks")
			}
			waitNativeProxySignal(t, p.AbortDone())
			if s.Valid() {
				t.Fatal("failed RPC left stale handle usable")
			}
			select {
			case <-p.done:
				t.Fatal("RPC failure closed proxy before ordered cleanup")
			case <-s.Done():
				t.Fatal("RPC failure closed subscription before ordered cleanup")
			default:
			}
			unlock()
			waitNativeProxySignal(t, p.done)
			waitNativeProxySignal(t, s.Done())
		})
	}
}

func TestNativeWorkerEndpointRPCPreflightPreservesProxy(t *testing.T) {
	p, _ := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
		if endpointRPCRequest(t, server) {
			endpointRPCSuccess(t, server)
		}
		var b [1]byte
		_, _ = server.Read(b[:])
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.verifyEndpointOwnership(ctx, transport.NativeWorkerOwnership{}); !errors.Is(err, context.Canceled) || !errors.Is(err, sessionworker.ErrControllerCallNotStarted) {
		t.Fatalf("canceled preflight = %v", err)
	}
	p.connection.mu.Lock()
	_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
	p.connection.mu.Unlock()
	if !errors.Is(err, ErrNativeOriginAdmissionDeferred) || !errors.Is(err, sessionworker.ErrControllerCallNotStarted) || p.aborted() {
		t.Fatalf("busy preflight = %v, aborted=%v", err, p.aborted())
	}
	if _, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{}); err != nil || p.aborted() {
		t.Fatalf("healthy RPC after preflight failure = %v", err)
	}
}

func TestNativeWorkerEndpointRPCPostAdmissionContention(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, _ := endpointRPCFixture(t, func(server net.Conn, native *NativeObservationConnection) {
		if !endpointRPCRequest(t, server) {
			return
		}
		native.mu.Lock()
		endpointRPCSuccess(t, server)
		<-release
		native.mu.Unlock()
		if endpointRPCRequest(t, server) {
			endpointRPCSuccess(t, server)
		}
		var b [1]byte
		_, _ = server.Read(b[:])
	})
	finished := make(chan error, 1)
	go func() {
		_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
		finished <- err
	}()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrNativeOriginAdmissionDeferred) || errors.Is(err, sessionworker.ErrControllerCallNotStarted) || p.aborted() {
			t.Fatalf("post-RPC contention = %v, aborted=%v", err, p.aborted())
		}
	case <-time.After(time.Second):
		t.Fatal("post-RPC admission waited on connection lock")
	}
	once.Do(func() { close(release) })
	// Acquire once after the worker releases, so the retry cannot race it.
	p.connection.mu.Lock()
	p.connection.mu.Unlock()
	if _, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{}); err != nil {
		t.Fatalf("healthy retry after post-RPC contention = %v", err)
	}
}

func TestNativeWorkerEndpointRPCRejectsSuccessAfterAbort(t *testing.T) {
	dispatched, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, s := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
		if !endpointRPCRequest(t, server) {
			return
		}
		close(dispatched)
		<-release
		endpointRPCSuccess(t, server)
		var b [1]byte
		_, _ = server.Read(b[:])
	})
	p.publicationMu.Lock()
	var unlock sync.Once
	defer unlock.Do(p.publicationMu.Unlock)
	finished := make(chan error, 1)
	go func() {
		_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
		finished <- err
	}()
	waitNativeProxySignal(t, dispatched)
	p.abort()
	once.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err != errDirectEndpointRPCUnknown || s.Valid() {
			t.Fatal("successful reply revived aborted authority")
		}
	case <-time.After(time.Second):
		t.Fatal("success rejection waited for ordered cleanup")
	}
	unlock.Do(p.publicationMu.Unlock)
}

func TestNativeWorkerEndpointRPCConcurrentCloseFailure(t *testing.T) {
	dispatched, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	p, s := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
		if endpointRPCRequest(t, server) {
			close(dispatched)
			<-release
		}
	})
	p.publicationMu.Lock()
	var unlock sync.Once
	defer unlock.Do(p.publicationMu.Unlock)
	finished := make(chan error, 1)
	go func() {
		_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
		finished <- err
	}()
	waitNativeProxySignal(t, dispatched)
	var closers sync.WaitGroup
	for i := 0; i < 16; i++ {
		closers.Add(1)
		go func(abortOnly bool) {
			defer closers.Done()
			if abortOnly {
				p.abort()
			} else {
				_ = p.Close()
			}
		}(i%2 == 0)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err != errDirectEndpointRPCUnknown {
			t.Fatalf("failed RPC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed RPC waited for concurrent Close")
	}
	unlock.Do(p.publicationMu.Unlock)
	closed := make(chan struct{})
	go func() { defer close(closed); closers.Wait() }()
	waitNativeProxySignal(t, closed)
	waitNativeProxySignal(t, p.done)
	waitNativeProxySignal(t, s.Done())
}

func TestNativeWorkerEndpointRPCControllerBusyPreservesProxy(t *testing.T) {
	dispatched, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, _ := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
		if !endpointRPCRequest(t, server) {
			return
		}
		close(dispatched)
		<-release
		endpointRPCSuccess(t, server)
		if endpointRPCRequest(t, server) {
			endpointRPCSuccess(t, server)
		}
		var b [1]byte
		_, _ = server.Read(b[:])
	})
	first := make(chan error, 1)
	go func() {
		_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
		first <- err
	}()
	waitNativeProxySignal(t, dispatched)
	_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
	if !errors.Is(err, sessionworker.ErrControllerCallNotStarted) || !errors.Is(err, sessionworker.ErrControllerCallBusy) || p.aborted() {
		t.Fatalf("controller contention = %v, aborted=%v", err, p.aborted())
	}
	once.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatalf("original call failed after contention: %v", err)
	}
	if _, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{}); err != nil {
		t.Fatalf("later call failed after contention: %v", err)
	}
}

func TestNativeWorkerEndpointRPCSanitizesRejection(t *testing.T) {
	for _, retryable := range []bool{false, true} {
		name := "rejected"
		if retryable {
			name = "retryable"
		}
		t.Run(name, func(t *testing.T) {
			p, _ := endpointRPCFixture(t, func(server net.Conn, _ *NativeObservationConnection) {
				if !endpointRPCRequest(t, server) {
					return
				}
				_ = swWriteFrame(server, sessionworker.Response{Error: "private worker diagnostic", Retryable: retryable})
				if endpointRPCRequest(t, server) {
					endpointRPCSuccess(t, server)
				}
				var b [1]byte
				_, _ = server.Read(b[:])
			})
			_, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{})
			want := ErrNativeObservationConflict
			if retryable {
				want = ErrNativeOriginAdmissionDeferred
			}
			if err != want || p.aborted() {
				t.Fatalf("explicit rejection = %v, aborted=%v", err, p.aborted())
			}
			if _, err := p.verifyEndpointOwnership(t.Context(), transport.NativeWorkerOwnership{}); err != nil {
				t.Fatalf("explicit rejection poisoned controller: %v", err)
			}
		})
	}
}
