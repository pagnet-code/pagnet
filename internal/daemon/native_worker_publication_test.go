//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func managedPreparePublicationFixture(t *testing.T) (*managedPrepareVerifierFixture, *nativeWorkerPublicationToken) {
	t.Helper()
	f := newManagedPrepareVerifierFixture(t)
	f.d.curConn, f.d.nativeConn = f.captured.Socket, f.captured.Connection
	f.d.writeTimeout = time.Second
	token, err := f.d.verifyManagedEndpointPrepareToken(t.Context(), f.captured, "https://example.test", f.command, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, token
}

func TestNativeWorkerPublicationRejectsChangesAfterVerification(t *testing.T) {
	for name, mutate := range map[string]func(*managedPrepareVerifierFixture, *nativeWorkerPublicationToken){
		"map replacement": func(f *managedPrepareVerifierFixture, token *nativeWorkerPublicationToken) {
			f.d.nativeWorkersMu.Lock()
			f.d.nativeWorkers[token.instanceID] = &nativeWorkerLink{conn: token.link.conn, proxy: token.proxy, ownership: token.ownership}
			f.d.nativeWorkersMu.Unlock()
		},
		"ownership mutation": func(_ *managedPrepareVerifierFixture, token *nativeWorkerPublicationToken) {
			token.link.mu.Lock()
			token.link.ownership.State = "retired"
			token.link.mu.Unlock()
		},
		"proxy close": func(_ *managedPrepareVerifierFixture, token *nativeWorkerPublicationToken) {
			if err := token.proxy.Close(); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, token := managedPreparePublicationFixture(t)
			mutate(f, token)
			f.d.writeMu.Lock()
			err := f.d.publishNativeWorker(token, f.captured, make(chan struct{}), f.command.Subject.ExpiresAt, func(time.Time) error {
				t.Error("stale verified worker reached write")
				return nil
			})
			f.d.writeMu.Unlock()
			if !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
				t.Fatalf("unexpected publication result: %v", err)
			}
		})
	}
}

func TestNativeWorkerPublicationHoldsFenceThroughWrite(t *testing.T) {
	f, token := managedPreparePublicationFixture(t)
	entered, release, published := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		f.d.writeMu.Lock()
		defer f.d.writeMu.Unlock()
		published <- f.d.publishNativeWorker(token, f.captured, make(chan struct{}), f.command.Subject.ExpiresAt, func(deadline time.Time) error {
			if !deadline.After(time.Now()) || deadline.After(f.command.Subject.ExpiresAt) {
				t.Error("write deadline exceeds authority lifetime")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	// TryLock observes the controlled callback while it is blocked, without
	// timing assumptions about the scheduling of competing mutations.
	for name, lock := range map[string]interface {
		TryLock() bool
		Unlock()
	}{
		"writer":                 &f.d.writeMu,
		"map replacement":        &f.d.nativeWorkersMu,
		"ownership mutation":     &token.link.mu,
		"proxy close":            &token.proxy.publicationMu,
		"connection replacement": &f.d.connMu,
		"host session":           &f.captured.Connection.mu,
	} {
		if lock.TryLock() {
			lock.Unlock()
			t.Errorf("%s was not fenced through write", name)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- token.proxy.Close() }()
	select {
	case <-token.proxy.done:
		t.Error("Close revoked proxy during publication")
	default:
	}
	close(release)
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-token.proxy.done:
	default:
		t.Fatal("Close did not complete after publication")
	}
}

func TestNativeWorkerPublicationSuccessAllowsDispatchCounters(t *testing.T) {
	f, token := managedPreparePublicationFixture(t)
	token.link.mu.Lock()
	token.link.ownership.LastDispatchSequence++
	token.link.ownership.RetiredFloor++
	token.link.mu.Unlock()
	writes := 0
	f.d.writeMu.Lock()
	err := f.d.publishNativeWorker(token, f.captured, make(chan struct{}), f.command.Subject.ExpiresAt, func(time.Time) error { writes++; return nil })
	f.d.writeMu.Unlock()
	if err != nil || writes != 1 {
		t.Fatalf("current immutable ownership did not publish: writes=%d err=%v", writes, err)
	}
}
