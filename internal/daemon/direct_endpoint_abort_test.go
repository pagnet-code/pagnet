//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func checkEndpointAbortPromptly(t *testing.T, name string, check func() bool) {
	t.Helper()
	result := make(chan bool, 1)
	go func() { result <- check() }()
	select {
	case rejected := <-result:
		if !rejected {
			t.Fatalf("%s accepted aborted proxy", name)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s waited for cleanup lock", name)
	}
}

func TestDirectEndpointAbortRejectsAuthorityBeforeCleanup(t *testing.T) {
	d, token, captured, admit := subscriptionFixture(t)
	s, err := admit(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := token.proxy
	p.snapshotAt = time.Now()
	candidate := s.owner.add(s.binding)
	if candidate == nil {
		t.Fatal("candidate missing")
	}
	fresh := &NativeWorkerProxy{abortDone: make(chan struct{}), done: make(chan struct{}), directEndpointEpoch: p.directEndpointEpoch, directEndpointObserved: p.directEndpointObserved, directEndpointIdentity: p.directEndpointIdentity, snapshotAt: p.snapshotAt}
	freshBinding := s.binding
	freshBinding.proxy = fresh
	freshSubscription := s.owner.add(freshBinding)
	if freshSubscription == nil || !s.owner.activate(freshSubscription) {
		t.Fatal("fresh subscription missing")
	}
	watcherDone := make(chan struct{})
	go func() { defer close(watcherDone); p.watchLifecycle() }()
	p.publicationMu.Lock()
	s.owner.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(func() { s.owner.mu.Unlock(); p.publicationMu.Unlock() }) }
	defer unlock()
	p.abort()
	checkEndpointAbortPromptly(t, "Valid", func() bool { return !s.Valid() })
	checkEndpointAbortPromptly(t, "add", func() bool { return s.owner.add(s.binding) == nil })
	checkEndpointAbortPromptly(t, "activate", func() bool { return !s.owner.activate(candidate) })
	checkEndpointAbortPromptly(t, "operationCurrent", func() bool { return !s.operationCurrent(context.Background()) })
	checkEndpointAbortPromptly(t, "authority", func() bool { _, valid := p.directEndpointAuthority(token.subject); return !valid })
	checkEndpointAbortPromptly(t, "context authority", func() bool {
		_, valid, err := p.directEndpointAuthorityContext(context.Background(), token.subject)
		return !valid && err == nil
	})
	checkEndpointAbortPromptly(t, "availability", func() bool { return p.availability(time.Now()) == "unavailable" })
	checkEndpointAbortPromptly(t, "publication", func() bool {
		return errors.Is(d.publishNativeWorker(token, captured, make(chan struct{}), token.subject.ExpiresAt, func(time.Time) error {
			t.Error("aborted proxy published")
			return nil
		}), ErrManagedEndpointPrepareRetryable)
	})
	select {
	case <-p.done:
		t.Fatal("abort closed ordered proxy completion")
	case <-s.Done():
		t.Fatal("abort closed ordered subscription completion")
	default:
	}
	unlock()
	waitNativeProxySignal(t, watcherDone)
	waitNativeProxySignal(t, p.done)
	if !freshSubscription.Valid() || fresh.availability(time.Now()) != "connected" {
		t.Fatal("old proxy cleanup revoked fresh proxy")
	}
	if _, valid := fresh.directEndpointAuthority(token.subject); !valid {
		t.Fatal("old proxy abort revoked fresh authority")
	}
	if (&DirectEndpointSubscription{}).AbortDone() != nil {
		t.Fatal("partial fixture exposed an abort channel")
	}
}

func TestDirectEndpointOperationAbortCancelsBeforeCleanup(t *testing.T) {
	f := newDirectEndpointOperationFixture(t, 0)
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	finished := make(chan error, 1)
	go func() {
		finished <- f.operate(context.Background(), func(ctx context.Context, _ endpointMaterial) error {
			entered <- ctx
			<-release
			return nil
		})
	}()
	var opctx context.Context
	select {
	case opctx = <-entered:
	case err := <-finished:
		t.Fatalf("operation did not dispatch: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not dispatch")
	}
	p := f.token.proxy
	p.publicationMu.Lock()
	f.s.owner.mu.Lock()
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(func() { f.s.owner.mu.Unlock(); p.publicationMu.Unlock() }) }
	defer unlock()
	p.abort()
	waitNativeProxySignal(t, opctx.Done())
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err != errDirectEndpointOperationUnknown {
			t.Fatalf("aborted callback result = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("operation response waited for cleanup")
	}
	select {
	case <-f.s.Done():
		t.Fatal("operation cancellation closed ordered subscription completion")
	default:
	}
	unlock()
	_ = p.Close()
}

func TestDirectEndpointCredentialFenceRejectsAbortDuringAcquisition(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "context"}[bounded], func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
			var filename string
			if err := d.state.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&filename); err != nil {
				t.Fatal(err)
			}
			if err := d.state.db.Close(); err != nil {
				t.Fatal(err)
			}
			connector := &enrollmentContextConnector{path: filename}
			d.state.db = sql.OpenDB(connector)
			d.state.db.SetMaxOpenConns(1)
			aborted := false
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				result, err := next.ExecContext(ctx, query, args)
				if query == "BEGIN IMMEDIATE" && err == nil {
					// The fence has passed its entry check, but has not yet
					// acquired the publication locks or accepted authority.
					token.proxy.abort()
					aborted = true
				}
				return result, err
			}
			lane := newDirectManagedSourceCredentialPublicationLane()
			fence := d.credentialPublicationFenceContextMode(context.Background(), bounded, token, captured, lane, token.subject, true, directManagedSourceCredentialProtocolV2, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.BudgetExpiresAt)
			_, err := keys.InstallCredential(issue, "https://example.test", captured.Session, directSourceCredentialScopeOKV2, func(conn *sql.Conn, _ transport.DirectManagedSourceCredentialIssueV2, server string, session transport.HostSessionPayload) (func(), error) {
				return fence(conn, server, session)
			})
			if !aborted || !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
				t.Fatalf("acquisition abort = %v, fence result = %v", aborted, err)
			}
			var installed int
			if err := keys.registry.db.QueryRow("SELECT COUNT(*) FROM native_direct_managed_source_v2_credentials WHERE state='installed'").Scan(&installed); err != nil || installed != 0 {
				t.Fatalf("aborted credential publication: installed=%d err=%v", installed, err)
			}
		})
	}
}

func TestNativeWorkerPublicationRejectsAbortBeforeWrite(t *testing.T) {
	f, token := managedPreparePublicationFixture(t)
	f.captured.Connection.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(f.captured.Connection.mu.Unlock) }
	defer unlock()
	finished := make(chan error, 1)
	go func() {
		f.d.writeMu.Lock()
		defer f.d.writeMu.Unlock()
		finished <- f.d.publishNativeWorker(token, f.captured, make(chan struct{}), f.command.Subject.ExpiresAt, func(time.Time) error {
			t.Error("proxy aborted during acquisition reached write")
			return nil
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for token.proxy.publicationMu.TryLock() {
		token.proxy.publicationMu.Unlock()
		if !time.Now().Before(deadline) {
			t.Fatal("publication did not reach its fence")
		}
		time.Sleep(time.Millisecond)
	}
	token.proxy.abort()
	unlock()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
			t.Fatalf("publication result = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not finish")
	}
}
