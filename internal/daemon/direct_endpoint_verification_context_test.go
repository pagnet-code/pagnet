//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectEndpointVerifierContextAcquisition(t *testing.T) {
	for _, held := range []string{"worker map", "ownership", "native session", "publication epoch", "registry pool", "state pool", "canceled"} {
		t.Run(held, func(t *testing.T) {
			f := newManagedPrepareVerifierFixture(t)
			p := f.d.nativeWorkers[f.command.Subject.InstanceID.String()].proxy
			link := f.d.nativeWorkers[f.command.Subject.InstanceID.String()]
			release := func() {}
			switch held {
			case "worker map":
				f.d.nativeWorkersMu.Lock()
				release = f.d.nativeWorkersMu.Unlock
			case "ownership":
				link.mu.Lock()
				release = link.mu.Unlock
			case "native session":
				f.captured.Connection.mu.Lock()
				release = f.captured.Connection.mu.Unlock
			case "publication epoch":
				p.publicationMu.Lock()
				release = p.publicationMu.Unlock
			case "registry pool", "state pool":
				db := f.d.nativeRegistry.db
				if held == "state pool" {
					db = f.d.state.db
					db.SetMaxOpenConns(1)
				}
				conn, err := db.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				release = func() { conn.Close() }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if held == "canceled" {
				cancel()
			}
			called := false
			start := time.Now()
			token, err := f.d.verifyNativeManagedSubjectTokenContext(ctx, f.captured, "https://example.test", nativeManagedSubjectFromEndpoint(f.command.Subject), func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				called = true
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			release()
			if token != nil || err == nil || called {
				t.Fatalf("failed acquisition reached verifier: token=%v err=%v called=%v", token != nil, err, called)
			}
			if time.Since(start) > time.Second {
				t.Fatal("bounded verifier waited")
			}
			if err := f.verify(context.Background(), nil); err != nil {
				t.Fatalf("failed acquisition leaked lock/connection: %v", err)
			}
		})
	}
}

func TestDirectEndpointVerifierContextSnapshotContention(t *testing.T) {
	for _, held := range []string{"publication", "invalidation index", "subscription owner"} {
		t.Run(held, func(t *testing.T) {
			f := newManagedPrepareVerifierFixture(t)
			p := f.d.nativeWorkers[f.command.Subject.InstanceID.String()].proxy
			owner := &directEndpointSubscriptions{}
			s := owner.add(directEndpointBinding{proxy: p, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
			defer owner.close()
			p.directInvalidations.register(owner)
			release := func() {}
			token, err := f.d.verifyNativeManagedSubjectTokenContext(context.Background(), f.captured, "https://example.test", nativeManagedSubjectFromEndpoint(f.command.Subject), func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				switch held {
				case "publication":
					p.publicationMu.Lock()
					release = p.publicationMu.Unlock
				case "invalidation index":
					p.directInvalidations.mu.Lock()
					release = p.directInvalidations.mu.Unlock
				case "subscription owner":
					owner.mu.Lock()
					release = owner.mu.Unlock
				}
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			release()
			if token != nil || err == nil {
				t.Fatal("snapshot contention accepted as authority")
			}
			if p.directEndpointObserved || p.directEndpointEpoch != 0 {
				t.Fatal("failed snapshot partially mutated lifecycle")
			}
			select {
			case <-s.Done():
				t.Fatal("failed snapshot partially revoked owner")
			default:
			}
			if token, err := f.d.verifyNativeManagedSubjectTokenContext(context.Background(), f.captured, "https://example.test", nativeManagedSubjectFromEndpoint(f.command.Subject), func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			}); err != nil || token == nil {
				t.Fatalf("bounded retry failed: %v", err)
			}
			select {
			case <-s.Done():
			default:
				t.Fatal("successful snapshot failed to invalidate prior admission")
			}
		})
	}
}

func TestDirectEndpointVerifierContextSnapshotRevokes(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	p := f.d.nativeWorkers[f.command.Subject.InstanceID.String()].proxy
	p.observeDirectEndpointSnapshot(f.snapshot, p.directEndpointObservationEpoch())
	owner := &directEndpointSubscriptions{}
	s := owner.add(directEndpointBinding{proxy: p, metadata: DirectEndpointSubscriptionMetadata{Deadline: time.Now().Add(time.Hour)}})
	defer owner.close()
	p.directInvalidations.register(owner)
	snapshot := f.snapshot
	snapshot.NativeGeneration = "changed"
	token, err := f.d.verifyNativeManagedSubjectTokenContext(context.Background(), f.captured, "https://example.test", nativeManagedSubjectFromEndpoint(f.command.Subject), func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		return &sessionworker.NativeOwnershipVerifyResult{Snapshot: snapshot}, nil
	})
	if token != nil || err == nil {
		t.Fatal("stale requested subject accepted")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("new authenticated snapshot failed to revoke")
	}
}

func TestDirectEndpointPublicationFenceContextAcquisition(t *testing.T) {
	for _, held := range []string{"worker map", "ownership", "publication", "connection", "native session", "lane", "state pool", "state writer", "canceled"} {
		t.Run(held, func(t *testing.T) {
			keys, issue, d, token, captured := sourceCredentialAuthorityFixtureV2(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			releaseHeld := func() {}
			switch held {
			case "worker map":
				d.nativeWorkersMu.Lock()
				releaseHeld = d.nativeWorkersMu.Unlock
			case "ownership":
				token.link.mu.Lock()
				releaseHeld = token.link.mu.Unlock
			case "publication":
				token.proxy.publicationMu.Lock()
				releaseHeld = token.proxy.publicationMu.Unlock
			case "connection":
				d.connMu.Lock()
				releaseHeld = d.connMu.Unlock
			case "native session":
				captured.Connection.mu.Lock()
				releaseHeld = captured.Connection.mu.Unlock
			case "lane":
				lane.mu.Lock()
				releaseHeld = lane.mu.Unlock
			case "state pool":
				d.state.db.SetMaxOpenConns(1)
				conn, err := d.state.db.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				releaseHeld = func() { conn.Close() }
			case "state writer":
				var filename string
				if err := d.state.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&filename); err != nil {
					t.Fatal(err)
				}
				other, err := sql.Open("sqlite", filepath.Clean(filename))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := other.Exec("BEGIN IMMEDIATE"); err != nil {
					other.Close()
					t.Fatal(err)
				}
				releaseHeld = func() { _, _ = other.Exec("ROLLBACK"); other.Close() }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if held == "canceled" {
				cancel()
			}
			called := false
			start := time.Now()
			err := withEndpointMaterialLockedContext(ctx, keys.registry, nativeDirectManagedSourceKeyNamespaceV2, func(conn *sql.Conn, _ *os.File, release *func()) error {
				var err error
				*release, err = d.credentialPublicationFenceContext(ctx, token, captured, lane, token.subject, true, directManagedSourceCredentialProtocolV2, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.BudgetExpiresAt)(conn, "https://example.test", captured.Session)
				if err == nil {
					called = true
				}
				return err
			})
			releaseHeld()
			if err == nil || called {
				t.Fatal("failed fence acquisition allowed use")
			}
			if time.Since(start) > time.Second {
				t.Fatal("bounded fence waited")
			}
			for _, mu := range []*sync.Mutex{&d.nativeWorkersMu, &token.link.mu, &d.connMu, &captured.Connection.mu, &lane.mu} {
				if !mu.TryLock() {
					t.Fatal("fence leaked lock")
				}
				mu.Unlock()
			}
			if !token.proxy.publicationMu.TryLock() {
				t.Fatal("fence leaked publication lock")
			}
			token.proxy.publicationMu.Unlock()
			if _, err := d.state.db.Exec("BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			if _, err := d.state.db.Exec("ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectEndpointPublicationFenceContextCleanup(t *testing.T) {
	for _, failure := range []string{"canceled", "ROLLBACK", "PRAGMA busy_timeout=1234"} {
		t.Run(failure, func(t *testing.T) {
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
			if _, err := d.state.db.Exec("PRAGMA busy_timeout=1234"); err != nil {
				t.Fatal(err)
			}
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if query == "ROLLBACK" || query == "PRAGMA busy_timeout=1234" {
					if ctx.Err() != nil {
						t.Error("cleanup inherited canceled request")
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Error("cleanup has no deadline")
					}
					if d.nativeWorkersMu.TryLock() {
						d.nativeWorkersMu.Unlock()
						t.Error("authority unlocked before SQL cleanup")
					}
				}
				if query == failure {
					return nil, errors.New("injected cleanup failure")
				}
				return next.ExecContext(ctx, query, args)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			acquired := false
			err := withEndpointMaterialLockedContext(ctx, keys.registry, nativeDirectManagedSourceKeyNamespaceV2, func(conn *sql.Conn, _ *os.File, release *func()) error {
				var err error
				*release, err = d.credentialPublicationFenceContext(ctx, token, captured, newDirectManagedSourceCredentialPublicationLane(), token.subject, true, directManagedSourceCredentialProtocolV2, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.BudgetExpiresAt)(conn, "https://example.test", captured.Session)
				if err != nil {
					return err
				}
				acquired = true
				cancel()
				return nil
			})
			connector.exec = nil
			if !acquired || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled fence transaction: %v", err)
			}
			if failure != "canceled" && connector.closed.Load() != 1 {
				t.Fatal("uncertain state connection returned to pool")
			}
			if failure == "canceled" {
				var timeout int
				if err := d.state.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 1234 {
					t.Fatalf("timeout not restored: %d %v", timeout, err)
				}
			}
			if !d.nativeWorkersMu.TryLock() {
				t.Fatal("cleanup leaked authority lock")
			}
			d.nativeWorkersMu.Unlock()
			if _, err := d.state.db.Exec("BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			if _, err := d.state.db.Exec("ROLLBACK"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
