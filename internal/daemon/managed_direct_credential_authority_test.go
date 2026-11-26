//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func managedCredentialAuthorityFixture(t *testing.T) (*ManagedEndpointKeyStore, transport.ManagedDirectCredentialIssue, *Daemon, *nativeWorkerPublicationToken, ManagedEndpointPrepareScope) {
	t.Helper()
	keys, issue, session, _ := managedCredentialStoreFixture(t)
	s := issue.PoP.Prepare.Subject
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol, transport.NativeWorkerOwnershipProtocol}
	scope := sessionworker.Scope{ServerURL: "https://example.test", TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: s.InstanceID.String(), Generation: s.OwnershipGeneration}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeQwenCode, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: domain.NewID().String()}
	record, err := keys.registry.Reserve(scope, spec, "custom-qwen", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: s.OwnershipID.String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), Profile: record.Profile, ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: domain.NewID().String(), State: "active"}
	if err := keys.registry.BindOwnership(record, ownership); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.registry.db.Exec(`UPDATE native_workers SET launch_state='launched' WHERE instance_id=?`, scope.InstanceID); err != nil {
		t.Fatal(err)
	}
	state, err := OpenState(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), Profile: record.Profile, AgentPrincipalID: s.PrincipalID.String()}); err != nil {
		t.Fatal(err)
	}
	native := NewNativeObservationConnection(scope.ServerURL, scope.HostID, session.BootID, nil)
	if err := native.Admit(session); err != nil {
		t.Fatal(err)
	}
	socket := &websocket.Conn{}
	proxy := &NativeWorkerProxy{connection: native, scope: scope, profile: record.ProfileFingerprint, bootstrap: sessionworker.Bootstrap{Native: spec}, done: make(chan struct{}), abortDone: make(chan struct{})}
	link := &nativeWorkerLink{conn: socket, proxy: proxy, ownership: ownership}
	d := &Daemon{Config: Config{ServerURL: "https://example.test"}, state: state, nativeRegistry: keys.registry, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: link}, curConn: socket, nativeConn: native}
	token := &nativeWorkerPublicationToken{instanceID: scope.InstanceID, link: link, proxy: proxy, ownership: ownership, subject: nativeManagedSubjectFromEndpoint(s)}
	return keys, issue, d, token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}
}

func TestManagedCredentialAuthorityRejectsMutations(t *testing.T) {
	for _, mutation := range []string{"principal", "profile", "launch", "recovery", "gc", "link", "ownership", "session", "feature", "socket", "token", "cancel", "contention", "state writer", "state pool", "future", "lane contention", "worker closed", "native closed", "configured scope", "installation", "generation", "install deadline"} {
		t.Run(mutation, func(t *testing.T) {
			keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			var err error
			switch mutation {
			case "worker closed":
				close(token.proxy.done)
			case "native closed":
				captured.Connection.Close()
			case "configured scope":
				d.ServerURL = "https://untrusted.test"
			case "installation":
				issue.PoP.ACK.Reservation.InstallationID = domain.NewID()
			case "generation":
				issue.ChannelGeneration = 2
			case "install deadline":
				keys.now = func() time.Time { return issue.InstallExpiresAt }
			case "principal":
				_, err = d.state.db.Exec(`UPDATE instances SET agent_principal_id='changed'`)
			case "profile":
				_, err = d.state.db.Exec(`UPDATE instances SET profile='changed'`)
			case "launch":
				_, err = keys.registry.db.Exec(`UPDATE native_workers SET launch_state='reserved'`)
			case "recovery":
				_, err = keys.registry.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES('test',?,?,'test','prepared')`, token.instanceID, token.ownership.OwnershipGeneration)
			case "gc":
				_, err = keys.registry.db.Exec(`INSERT INTO native_worker_gc(instance_id,payload) VALUES(?, '{}')`, token.instanceID)
			case "link":
				d.nativeWorkers[token.instanceID] = &nativeWorkerLink{}
			case "ownership":
				token.link.ownership.State = "retired"
			case "session":
				captured.Connection.session.BootID = "changed"
			case "feature":
				captured.Session.ProtocolFeatures = captured.Session.ProtocolFeatures[:1]
				captured.Connection.session = &captured.Session
			case "socket":
				d.curConn = &websocket.Conn{}
			case "token":
				token.subject.NativeSessionID += "changed"
			case "cancel":
				lane.cancel()
			case "future":
				issue.IssuedAt = time.Now().Add(time.Minute)
			case "state writer":
				blocker, blockErr := d.state.db.Conn(context.Background())
				if blockErr != nil {
					t.Fatal(blockErr)
				}
				defer blocker.Close()
				if _, blockErr = blocker.ExecContext(context.Background(), "BEGIN IMMEDIATE"); blockErr != nil {
					t.Fatal(blockErr)
				}
				defer blocker.ExecContext(context.Background(), "ROLLBACK")
			case "state pool":
				d.state.db.SetMaxOpenConns(1)
				blocker, blockErr := d.state.db.Conn(context.Background())
				if blockErr != nil {
					t.Fatal(blockErr)
				}
				defer blocker.Close()
			case "lane contention":
				lane.mu.Lock()
				defer lane.mu.Unlock()
			case "contention":
				d.connMu.Lock()
				defer d.connMu.Unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = keys.InstallCredential(issue, "https://example.test", captured.Session, managedCredentialScopeOK, d.managedDirectCredentialPublicationFence(token, captured, lane))
			if err == nil {
				t.Fatal("changed authority published")
			}
			var n int
			if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_managed_direct_v1_credentials WHERE state='installed'`).Scan(&n); err != nil || n != 0 {
				t.Fatal("publication escaped fence", n, err)
			}
		})
	}
}

func TestManagedCredentialAuthorityHoldsUntilTransactionCompletion(t *testing.T) {
	for _, mode := range []string{"commit", "rollback", "panic"} {
		t.Run(mode, func(t *testing.T) {
			keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
			lane := newDirectManagedSourceCredentialPublicationLane()
			fence := d.managedDirectCredentialPublicationFence(token, captured, lane)
			entered := false
			mutationDone := make(chan string, 1)
			cancelStarted, cancelDone := make(chan struct{}), make(chan struct{})
			func() {
				defer func() {
					if r := recover(); r != nil && mode != "panic" {
						panic(r)
					}
				}()
				err := keys.withCredentialLockedScoped(func(conn *sql.Conn, _ *os.File, release *func()) error {
					var err error
					*release, err = fence(conn, issue, "https://example.test", captured.Session)
					if err != nil {
						return err
					}
					entered = true
					go func() {
						close(cancelStarted)
						lane.cancel()
						close(cancelDone)
					}()
					<-cancelStarted
					select {
					case <-cancelDone:
						t.Error("cancellation completed during transaction")
					default:
					}
					select {
					case <-lane.done:
						t.Error("cancellation revoked acquired publication")
					default:
					}

					if _, err := conn.ExecContext(context.Background(), `UPDATE native_workers SET launch_state='launching' WHERE instance_id=?`, token.instanceID); err != nil {
						return err
					}
					started := make(chan struct{})
					go func() {
						close(started)
						d.nativeWorkersMu.Lock()
						token.link.mu.Lock()
						token.link.ownership.State = "retired"
						token.link.mu.Unlock()
						d.nativeWorkersMu.Unlock()
						var launch string
						if err := keys.registry.db.QueryRow(`SELECT launch_state FROM native_workers WHERE instance_id=?`, token.instanceID).Scan(&launch); err != nil {
							launch = err.Error()
						}
						mutationDone <- launch
					}()
					<-started
					select {
					case <-mutationDone:
						t.Error("concurrent mutation escaped transaction")
					default:
					}
					for _, lock := range []interface {
						TryLock() bool
						Unlock()
					}{&d.nativeWorkersMu, &token.link.mu, &token.proxy.publicationMu, &d.connMu, &captured.Connection.mu, &lane.mu} {
						if lock.TryLock() {
							lock.Unlock()
							t.Error("publication mutation not fenced")
						}
					}
					other, err := d.state.db.Conn(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close()
					_, _ = other.ExecContext(context.Background(), "PRAGMA busy_timeout=0")
					if _, err := other.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err == nil {
						_, _ = other.ExecContext(context.Background(), "ROLLBACK")
						t.Error("state mutation not fenced")
					}
					if mode == "panic" {
						panic("publication panic")
					}
					if mode == "rollback" {
						return errors.New("rollback")
					}
					return nil
				})
				if mode == "commit" && err != nil {
					t.Fatal(err)
				}
			}()
			if !entered {
				t.Fatal("guard never acquired")
			}
			<-cancelDone
			wantLaunch := "launched"
			if mode == "commit" {
				wantLaunch = "launching"
			}
			if launch := <-mutationDone; launch != wantLaunch {
				t.Fatalf("mutation observed %q, want transaction result %q", launch, wantLaunch)
			}
			for _, lock := range []*sync.Mutex{&d.nativeWorkersMu, &token.link.mu, &d.connMu, &captured.Connection.mu, &lane.mu} {
				if !lock.TryLock() {
					t.Fatal("lock leaked")
				}
				lock.Unlock()
			}
			if !token.proxy.publicationMu.TryLock() {
				t.Fatal("proxy lock leaked")
			}
			token.proxy.publicationMu.Unlock()
			if _, err := d.state.db.Exec(`UPDATE instances SET profile=profile`); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.registry.db.Exec(`UPDATE native_workers SET launch_state=launch_state`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedCredentialAuthorityCompletedCancellationRejectsAcquisition(t *testing.T) {
	keys, issue, d, token, captured := managedCredentialAuthorityFixture(t)
	lane := newDirectManagedSourceCredentialPublicationLane()
	fence := d.managedDirectCredentialPublicationFence(token, captured, lane)
	acquire := func() error {
		return keys.withCredentialLockedScoped(func(conn *sql.Conn, _ *os.File, release *func()) error {
			var err error
			*release, err = fence(conn, issue, "https://example.test", captured.Session)
			return err
		})
	}
	if err := acquire(); err != nil {
		t.Fatal(err)
	}
	lane.cancel()
	lane.cancel()
	if err := acquire(); !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
		t.Fatalf("completed cancellation returned %v", err)
	}
}
