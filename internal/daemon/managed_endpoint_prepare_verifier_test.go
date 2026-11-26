//go:build linux || darwin

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type managedPrepareVerifierFixture struct {
	d        *Daemon
	captured ManagedEndpointPrepareScope
	command  transport.ManagedEndpointPrepareCommand
	snapshot sessionworker.NativeSnapshot
}

func newManagedPrepareVerifierFixture(t *testing.T) *managedPrepareVerifierFixture {
	t.Helper()
	return newManagedPrepareVerifierFixtureForServer(t, "https://example.test")
}

func newManagedPrepareVerifierFixtureForServer(t *testing.T, server string) *managedPrepareVerifierFixture {
	t.Helper()
	keys, subject, session := managedEndpointFixture(t)
	session.ProtocolFeatures = []string{transport.NativeObservationReceiptProtocol}
	scope := sessionworker.Scope{ServerURL: server, TenantID: session.TenantID, AccountID: session.AccountID, HostID: session.HostID, InstanceID: subject.InstanceID.String(), Generation: subject.OwnershipGeneration}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeQwenCode, Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkTenantID: scope.TenantID, NetworkID: domain.NewID().String()}
	record, err := keys.registry.Reserve(scope, spec, "custom-qwen", "")
	if err != nil {
		t.Fatal(err)
	}
	ownership := transport.NativeWorkerOwnership{ID: subject.OwnershipID.String(), InstanceID: scope.InstanceID, OwnershipGeneration: scope.Generation, Runtime: string(spec.Runtime), Profile: record.Profile, ProfileFingerprint: record.ProfileFingerprint, OriginalAdmissionID: domain.NewID().String(), State: "active"}
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
	if err := state.UpsertInstance(InstanceRow{InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), Profile: record.Profile, AgentPrincipalID: subject.PrincipalID.String()}); err != nil {
		t.Fatal(err)
	}
	c := NewNativeObservationConnection(scope.ServerURL, scope.HostID, session.BootID, nil)
	if err := c.Admit(session); err != nil {
		t.Fatal(err)
	}
	socket := &websocket.Conn{}
	p := &NativeWorkerProxy{connection: c, scope: scope, profile: record.ProfileFingerprint, bootstrap: sessionworker.Bootstrap{Native: spec}, done: make(chan struct{}), abortDone: make(chan struct{})}
	d := &Daemon{state: state, nativeRegistry: keys.registry, nativeWorkers: map[string]*nativeWorkerLink{scope.InstanceID: {conn: socket, proxy: p, ownership: ownership}}}
	start, err := proc.StartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	// The origin belongs to an older admission, which is allowed after reconnect.
	origin, _ := json.Marshal(transport.NativeObservationOrigin{ID: subject.OriginID.String(), TenantID: scope.TenantID, HostID: scope.HostID, InstanceID: scope.InstanceID, Runtime: string(spec.Runtime), NativeGeneration: subject.NativeGeneration, NativeSessionID: subject.NativeSessionID, NativeAdmissionID: domain.NewID().String()})
	return &managedPrepareVerifierFixture{d: d, captured: ManagedEndpointPrepareScope{Socket: socket, Connection: c, Session: session}, command: transport.ManagedEndpointPrepareCommand{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: domain.NewID(), Subject: subject}, snapshot: sessionworker.NativeSnapshot{Scope: scope, ActualRuntime: spec.Runtime, ProfileFingerprint: record.ProfileFingerprint, PID: os.Getpid(), NativeStartIdentity: start, NativeGeneration: subject.NativeGeneration, NativeSessionID: subject.NativeSessionID, Origin: origin}}
}
func (f *managedPrepareVerifierFixture) verify(ctx context.Context, hook func()) error {
	return f.d.verifyManagedEndpointPrepare(ctx, f.captured, "https://example.test", f.command, func(_ context.Context, _ *NativeWorkerProxy, o transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		if o.ID != f.command.Subject.OwnershipID.String() {
			return nil, ErrManagedEndpointPrepareRejected
		}
		if hook != nil {
			hook()
		}
		return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
	})
}
func TestManagedPrepareVerifierExactAuthorityAndSurvivingReconnect(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	if err := f.verify(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	// Endpoint ID remains server subject data and has no fabricated local mapping.
	f.command.Subject.EndpointID = domain.NewID()
	if err := f.verify(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}
func TestManagedPrepareVerifierRejectsMismatches(t *testing.T) {
	tests := map[string]func(*managedPrepareVerifierFixture){
		"tenant":            func(f *managedPrepareVerifierFixture) { f.command.Subject.TenantID = domain.NewID() },
		"personal scope":    func(f *managedPrepareVerifierFixture) { f.captured.Session.OwnershipScope = "organization" },
		"native generation": func(f *managedPrepareVerifierFixture) { f.command.Subject.NativeGeneration = "other" },
		"profile":           func(f *managedPrepareVerifierFixture) { f.snapshot.ProfileFingerprint = "other" },
		"principal":         func(f *managedPrepareVerifierFixture) { f.command.Subject.PrincipalID = domain.NewID() },
		"account":           func(f *managedPrepareVerifierFixture) { f.command.Subject.AccountID = domain.NewID() },
		"credential":        func(f *managedPrepareVerifierFixture) { f.command.Subject.HostCredentialID = domain.NewID() },
		"admission": func(f *managedPrepareVerifierFixture) {
			f.command.Subject.NativeAdmissionID = domain.NewID()
			f.command.Subject.ConnectionIncarnationID = f.command.Subject.NativeAdmissionID
		},
		"incarnation": func(f *managedPrepareVerifierFixture) { f.command.Subject.ConnectionIncarnationID = domain.NewID() },
		"runner":      func(f *managedPrepareVerifierFixture) { f.command.Subject.RunnerID = domain.NewID() },
		"epoch": func(f *managedPrepareVerifierFixture) {
			f.command.Subject.RunnerConnectedAt = f.command.Subject.RunnerConnectedAt.Add(1)
		},
		"boot":           func(f *managedPrepareVerifierFixture) { f.command.Subject.BootID = "other" },
		"captured scope": func(f *managedPrepareVerifierFixture) { f.captured.Session.TenantID = domain.NewID().String() },
		"ownership":      func(f *managedPrepareVerifierFixture) { f.command.Subject.OwnershipID = domain.NewID() },
		"generation":     func(f *managedPrepareVerifierFixture) { f.command.Subject.OwnershipGeneration = "other" },
		"session":        func(f *managedPrepareVerifierFixture) { f.snapshot.NativeSessionID = "other" },
		"origin":         func(f *managedPrepareVerifierFixture) { f.command.Subject.OriginID = domain.NewID() },
		"dead worker":    func(f *managedPrepareVerifierFixture) { f.snapshot.PID = -1 },
		"pid reuse":      func(f *managedPrepareVerifierFixture) { f.snapshot.NativeStartIdentity = "other" },
		"runtime":        func(f *managedPrepareVerifierFixture) { f.snapshot.ActualRuntime = domain.RuntimeFakePersistent },
		"retirement": func(f *managedPrepareVerifierFixture) {
			f.d.nativeWorkers[f.command.Subject.InstanceID.String()].ownership.State = "retired"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newManagedPrepareVerifierFixture(t)
			mutate(f)
			if err := f.verify(t.Context(), nil); !errors.Is(err, ErrManagedEndpointPrepareRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestManagedPrepareVerifierFencesInFlightChanges(t *testing.T) {
	for _, kind := range []string{"link", "proxy", "reconnect", "scope", "local scope", "retirement", "ownership", "generation", "recovery", "gc"} {
		t.Run(kind, func(t *testing.T) {
			f := newManagedPrepareVerifierFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			go func() { result <- f.verify(t.Context(), func() { close(entered); <-release }) }()
			<-entered
			id := f.command.Subject.InstanceID.String()
			switch kind {
			case "link":
				f.d.nativeWorkersMu.Lock()
				old := f.d.nativeWorkers[id]
				f.d.nativeWorkers[id] = &nativeWorkerLink{proxy: old.proxy, conn: old.conn, ownership: old.ownership}
				f.d.nativeWorkersMu.Unlock()
			case "proxy":
				f.d.nativeWorkersMu.Lock()
				old := f.d.nativeWorkers[id]
				replacement := &NativeWorkerProxy{connection: old.proxy.connection, scope: old.proxy.scope, profile: old.proxy.profile, bootstrap: old.proxy.bootstrap, done: make(chan struct{}), abortDone: make(chan struct{})}
				f.d.nativeWorkers[id] = &nativeWorkerLink{proxy: replacement, conn: old.conn, ownership: old.ownership}
				f.d.nativeWorkersMu.Unlock()
			case "local scope":
				f.d.nativeWorkers[id].proxy.scope.Generation = "other"
			case "reconnect":
				f.captured.Connection.mu.Lock()
				f.captured.Connection.session.NativeAdmissionID = domain.NewID().String()
				f.captured.Connection.mu.Unlock()
			case "scope":
				f.captured.Connection.mu.Lock()
				f.captured.Connection.session.AccountID = domain.NewID().String()
				f.captured.Connection.mu.Unlock()
			case "retirement":
				link := f.d.nativeWorkers[id]
				link.mu.Lock()
				link.ownership.State = "retired"
				link.mu.Unlock()
			case "ownership", "generation":
				link := f.d.nativeWorkers[id]
				link.mu.Lock()
				if kind == "ownership" {
					link.ownership.ID = domain.NewID().String()
				} else {
					link.ownership.OwnershipGeneration = "other"
				}
				link.mu.Unlock()
			case "recovery":
				_, err := f.d.nativeRegistry.db.Exec(`INSERT INTO native_worker_recoveries(recovery_id,instance_id,original_generation,prepare_boot_identity,phase) VALUES(?,?,?,?,?)`, domain.NewID().String(), id, f.command.Subject.OwnershipGeneration, "boot", "prepared")
				if err != nil {
					t.Fatal(err)
				}
			case "gc":
				raw, _ := json.Marshal(nativeWorkerGC{Ownership: f.d.nativeWorkers[id].ownership})
				if _, err := f.d.nativeRegistry.db.Exec(`INSERT INTO native_worker_gc(instance_id,payload) VALUES(?,?)`, id, raw); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			err := <-result
			expected := ErrManagedEndpointPrepareRejected
			if kind == "link" || kind == "proxy" {
				expected = ErrManagedEndpointPrepareRetryable
			}
			if !errors.Is(err, expected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestManagedPrepareVerifierUnavailableSocketAndRPC(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	f.captured.Socket = &websocket.Conn{}
	if err := f.verify(t.Context(), nil); !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
		t.Fatal(err)
	}
	f = newManagedPrepareVerifierFixture(t)
	for _, rpcErr := range []error{context.DeadlineExceeded, errors.New("connection reset"), errors.New(sessionworker.ErrConflict.Error())} {
		err := f.d.verifyManagedEndpointPrepare(t.Context(), f.captured, "https://example.test", f.command, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
			return nil, rpcErr
		})
		expected := ErrManagedEndpointPrepareRetryable
		if rpcErr.Error() == sessionworker.ErrConflict.Error() {
			expected = ErrManagedEndpointPrepareRejected
		}
		if !errors.Is(err, expected) {
			t.Fatal(err)
		}
	}
}

func TestManagedPrepareVerifierCounterDriftAndClosedWorker(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	link := f.d.nativeWorkers[f.command.Subject.InstanceID.String()]
	link.ownership.LastDispatchSequence = 4
	if err := f.verify(t.Context(), func() {
		link.mu.Lock()
		link.ownership.LastDispatchSequence++
		link.ownership.RetiredFloor++
		link.mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}
	close(link.proxy.done)
	if err := f.verify(t.Context(), nil); !errors.Is(err, ErrManagedEndpointPrepareRetryable) {
		t.Fatal(err)
	}
}

func TestManagedPrepareVerifierServerOriginComparisons(t *testing.T) {
	for _, test := range []struct {
		name, stored, configured string
		accepted                 bool
	}{
		{"uppercase stored host", "https://EXAMPLE.TEST", "https://example.test", true},
		{"stored trailing slashes", "https://example.test///", "https://example.test", true},
		{"configured equivalent", "https://example.test", "https://EXAMPLE.TEST///", true},
		{"same noncanonical configuration", "https://EXAMPLE.TEST///", "https://EXAMPLE.TEST///", true},
		{"escaped stored slash vs decoded slash", "https://example.test/a%2Fb/", "https://example.test/a/b", false},
		{"escaped configured slash vs decoded slash", "https://example.test/a/b", "https://example.test/a%2Fb/", false},
		{"escaped trailing slash vs literal slash", "https://example.test/a%2F", "https://example.test/a/", false},
		{"same escaped path", "https://EXAMPLE.TEST/a%2Fb/", "https://example.test/a%2Fb", true},
		{"same literal path", "https://EXAMPLE.TEST/a/b///", "https://example.test/a/b", true},
		{"empty fragment delimiter", "https://example.test", "https://example.test#", false},
		{"uppercase IPv6 zone", "https://example.test", "https://[fe80::1%25ETH0]", false},
		{"lowercase IPv6 zone", "https://example.test", "https://[fe80::1%25eth0]", false},
		{"unscoped IPv6", "https://[2001:DB8::1]///", "https://[2001:db8::1]", true},
		{"different host", "https://example.test", "https://other.test", false},
		{"different scheme", "https://example.test", "http://example.test", false},
		{"different path", "https://example.test", "https://example.test/other", false},
		{"different port", "https://example.test", "https://example.test:8443", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newManagedPrepareVerifierFixtureForServer(t, test.stored)
			before, err := f.d.nativeRegistry.Lookup(f.command.Subject.InstanceID.String())
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = f.d.verifyManagedEndpointPrepare(t.Context(), f.captured, test.configured, f.command, func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
				called = true
				return &sessionworker.NativeOwnershipVerifyResult{Snapshot: f.snapshot}, nil
			})
			if test.accepted {
				if err != nil || !called {
					t.Fatalf("equivalent origin rejected: called=%v err=%v", called, err)
				}
			} else if !errors.Is(err, ErrManagedEndpointPrepareRejected) || called {
				t.Fatalf("different origin reached owner: called=%v err=%v", called, err)
			}
			after, err := f.d.nativeRegistry.Lookup(f.command.Subject.InstanceID.String())
			if err != nil {
				t.Fatal(err)
			}
			p := f.d.nativeWorkers[f.command.Subject.InstanceID.String()].proxy
			if before.Scope != after.Scope || p.scope != before.Scope || f.snapshot.Scope != before.Scope || f.captured.Connection.serverURL != test.stored {
				t.Fatal("origin comparison modified stored scope identity")
			}
		})
	}
}

func TestManagedPrepareVerifierRejectsUnsafeStoredOrigins(t *testing.T) {
	for _, server := range []string{"https://example.test?", "https://example.test#", "https://example.test?query=value", "https://example.test#fragment", "https://user@example.test", "https://[fe80::1%25ETH0]", "https://[fe80::1%25eth0]", "https://example.test/%zz", "ftp://example.test", "/relative"} {
		t.Run(server, func(t *testing.T) {
			if got := managedPrepareServerOrigin(server); got != "" {
				t.Fatalf("unsafe origin accepted as %q", got)
			}
		})
	}
}

func TestManagedPrepareServerOriginMatchesTextServiceServer(t *testing.T) {
	for _, server := range []string{" https://EXAMPLE.TEST/a%2Fb/// ", "https://example.test/a%2F", "https://example.test/%61/", "https://example.test/a%2fb///", "https://example.test/a/b///", "https://EXAMPLE.TEST///", "HTTP://EXAMPLE.TEST/path/", "https://example.test/a b/"} {
		t.Run(server, func(t *testing.T) {
			want := textServiceServer(server)
			if got := managedPrepareServerOrigin(server); want == "" || got != want {
				t.Fatalf("managed prepare origin = %q, want text service origin %q", got, want)
			}
		})
	}
}
