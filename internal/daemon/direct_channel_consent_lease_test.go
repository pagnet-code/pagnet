//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
)

type consentLeaseFixture struct {
	d        *Daemon
	store    *directChannelConsentStore
	sub      *DirectEndpointSubscription
	captured ManagedEndpointPrepareScope
	evidence directEndpointReconcileBinding
	binding  directChannelConsentBinding
}

func newConsentLeaseFixture(t *testing.T) consentLeaseFixture {
	t.Helper()
	base, _ := consentFixture(t)
	old, captured, _, evidence, now := consentBindingFixture(t, "S")
	store, err := newDirectChannelConsentStore(t.Context(), base.registry, old.binding.metadata.ServerOrigin, captured.Session)
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{nativeRegistry: store.registry}
	b := old.binding
	b.metadata.InstallationID = domain.ID(store.installation)
	sub := d.directSubscriptions.add(b)
	t.Cleanup(d.directSubscriptions.close)
	binding, err := deriveDirectChannelConsentBinding(sub, captured, store.installation, evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Enable(t.Context(), binding, 0, "enable"); err != nil {
		t.Fatal(err)
	}
	return consentLeaseFixture{d, store, sub, captured, evidence, binding}
}

func (f consentLeaseFixture) register(ctx context.Context, sub *DirectEndpointSubscription, revision int64) error {
	return f.d.registerDirectChannelConsentLease(ctx, f.store, f.binding.Key, revision, sub, f.captured, f.evidence)
}

func TestDirectConsentLeaseMutation(t *testing.T) {
	for _, operation := range []string{"disable", "replace"} {
		t.Run(operation, func(t *testing.T) {
			f := newConsentLeaseFixture(t)
			if err := f.register(t.Context(), f.sub, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Enable(t.Context(), f.binding, 0, "enable"); err != nil || !f.sub.Valid() {
				t.Fatal("exact replay revoked lease", err)
			}
			if _, err := f.store.Disable(t.Context(), f.binding.Key, 0, "stale"); err == nil || !f.sub.Valid() {
				t.Fatal("stale mutation affected lease", err)
			}
			if operation == "disable" {
				if _, err := f.store.Disable(t.Context(), f.binding.Key, 1, "disable"); err != nil {
					t.Fatal(err)
				}
			} else {
				replacement := f.binding
				replacement.Epoch += "-replacement"
				if _, err := f.store.Enable(t.Context(), replacement, 1, "replace"); err != nil {
					t.Fatal(err)
				}
			}
			if f.sub.Valid() {
				t.Fatal("mutation retained old lease")
			}
			if err := f.register(t.Context(), f.sub, 1); err == nil {
				t.Fatal("old revision registered")
			}
		})
	}
}

func TestDirectConsentLeaseSharedStoresAndExactHandle(t *testing.T) {
	f := newConsentLeaseFixture(t)
	if err := f.register(t.Context(), f.sub, 1); err != nil {
		t.Fatal(err)
	}
	next := f.d.directSubscriptions.add(f.sub.binding)
	if err := f.register(t.Context(), next, 1); err != nil {
		t.Fatal(err)
	}
	f.sub.Remove()
	if !next.Valid() {
		t.Fatal("old handle removed replacement")
	}
	peer, err := newDirectChannelConsentStore(t.Context(), f.store.registry, f.store.server, f.captured.Session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = peer.Disable(t.Context(), f.binding.Key, 1, "disable"); err != nil {
		t.Fatal(err)
	}
	if next.Valid() {
		t.Fatal("peer store did not revoke replacement")
	}
}

func TestDirectConsentLeaseRegisterAgainstDisable(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newConsentLeaseFixture(t)
		start := make(chan struct{})
		registered := make(chan error, 1)
		disabled := make(chan error, 1)
		go func() { <-start; registered <- f.register(context.Background(), f.sub, 1) }()
		go func() {
			<-start
			_, err := f.store.Disable(context.Background(), f.binding.Key, 1, "disable")
			disabled <- err
		}()
		close(start)
		registerErr := <-registered
		disableErr := <-disabled
		if errors.Is(disableErr, errDirectEndpointLocalBusy) {
			_, disableErr = f.store.Disable(t.Context(), f.binding.Key, 1, "disable")
		}
		if disableErr != nil {
			t.Fatal(disableErr)
		}
		if registerErr == nil && f.sub.Valid() {
			t.Fatal("registered subscription survived disable")
		}
		if f.sub.Valid() {
			// If disable won, registration was rejected and did not acquire a lease.
			key := directChannelConsentLeaseKey{f.store.installation, f.binding.Key}
			f.store.registry.mu.Lock()
			count := len(f.store.registry.directConsentLeases[key])
			f.store.registry.mu.Unlock()
			if count != 0 {
				t.Fatal("lease survived disable")
			}
		}
		if err := f.register(t.Context(), f.sub, 1); err == nil {
			t.Fatal("disabled consent registered")
		}
	}
}

func TestDirectConsentLeaseRejectsForeignAndStale(t *testing.T) {
	for _, kind := range []string{"daemon", "registry", "revision", "removed", "binding", "installation", "aborted"} {
		t.Run(kind, func(t *testing.T) {
			f := newConsentLeaseFixture(t)
			revision := int64(1)
			switch kind {
			case "daemon":
				f.d = &Daemon{nativeRegistry: f.store.registry}
			case "registry":
				f.d.nativeRegistry = &NativeWorkerRegistry{}
			case "revision":
				revision++
			case "removed":
				f.sub.Remove()
			case "binding":
				f.evidence.Authority.EpochID += "-foreign"
			case "installation":
				f.sub.binding.metadata.InstallationID = "foreign"
			case "aborted":
				f.sub.binding.proxy = &NativeWorkerProxy{abortDone: make(chan struct{})}
				close(f.sub.binding.proxy.abortDone)
			}
			if err := f.register(t.Context(), f.sub, revision); err == nil {
				t.Fatal("ineligible lease accepted")
			}
		})
	}
}

func TestDirectConsentLeaseUncertainCompletion(t *testing.T) {
	for _, operation := range []string{"COMMIT", "ROLLBACK"} {
		t.Run(operation, func(t *testing.T) {
			f := newConsentLeaseFixture(t)
			if err := f.register(t.Context(), f.sub, 1); err != nil {
				t.Fatal(err)
			}
			err := f.store.locked(t.Context(), func(c *sql.Conn) error {
				_, err := c.ExecContext(t.Context(), operation)
				return err
			})
			if err == nil || f.sub.Valid() {
				t.Fatal("uncertain completion retained lease", err)
			}
		})
	}
}

func TestDirectConsentLeaseFailedWriteCompletion(t *testing.T) {
	f := newConsentLeaseFixture(t)
	if err := f.register(t.Context(), f.sub, 1); err != nil {
		t.Fatal(err)
	}
	// A deferred foreign key violation fails COMMIT after the mutation ran.
	if _, err := f.store.registry.db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.registry.db.Exec(`CREATE TABLE consent_test_parent(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.registry.db.Exec(`CREATE TABLE consent_test_child(id INTEGER REFERENCES consent_test_parent(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	err := f.store.locked(t.Context(), func(c *sql.Conn) error {
		_, err := c.ExecContext(t.Context(), `INSERT INTO consent_test_child VALUES(1)`)
		return err
	})
	if err == nil || f.sub.Valid() {
		t.Fatal("failed commit retained lease", err)
	}
}

func TestDirectConsentLeaseCancelledRegistration(t *testing.T) {
	f := newConsentLeaseFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.register(ctx, f.sub, 1); err == nil {
		t.Fatal("cancelled registration accepted")
	}
	if len(f.store.registry.directConsentLeases) != 0 {
		t.Fatal("cancelled lease retained")
	}
}

func TestDirectConsentLeaseNewRevisionSurvivesStaleMutation(t *testing.T) {
	f := newConsentLeaseFixture(t)
	if err := f.register(t.Context(), f.sub, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Enable(t.Context(), f.binding, 1, "new-enable"); err != nil {
		t.Fatal(err)
	}
	next := f.d.directSubscriptions.add(f.sub.binding)
	if err := f.register(t.Context(), next, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Disable(t.Context(), f.binding.Key, 1, "stale-disable"); err == nil {
		t.Fatal("stale disable succeeded")
	}
	if _, err := f.store.Enable(t.Context(), f.binding, 1, "new-enable"); err != nil {
		t.Fatal(err)
	}
	if !next.Valid() {
		t.Fatal("stale mutation or exact replay revoked new lease")
	}
	if revision := f.store.registry.directConsentLeases[directChannelConsentLeaseKey{f.store.installation, f.binding.Key}][next]; revision != 2 {
		t.Fatal("wrong indexed revision", revision)
	}
}

func TestDirectConsentLeaseRegistrationCleanup(t *testing.T) {
	for _, kind := range []string{"cancel", "panic"} {
		t.Run(kind, func(t *testing.T) {
			f := newConsentLeaseFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			registered := false
			cleanup := func(err error) {
				if registered && err != nil {
					f.sub.Remove()
				}
			}
			invoke := func() (err error) {
				defer func() {
					if recovered := recover(); recovered != nil {
						err = errDirectChannelConsent
					}
				}()
				return f.store.lockedCompletion(ctx, func(*sql.Conn) error {
					registered = true
					if kind == "panic" {
						panic("interrupted registration")
					}
					cancel()
					return nil
				}, cleanup)
			}
			if err := invoke(); err == nil || f.sub.Valid() {
				t.Fatal("failed registration retained subscription", err)
			}
		})
	}
}
