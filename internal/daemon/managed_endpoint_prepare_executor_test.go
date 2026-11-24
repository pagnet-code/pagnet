//go:build linux || darwin

package daemon

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedPrepareExecutorCrashRecovery(t *testing.T) {
	for _, crash := range []string{"before_start", "after_start", "after_key", "terminal"} {
		t.Run(crash, func(t *testing.T) {
			journal, keys, command, session := managedPrepareJournalFixture(t)
			endpoint := "https://example.test"
			if _, err := journal.Reserve(command, endpoint, managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			if crash != "before_start" {
				if _, err := journal.BeginKeyReservation(command, endpoint, managedPrepareScopeOK); err != nil {
					t.Fatal(err)
				}
			}
			var original []byte
			if crash == "after_key" || crash == "terminal" {
				original = managedPrepareSuccess(t, keys, command, session)
			}
			if crash == "terminal" {
				if _, err := journal.Succeed(command, endpoint, managedPrepareScopeOK, original); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := NewManagedEndpointPrepareJournal(keys.registry)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := NewManagedEndpointKeyStore(keys.registry)
			if err != nil {
				t.Fatal(err)
			}
			executor := &localManagedEndpointPrepare{journal: reopened, keys: recovered}
			ack, err := executor.execute(session, endpoint, command, managedPrepareScopeOK)
			if err != nil {
				t.Fatal(err)
			}
			if crash == "after_start" {
				if _, err := transport.DecodeManagedEndpointPrepareFailureACK(ack, command.CommandID); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := keys.registry.db.QueryRow(`SELECT COUNT(*) FROM native_managed_endpoint_keys`).Scan(&count); err != nil || count != 0 {
					t.Fatalf("key creation after consumed grant: count=%d err=%v", count, err)
				}
			} else {
				if _, err := transport.DecodeManagedEndpointPrepareACK(ack, command); err != nil {
					t.Fatal(err)
				}
				if original != nil && !bytes.Equal(original, ack) {
					t.Fatal("recovery changed reservation")
				}
			}
			replay, err := executor.execute(session, endpoint, command, managedPrepareScopeOK)
			if err != nil || !bytes.Equal(ack, replay) {
				t.Fatalf("immutable replay err=%v", err)
			}
			changed := command
			changed.Subject.NativeSessionID += "-changed"
			if _, err := executor.execute(session, endpoint, changed, managedPrepareScopeOK); err == nil {
				t.Fatal("changed transcript accepted")
			}
		})
	}
}

func TestManagedPrepareExecutorRechecksReplayAndPublication(t *testing.T) {
	journal, keys, command, session := managedPrepareJournalFixture(t)
	e := &localManagedEndpointPrepare{journal: journal, keys: keys}
	endpoint := "https://example.test"
	ack, err := e.execute(session, endpoint, command, managedPrepareScopeOK)
	if err != nil || len(ack) == 0 {
		t.Fatal(err)
	}
	for _, reason := range []string{"revoked", "stale_worker", "reconnect"} {
		t.Run(reason, func(t *testing.T) {
			if _, err := e.execute(session, endpoint, command, func(transport.ManagedEndpointPrepareCommand, string) error { return errors.New(reason) }); err == nil {
				t.Fatal("replayed without current authority")
			}
		})
	}
	journal.now = func() time.Time { return command.Subject.ExpiresAt }
	if _, err := e.execute(session, endpoint, command, managedPrepareScopeOK); err == nil {
		t.Fatal("expired replay accepted")
	}
	journal.now = time.Now
	calls := 0
	_, err = e.execute(session, endpoint, command, func(transport.ManagedEndpointPrepareCommand, string) error {
		calls++
		if calls == 3 {
			return errors.New("revoked before publication")
		}
		return nil
	})
	if err == nil || calls != 3 {
		t.Fatalf("missing final verification: calls=%d err=%v", calls, err)
	}
}

func TestManagedPrepareReadinessHasNoKeySideEffects(t *testing.T) {
	f := newManagedPrepareVerifierFixture(t)
	d := f.d
	d.Config = Config{StateDir: filepath.Dir(d.nativeRegistry.root), ManagedEndpointPrepareEnabled: true}
	d.Log = discardLog()
	d.initManagedEndpointPrepare()
	if d.managedEndpointPrepareReady() {
		t.Fatal("ready without serve lock and keys")
	}
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	d.initManagedEndpointKeys()
	d.initManagedEndpointPrepare()
	if !d.managedEndpointPrepareReady() {
		t.Fatal("closed prerequisites unavailable")
	}
	for _, table := range []string{"native_managed_endpoint_keys", "native_managed_endpoint_prepare_commands"} {
		var count int
		if err := d.nativeRegistry.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("readiness mutated %s: count=%d err=%v", table, count, err)
		}
	}
	if err := d.serveLockFile.Close(); err != nil {
		t.Fatal(err)
	}
	if d.managedEndpointPrepareReady() {
		t.Fatal("ready with closed serve lock")
	}
}
