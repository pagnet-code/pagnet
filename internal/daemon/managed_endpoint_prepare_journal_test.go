//go:build linux || darwin

package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func managedPrepareJournalFixture(t *testing.T) (*ManagedEndpointPrepareJournal, *ManagedEndpointKeyStore, transport.ManagedEndpointPrepareCommand, transport.HostSessionPayload) {
	t.Helper()
	keys, subject, session := managedEndpointFixture(t)
	j, err := NewManagedEndpointPrepareJournal(keys.registry)
	if err != nil {
		t.Fatal(err)
	}
	return j, keys, transport.ManagedEndpointPrepareCommand{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: domain.NewID(), Subject: subject}, session
}
func managedPrepareScopeOK(transport.ManagedEndpointPrepareCommand, string) error { return nil }
func managedPrepareSuccess(t *testing.T, keys *ManagedEndpointKeyStore, command transport.ManagedEndpointPrepareCommand, session transport.HostSessionPayload) []byte {
	t.Helper()
	reservation, err := keys.Reserve(command.Subject, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := (transport.ManagedEndpointPrepareACK{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: command.CommandID, Reservation: reservation}).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return ack
}
func TestManagedPrepareJournalConcurrentReservationAndTerminal(t *testing.T) {
	j, keys, command, session := managedPrepareJournalFixture(t)
	r, err := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	second, err := NewManagedEndpointPrepareJournal(r)
	if err != nil {
		t.Fatal(err)
	}
	const count = 16
	results := make(chan ManagedEndpointPrepareResult, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		current := j
		if i%2 == 1 {
			current = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := current.Reserve(command, "https://EXAMPLE.TEST///", managedPrepareScopeOK)
			results <- v
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	created := 0
	for v := range results {
		if v.Created {
			created++
		}
		if v.State != "reserved" || v.ACK != nil {
			t.Fatal("invalid reservation", v)
		}
	}
	if created != 1 {
		t.Fatal("new command associations", created)
	}
	ack := managedPrepareSuccess(t, keys, command, session)
	for i := range count {
		current := j
		if i%2 == 1 {
			current = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := current.Succeed(command, "https://example.test", managedPrepareScopeOK, ack)
			if e != nil {
				t.Error(e)
				return
			}
			if v.Created || v.State != "succeeded" || !bytes.Equal(v.ACK, ack) {
				t.Error("terminal changed")
			}
		}()
	}
	wg.Wait()
	if _, err = j.Fail(command, "https://example.test", managedPrepareScopeOK); err == nil {
		t.Fatal("rewrote terminal success")
	}
	// Returned byte slices cannot change the durable result.
	v, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK)
	if err != nil {
		t.Fatal(err)
	}
	v.ACK[0] = '!'
	v, err = j.Reserve(command, "https://example.test", managedPrepareScopeOK)
	if err != nil || !bytes.Equal(v.ACK, ack) {
		t.Fatal("mutable returned result", err)
	}
}
func TestManagedPrepareJournalCollisions(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*transport.ManagedEndpointPrepareCommand){
		"enrollment": func(p *transport.ManagedEndpointPrepareCommand) { p.Subject.ID = domain.NewID() },
		"command":    func(p *transport.ManagedEndpointPrepareCommand) { p.CommandID = domain.NewID() },
		"expiry": func(p *transport.ManagedEndpointPrepareCommand) {
			p.Subject.ExpiresAt = p.Subject.ExpiresAt.Add(time.Second)
		},
		"native session": func(p *transport.ManagedEndpointPrepareCommand) { p.Subject.NativeSessionID += "-other" },
		"principal":      func(p *transport.ManagedEndpointPrepareCommand) { p.Subject.PrincipalID = domain.NewID() },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := command
			mutate(&changed)
			if _, err := j.Reserve(changed, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("collision accepted")
			}
		})
	}
	if _, err := j.Reserve(command, "https://another.test", managedPrepareScopeOK); err == nil {
		t.Fatal("origin collision accepted")
	}
	var count int
	if err := j.registry.db.QueryRow(`SELECT COUNT(*) FROM native_managed_endpoint_prepare_commands`).Scan(&count); err != nil || count != 1 {
		t.Fatal("association changed", count, err)
	}
}
func TestManagedPrepareJournalRestartAtCrashBoundaries(t *testing.T) {
	for _, point := range []string{"reserve", "key", "success", "failure"} {
		t.Run(point, func(t *testing.T) {
			j, keys, command, session := managedPrepareJournalFixture(t)
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			var ack []byte
			if point == "key" || point == "success" {
				ack = managedPrepareSuccess(t, keys, command, session)
			}
			if point == "success" {
				if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, ack); err != nil {
					t.Fatal(err)
				}
			}
			if point == "failure" {
				v, err := j.Fail(command, "https://example.test", managedPrepareScopeOK)
				if err != nil {
					t.Fatal(err)
				}
				ack = v.ACK
			}
			root := j.registry.root
			if err := j.registry.Close(); err != nil {
				t.Fatal(err)
			}
			registry, err := OpenNativeWorkerRegistry(filepath.Dir(root))
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			reopened, err := NewManagedEndpointPrepareJournal(registry)
			if err != nil {
				t.Fatal(err)
			}
			v, err := reopened.Reserve(command, "https://example.test", managedPrepareScopeOK)
			if err != nil || v.Created {
				t.Fatal("restart allocated command", err)
			}
			expected := "reserved"
			if point == "success" {
				expected = "succeeded"
			}
			if point == "failure" {
				expected = "failed"
			}
			if v.State != expected {
				t.Fatal("state changed", v.State)
			}
			if point == "success" || point == "failure" {
				if !bytes.Equal(v.ACK, ack) {
					t.Fatal("terminal bytes changed")
				}
			}
			if point == "reserve" || point == "key" {
				if v.ACK != nil {
					t.Fatal("reserved acquired result")
				}
			}
			if point == "failure" {
				if _, err := reopened.Fail(command, "https://example.test", managedPrepareScopeOK); err != nil {
					t.Fatal(err)
				}
				changed := command
				changed.CommandID = domain.NewID()
				if _, err := reopened.Reserve(changed, "https://example.test", managedPrepareScopeOK); err == nil {
					t.Fatal("failed enrollment reused")
				}
			}
		})
	}
}
func TestManagedPrepareJournalRequiresCurrentScopeAndOriginalExpiry(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", nil); err == nil {
		t.Fatal("missing verifier accepted")
	}
	var count int
	verify := func(got transport.ManagedEndpointPrepareCommand, server string) error {
		count++
		if got != command || server != "https://example.test" {
			t.Fatal("incorrect verification scope")
		}
		return nil
	}
	if _, err := j.Reserve(command, "https://EXAMPLE.TEST///", verify); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Fail(command, "https://example.test", verify); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Reserve(command, "https://example.test", verify); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatal("verification skipped", count)
	}
	denied := func(transport.ManagedEndpointPrepareCommand, string) error { return errors.New("stale session") }
	if _, err := j.Reserve(command, "https://example.test", denied); err == nil {
		t.Fatal("terminal replay without current scope")
	}
	if _, err := j.Fail(command, "https://example.test", nil); err == nil {
		t.Fatal("terminal commit without scope")
	}
	j.now = func() time.Time { return command.Subject.ExpiresAt }
	if _, err := j.Reserve(command, "https://example.test", verify); err == nil {
		t.Fatal("expired replay accepted")
	}
}
func TestManagedPrepareJournalCorruptionFailsClosed(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE native_managed_endpoint_prepare_commands SET request=x'00'`,
		`UPDATE native_managed_endpoint_prepare_commands SET request_digest=zeroblob(32)`,
		`UPDATE native_managed_endpoint_prepare_commands SET expires_at='later'`,
		`UPDATE native_managed_endpoint_prepare_commands SET installation_id='wrong'`,
		`UPDATE native_managed_endpoint_prepare_commands SET enrollment_id='wrong'`,
		`UPDATE native_managed_endpoint_prepare_commands SET server_url='https://other.test'`,
		`UPDATE native_managed_endpoint_prepare_commands SET state='succeeded',ack=x'00'`,
		`UPDATE native_managed_endpoint_prepare_commands SET state='failed',ack=x'00'`,
	} {
		t.Run(mutation, func(t *testing.T) {
			j, _, command, _ := managedPrepareJournalFixture(t)
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			if _, err := j.registry.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("corrupt journal accepted")
			}
			if _, err := j.Fail(command, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("corrupt journal overwritten")
			}
		})
	}
}
func TestManagedPrepareJournalCanonicalACKAndNoImplicitReservation(t *testing.T) {
	j, keys, command, session := managedPrepareJournalFixture(t)
	if _, err := j.Fail(command, "https://example.test", managedPrepareScopeOK); err == nil {
		t.Fatal("terminal created association")
	}
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	ack := managedPrepareSuccess(t, keys, command, session)
	if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, append([]byte(" "), ack...)); err == nil {
		t.Fatal("noncanonical ACK accepted")
	}
	other := command
	other.CommandID = domain.NewID()
	if _, err := j.Succeed(other, "https://example.test", managedPrepareScopeOK, ack); err == nil {
		t.Fatal("ACK command mismatch accepted")
	}
	if _, err := j.Fail(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, ack); err == nil {
		t.Fatal("rewrote terminal failure")
	}
}
func TestManagedPrepareJournalServeLockAndFileProtection(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	d := &Daemon{Config: Config{StateDir: filepath.Dir(j.registry.root)}, Log: discardLog(), nativeRegistry: j.registry}
	if _, err := d.newManagedEndpointPrepareJournal(); err == nil {
		t.Fatal("composed without serve lock")
	}
	release, err := d.acquireServeLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := d.newManagedEndpointPrepareJournal(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(j.registry.root, "registry.sqlite"), filepath.Join(j.registry.root, managedEndpointPrepareJournalNamespace, "holder.lock")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe file mode", path, err)
		}
	}
	if err := os.Chmod(filepath.Join(j.registry.root, managedEndpointPrepareJournalNamespace, "holder.lock"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err == nil {
		t.Fatal("unsafe lock accepted")
	}
}

func TestManagedPrepareJournalConcurrentEnrollmentCollision(t *testing.T) {
	j, _, first, _ := managedPrepareJournalFixture(t)
	second := first
	second.CommandID = domain.NewID()
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	other, err := NewManagedEndpointPrepareJournal(registry)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, command := range []transport.ManagedEndpointPrepareCommand{first, second} {
		current := j
		if i == 1 {
			current = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, e := current.Reserve(command, "https://example.test", managedPrepareScopeOK)
			errs <- e
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("competing enrollment reservations", successes)
	}
}

func TestManagedPrepareJournalInstallationLossFailsClosed(t *testing.T) {
	for _, removeRows := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained rows", true: "retained namespace"}[removeRows], func(t *testing.T) {
			j, _, command, _ := managedPrepareJournalFixture(t)
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			if removeRows {
				if _, err := j.registry.db.Exec(`DELETE FROM native_managed_endpoint_prepare_commands`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := j.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`); err != nil {
				t.Fatal(err)
			}
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("missing installation accepted")
			}
			root := j.registry.root
			if err := j.registry.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenNativeWorkerRegistry(filepath.Dir(root))
			if err == nil {
				reopened.Close()
				t.Fatal("replacement installation minted")
			}
		})
	}
}

func TestManagedPrepareJournalSuccessBytesImmutable(t *testing.T) {
	j, keys, command, session := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	original := managedPrepareSuccess(t, keys, command, session)
	// Independently valid evidence with a different public key still cannot replace
	// an already committed result for the same full command.
	otherKeys, _, _ := managedEndpointFixture(t)
	alternate := managedPrepareSuccess(t, otherKeys, command, session)
	if bytes.Equal(original, alternate) {
		t.Fatal("independent keys matched")
	}
	if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, original); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, alternate); err == nil {
		t.Fatal("rewrote success bytes")
	}
	replay, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK)
	if err != nil || !bytes.Equal(replay.ACK, original) {
		t.Fatal("changed original ACK", err)
	}
}
