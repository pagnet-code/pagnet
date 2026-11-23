//go:build linux || darwin

package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			// A transition during unlocked verification rejects that attempt;
			// an exact terminal replay independently verifies the current state.
			if e != nil {
				v, e = current.Succeed(command, "https://example.test", managedPrepareScopeOK, ack)
			}
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
	alternate := managedPrepareMutateACK(t, original, command, func(reservation *transport.ManagedEndpointKeyReservation) {
		reservation.X25519 = strings.Repeat("a", 64)
	})
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

func managedPrepareMutateACK(t *testing.T, raw []byte, command transport.ManagedEndpointPrepareCommand, mutate func(*transport.ManagedEndpointKeyReservation)) []byte {
	t.Helper()
	ack, err := transport.DecodeManagedEndpointPrepareACK(raw, command)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&ack.Reservation)
	ack.Reservation.EnrollmentDigest, err = ack.Reservation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.DecodeManagedEndpointPrepareACK(changed, command); err != nil {
		t.Fatal("fixture must be valid command-bound evidence", err)
	}
	return changed
}

func TestManagedPrepareJournalSuccessRequiresRetainedCustodyScope(t *testing.T) {
	for name, mutate := range map[string]func(*transport.ManagedEndpointKeyReservation){
		"origin":       func(r *transport.ManagedEndpointKeyReservation) { r.ServerURL = "https://other.test" },
		"installation": func(r *transport.ManagedEndpointKeyReservation) { r.InstallationID = domain.NewID() },
	} {
		t.Run(name, func(t *testing.T) {
			j, keys, command, session := managedPrepareJournalFixture(t)
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			original := managedPrepareSuccess(t, keys, command, session)
			wrongScope := managedPrepareMutateACK(t, original, command, mutate)
			if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, wrongScope); err == nil {
				t.Fatal("first success accepted wrong custody scope")
			}
			reserved, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK)
			if err != nil || reserved.State != "reserved" || reserved.ACK != nil {
				t.Fatal("rejection changed reservation", err)
			}
			if _, err := j.Succeed(command, "https://example.test", managedPrepareScopeOK, original); err != nil {
				t.Fatal(err)
			}
			// A valid wire ACK transplanted into the durable row must also fail
			// replay's local custody checks, rather than reaching a caller.
			if _, err := j.registry.db.Exec(`UPDATE native_managed_endpoint_prepare_commands SET ack=? WHERE command_id=?`, wrongScope, command.CommandID); err != nil {
				t.Fatal(err)
			}
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("replayed wrong custody scope")
			}
		})
	}
}

func TestManagedPrepareJournalVerifierReceivesRetainedCanonicalContext(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	request, err := command.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	retry := command
	retry.Subject.ExpiresAt = retry.Subject.ExpiresAt.In(time.FixedZone("retry-offset", 3600))
	called := false
	verify := func(retained transport.ManagedEndpointPrepareCommand, server string) error {
		called = true
		canonical, err := retained.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, request) || server != "https://example.test" || retained.Subject.ExpiresAt.Location() != time.UTC {
			t.Fatal("verifier did not receive retained canonical context", err)
		}
		return nil
	}
	if _, err := j.Reserve(retry, "https://EXAMPLE.TEST///", verify); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("scope verifier skipped")
	}
}

func TestManagedPrepareJournalKeyStartCrashFence(t *testing.T) {
	for _, createKey := range []bool{false, true} {
		t.Run(map[bool]string{false: "before creation", true: "after creation"}[createKey], func(t *testing.T) {
			j, keys, command, session := managedPrepareJournalFixture(t)
			if _, err := j.BeginKeyReservation(command, "https://example.test", managedPrepareScopeOK); err == nil {
				t.Fatal("start created association")
			}
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			v, err := j.BeginKeyReservation(command, "https://example.test", managedPrepareScopeOK)
			if err != nil || !v.KeyStarted {
				t.Fatal("missing first grant", err)
			}
			if createKey {
				if _, err := keys.Reserve(command.Subject, "https://example.test", session); err != nil {
					t.Fatal(err)
				}
			}
			root := j.registry.root
			if err := j.registry.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := OpenNativeWorkerRegistry(filepath.Dir(root))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			j, err = NewManagedEndpointPrepareJournal(r)
			if err != nil {
				t.Fatal(err)
			}
			keys, err = NewManagedEndpointKeyStore(r)
			if err != nil {
				t.Fatal(err)
			}
			v, err = j.BeginKeyReservation(command, "https://example.test", managedPrepareScopeOK)
			if err != nil || v.KeyStarted {
				t.Fatal("regranted after crash", err)
			}
			_, err = keys.RecoverReservation(command.Subject, "https://example.test", session)
			if createKey != (err == nil) {
				t.Fatal("incorrect crash recovery", err)
			}
		})
	}
}

func TestManagedPrepareJournalConcurrentKeyStart(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	r, err := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	other, err := NewManagedEndpointPrepareJournal(r)
	if err != nil {
		t.Fatal(err)
	}
	const count = 16
	grants := make(chan bool, count)
	var wg sync.WaitGroup
	for i := range count {
		current := j
		if i%2 == 1 {
			current = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := current.BeginKeyReservation(command, "https://example.test", managedPrepareScopeOK)
			grants <- err == nil && v.KeyStarted
		}()
	}
	wg.Wait()
	close(grants)
	winners := 0
	for grant := range grants {
		if grant {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("key start winners", winners)
	}
}

func TestManagedPrepareJournalVerifierCanLookupRegistry(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	done := make(chan error, 1)
	go func() {
		_, err := j.Reserve(command, "https://example.test", func(transport.ManagedEndpointPrepareCommand, string) error {
			_, _ = j.registry.Lookup(command.Subject.InstanceID.String())
			return nil
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verifier deadlocked")
	}
}

func TestManagedPrepareJournalRejectsChangesDuringVerification(t *testing.T) {
	for name, mutation := range map[string]string{
		"association":  `UPDATE native_managed_endpoint_prepare_commands SET server_url='https://other.test'`,
		"installation": `UPDATE native_registry_metadata SET value='other' WHERE name='installation_id'`,
		"marker":       `UPDATE native_managed_endpoint_prepare_commands SET key_started=1`,
		"deletion":     `DELETE FROM native_managed_endpoint_prepare_commands`,
		"state":        `UPDATE native_managed_endpoint_prepare_commands SET state='failed',ack=?`,
		"expiry":       "",
	} {
		t.Run(name, func(t *testing.T) {
			j, _, command, _ := managedPrepareJournalFixture(t)
			if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
				t.Fatal(err)
			}
			verify := func(transport.ManagedEndpointPrepareCommand, string) error {
				if name == "expiry" {
					j.now = func() time.Time { return command.Subject.ExpiresAt }
					return nil
				}
				var args []any
				if name == "state" {
					ack, err := (transport.ManagedEndpointPrepareFailureACK{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: command.CommandID, Error: transport.ManagedEndpointPrepareFailure}).CanonicalBytes()
					if err != nil {
						t.Fatal(err)
					}
					args = []any{ack}
				}
				if _, err := j.registry.db.Exec(mutation, args...); err != nil {
					t.Fatal(err)
				}
				return nil
			}
			if _, err := j.BeginKeyReservation(command, "https://example.test", verify); err == nil {
				t.Fatal("changed snapshot accepted")
			}
		})
	}
}

func TestManagedPrepareJournalMigratesKeyStartConservatively(t *testing.T) {
	j, _, command, _ := managedPrepareJournalFixture(t)
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	if _, err := j.registry.db.Exec(`ALTER TABLE native_managed_endpoint_prepare_commands DROP COLUMN key_started`); err != nil {
		t.Fatal(err)
	}
	root := j.registry.root
	if err := j.registry.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenNativeWorkerRegistry(filepath.Dir(root))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	j, err = NewManagedEndpointPrepareJournal(r)
	if err != nil {
		t.Fatal(err)
	}
	var marker int
	if err := r.db.QueryRow(`SELECT key_started FROM native_managed_endpoint_prepare_commands WHERE command_id=?`, command.CommandID).Scan(&marker); err != nil || marker != 1 {
		t.Fatal("unsafe migration", marker, err)
	}
	v, err := j.BeginKeyReservation(command, "https://example.test", managedPrepareScopeOK)
	if err != nil || v.KeyStarted {
		t.Fatal("migrated regrant", err)
	}
	command.CommandID, command.Subject.ID = domain.NewID(), domain.NewID()
	if _, err := j.Reserve(command, "https://example.test", managedPrepareScopeOK); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow(`SELECT key_started FROM native_managed_endpoint_prepare_commands WHERE command_id=?`, command.CommandID).Scan(&marker); err != nil || marker != 0 {
		t.Fatal("new command already started", marker, err)
	}
}
