//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

func TestManagedEndpointSlotsDistinctEnrollments(t *testing.T) {
	store, subject, session := managedEndpointFixture(t)
	registry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	second, err := NewManagedEndpointKeyStore(registry)
	if err != nil {
		t.Fatal(err)
	}
	const count = 10
	subjects := make([]transport.ManagedEndpointBindingIntent, count)
	reservations := make([]transport.ManagedEndpointKeyReservation, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	for i := range count {
		subjects[i] = subject
		subjects[i].ID = domain.NewID()
		subjects[i].DirectIntentID = domain.NewID()
		subjects[i].CreatedAt = subjects[i].CreatedAt.Add(time.Duration(i) * time.Millisecond)
		subjects[i].ExpiresAt = subjects[i].ExpiresAt.Add(time.Duration(i) * time.Millisecond)
		current := store
		if i%2 == 1 {
			current = second
		}
		wg.Add(1)
		go func(i int, current *ManagedEndpointKeyStore) {
			defer wg.Done()
			reservations[i], errs[i] = current.Reserve(subjects[i], "https://example.test", session)
		}(i, current)
	}
	wg.Wait()
	digests := map[string]bool{}
	for i, reservation := range reservations {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if reservation.X25519 != reservations[0].X25519 || digests[reservation.EnrollmentDigest] {
			t.Fatal("slot key or enrollment digest mismatch")
		}
		digests[reservation.EnrollmentDigest] = true
	}
	path := managedEndpointPath(t, store)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	thirdRegistry, err := OpenNativeWorkerRegistry(filepath.Dir(store.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer thirdRegistry.Close()
	reopened, err := NewManagedEndpointKeyStore(thirdRegistry)
	if err != nil {
		t.Fatal(err)
	}
	for i := range count {
		got, err := reopened.RecoverReservation(subjects[i], "https://example.test", session)
		if err != nil || got != reservations[i] {
			t.Fatal("restart changed enrollment", err)
		}
	}
	subject.ID = domain.NewID()
	random := &managedEndpointRecoveryRandomReader{}
	original := rand.Reader
	rand.Reader = random
	defer func() { rand.Reader = original }()
	store.sync = func(*os.File) error { t.Fatal("reuse synced key"); return nil }
	got, err := store.Reserve(subject, "https://example.test", session)
	if err != nil || got.X25519 != reservations[0].X25519 || random.reads != 0 {
		t.Fatal("reuse generated a key", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reuse rewrote key", err)
	}
}

func TestManagedEndpointSlotsIdentityFence(t *testing.T) {
	for _, field := range []string{"origin", "nativeGeneration", "nativeSession", "ownership", "ownershipGeneration", "host", "credential", "runner", "epoch", "boot"} {
		t.Run(field, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if _, err := store.Reserve(p, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			p.ID = domain.NewID()
			switch field {
			case "origin":
				p.OriginID = domain.NewID()
			case "nativeGeneration":
				p.NativeGeneration = "changed"
			case "nativeSession":
				p.NativeSessionID = "changed"
			case "ownership":
				p.OwnershipID = domain.NewID()
			case "ownershipGeneration":
				p.OwnershipGeneration = "changed"
			case "host":
				p.HostID = domain.NewID()
				session.HostID = p.HostID.String()
			case "credential":
				p.HostCredentialID = domain.NewID()
				session.HostCredentialID = p.HostCredentialID.String()
			case "runner":
				p.RunnerID = domain.NewID()
				session.RunnerID = p.RunnerID.String()
			case "epoch":
				p.RunnerConnectedAt = p.RunnerConnectedAt.Add(time.Second)
				session.RunnerEpoch = p.RunnerConnectedAt
			case "boot":
				p.BootID = "changed"
				session.BootID = p.BootID
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("contradictory slot identity accepted")
			}
			var count int
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys`).Scan(&count); err != nil || count != 1 {
				t.Fatal("conflict created reference", err)
			}
		})
	}
}

func TestManagedEndpointSlotsFailClosed(t *testing.T) {
	for _, failure := range []string{"null", "missing", "corrupt", "pending", "null-reference"} {
		t.Run(failure, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if _, err := store.Reserve(p, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			path := managedEndpointPath(t, store)
			switch failure {
			case "null":
				if _, err := store.registry.db.Exec(`UPDATE native_managed_endpoint_key_slots SET x25519=NULL`); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(path[:len(path)-5]+".pending", []byte("uncertain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "null-reference":
				if _, err := store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation=NULL`); err != nil {
					t.Fatal(err)
				}
			}
			if failure != "null-reference" {
				p.ID = domain.NewID()
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("damaged slot reused")
			}
		})
	}
}

// Convert a freshly created fixture back to the exact legacy schema and file.
func legacyManagedEndpointFixture(t *testing.T, expired bool) (*ManagedEndpointKeyStore, transport.ManagedEndpointBindingIntent, transport.HostSessionPayload, []byte, []byte) {
	t.Helper()
	store, p, session := managedEndpointFixture(t)
	if expired {
		p.CreatedAt = p.CreatedAt.Add(-10 * time.Minute)
		p.ExpiresAt = p.ExpiresAt.Add(-10 * time.Minute)
		store.now = func() time.Time { return p.CreatedAt }
	}
	reservation, err := store.Reserve(p, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	path := managedEndpointPath(t, store)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record managedEndpointSlotKeyRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(managedEndpointKeyRecord{Reservation: reservation, Private: record.Private})
	clear(record.Private)
	if err = os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE native_managed_endpoint_keys RENAME TO slots_refs`,
		`CREATE TABLE native_managed_endpoint_keys(enrollment_id TEXT PRIMARY KEY,scope TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL,request BLOB NOT NULL,reservation BLOB)`,
		`INSERT INTO native_managed_endpoint_keys SELECT * FROM slots_refs`,
		`DROP TABLE slots_refs`,
		`DROP TABLE native_managed_endpoint_key_slots`,
		`DELETE FROM native_registry_metadata WHERE name='managed_endpoint_keys_schema'`,
	} {
		if _, err = store.registry.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	reservationRaw, _ := reservation.CanonicalBytes()
	return store, p, session, legacy, reservationRaw
}

func TestManagedEndpointSlotsLegacyMigration(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired-anchor"}[expired], func(t *testing.T) {
			store, p, session, legacy, reservationRaw := legacyManagedEndpointFixture(t, expired)
			root := store.registry.root
			path := managedEndpointPath(t, store)
			if err := store.registry.Close(); err != nil {
				t.Fatal(err)
			}
			registry, err := OpenNativeWorkerRegistry(filepath.Dir(root))
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			reopened, err := NewManagedEndpointKeyStore(registry)
			if err != nil {
				t.Fatal(err)
			}
			var reserved []byte
			if err = registry.db.QueryRow(`SELECT reservation FROM native_managed_endpoint_keys WHERE enrollment_id=?`, p.ID).Scan(&reserved); err != nil || !bytes.Equal(reserved, reservationRaw) {
				t.Fatal("migration changed reservation", err)
			}
			if !expired {
				recovered, err := reopened.RecoverReservation(p, "https://example.test", session)
				raw, canonicalErr := recovered.CanonicalBytes()
				if err != nil || canonicalErr != nil || !bytes.Equal(raw, reservationRaw) {
					t.Fatal("migration changed recoverable reservation", err, canonicalErr)
				}
			}
			p.ID = domain.NewID()
			p.DirectIntentID = domain.NewID()
			p.CreatedAt = time.Now().UTC()
			p.ExpiresAt = p.CreatedAt.Add(5 * time.Minute)
			got, err := reopened.Reserve(p, "https://example.test", session)
			if err != nil {
				t.Fatal("legacy slot reuse failed", err)
			}
			var anchor transport.ManagedEndpointKeyReservation
			if err = json.Unmarshal(reservationRaw, &anchor); err != nil || got.X25519 != anchor.X25519 || got.EnrollmentDigest == anchor.EnrollmentDigest {
				t.Fatal("legacy key not reused", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, legacy) {
				t.Fatal("migration rewrote private file", err)
			}
		})
	}
}

func TestManagedEndpointSlotsAbsentReferenceRecoveryReadOnly(t *testing.T) {
	store, p, session := managedEndpointFixture(t)
	if _, err := store.Reserve(p, "https://example.test", session); err != nil {
		t.Fatal(err)
	}
	path := managedEndpointPath(t, store)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = domain.NewID()
	random := &managedEndpointRecoveryRandomReader{}
	original := rand.Reader
	rand.Reader = random
	defer func() { rand.Reader = original }()
	store.sync = func(*os.File) error { t.Fatal("recovery synced"); return nil }
	if _, err = store.RecoverReservation(p, "https://example.test", session); err == nil {
		t.Fatal("recovery created absent reference")
	}
	var references, slots int
	if err = store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys`).Scan(&references); err != nil {
		t.Fatal(err)
	}
	if err = store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_key_slots`).Scan(&slots); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || references != 1 || slots != 1 || random.reads != 0 {
		t.Fatal("recovery changed custody", err)
	}
}

func TestManagedEndpointSlotsInterruptedReferenceCompletion(t *testing.T) {
	store, p, session := managedEndpointFixture(t)
	first, err := store.Reserve(p, "https://example.test", session)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = domain.NewID()
	if _, err = store.registry.db.Exec(`CREATE TRIGGER stop_reference_completion BEFORE UPDATE ON native_managed_endpoint_keys BEGIN SELECT RAISE(ABORT,'injected completion failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Reserve(p, "https://example.test", session); err == nil {
		t.Fatal("completion failure accepted")
	}
	if _, err = store.registry.db.Exec(`DROP TRIGGER stop_reference_completion`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Reserve(p, "https://example.test", session); err == nil {
		t.Fatal("NULL reference retried")
	}
	var count int
	if err = store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys WHERE reservation IS NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("reference fence lost", err)
	}
	p.ID = domain.NewID()
	got, err := store.Reserve(p, "https://example.test", session)
	if err != nil || got.X25519 != first.X25519 {
		t.Fatal("reference failure damaged healthy slot", err)
	}
}

func TestManagedEndpointSlotsMigrationRejectsMalformedRows(t *testing.T) {
	for _, failure := range []string{"request", "scope", "reservation", "identity"} {
		t.Run(failure, func(t *testing.T) {
			store, _, _, _, reservationRaw := legacyManagedEndpointFixture(t, false)
			var err error
			switch failure {
			case "request":
				_, err = store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET request='{}'`)
			case "scope":
				_, err = store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET scope='contradiction'`)
			case "reservation":
				_, err = store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation='{}'`)
			case "identity":
				var reservation transport.ManagedEndpointKeyReservation
				if err = json.Unmarshal(reservationRaw, &reservation); err != nil {
					t.Fatal(err)
				}
				reservation.Subject.OriginID = domain.NewID()
				reservation.EnrollmentDigest, err = reservation.Digest()
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := reservation.CanonicalBytes()
				_, err = store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation=?`, raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = store.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("malformed legacy row migrated")
			}
			var count int
			if err = store.registry.db.QueryRow(`SELECT count(*) FROM native_registry_metadata WHERE name='managed_endpoint_keys_schema'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed migration committed version", err)
			}
			if err = store.registry.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='native_managed_endpoint_key_slots'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed migration committed schema", err)
			}
		})
	}
}

func TestManagedEndpointSlotsLegacyNullTombstone(t *testing.T) {
	store, p, session, _, _ := legacyManagedEndpointFixture(t, false)
	if _, err := store.registry.db.Exec(`UPDATE native_managed_endpoint_keys SET reservation=NULL`); err != nil {
		t.Fatal(err)
	}
	if err := store.registry.initSourceHolderInstallation(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_key_slots WHERE x25519 IS NULL AND file_format=1`).Scan(&count); err != nil || count != 1 {
		t.Fatal("legacy tombstone lost", err)
	}
	p.ID = domain.NewID()
	if _, err := store.Reserve(p, "https://example.test", session); err == nil {
		t.Fatal("legacy tombstone reused")
	}
}

func TestManagedEndpointSlotsInstallationGuards(t *testing.T) {
	for _, failure := range []string{"lost", "mismatch"} {
		t.Run(failure, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if _, err := store.Reserve(p, "https://example.test", session); err != nil {
				t.Fatal(err)
			}
			if _, err := store.registry.db.Exec(`DELETE FROM native_managed_endpoint_keys`); err != nil {
				t.Fatal(err)
			}
			// Leave only the slot as retained SQL evidence; remove the namespace too.
			if err := os.RemoveAll(filepath.Join(store.registry.root, nativeManagedEndpointKeyNamespace)); err != nil {
				t.Fatal(err)
			}
			var err error
			if failure == "lost" {
				_, err = store.registry.db.Exec(`DELETE FROM native_registry_metadata WHERE name='installation_id'`)
			} else {
				_, err = store.registry.db.Exec(`UPDATE native_managed_endpoint_key_slots SET installation_id=?`, domain.NewID())
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = store.registry.initSourceHolderInstallation(); err == nil {
				t.Fatal("slot installation evidence ignored")
			}
		})
	}
}

func TestManagedEndpointSlotsNewSlotCrashBoundaries(t *testing.T) {
	for _, failure := range []string{"directory-sync", "slot-cas"} {
		t.Run(failure, func(t *testing.T) {
			store, p, session := managedEndpointFixture(t)
			if failure == "directory-sync" {
				store.sync = func(file *os.File) error {
					info, err := file.Stat()
					if err != nil {
						return err
					}
					if info.IsDir() {
						return os.ErrInvalid
					}
					return file.Sync()
				}
			} else {
				if _, err := store.registry.db.Exec(`CREATE TRIGGER stop_slot_completion BEFORE UPDATE ON native_managed_endpoint_key_slots BEGIN SELECT RAISE(ABORT,'injected slot completion failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("incomplete slot accepted")
			}
			store.sync = (*os.File).Sync
			var slots, refs int
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_key_slots WHERE x25519 IS NULL`).Scan(&slots); err != nil {
				t.Fatal(err)
			}
			if err := store.registry.db.QueryRow(`SELECT count(*) FROM native_managed_endpoint_keys WHERE reservation IS NULL`).Scan(&refs); err != nil {
				t.Fatal(err)
			}
			if slots != 1 || refs != 1 {
				t.Fatal("crash lost durable fences")
			}
			path := managedEndpointPath(t, store)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("incomplete enrollment replaced key")
			}
			p.ID = domain.NewID()
			if _, err := store.Reserve(p, "https://example.test", session); err == nil {
				t.Fatal("incomplete slot replaced key")
			}
		})
	}
}
