//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

const nativeManagedEndpointKeyNamespace = "closed-managed-endpoint-keys"

var errManagedEndpointKey = errors.New("closed managed endpoint key unavailable, unsafe or conflicting")

// ManagedEndpointKeyStore retains dedicated private X25519 keys locally. It has
// no export, activation, credential, or transport handler. A future
// negotiated ingress must authenticate server provenance, the live socket/session
// and local worker ownership before Reserve, and revalidate them before key use
// or publication.
// Lock order matches source holders: registry mutex, namespace flock, SQLite.
type ManagedEndpointKeyStore struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	now          func() time.Time
	sync         func(*os.File) error
}

func (s ManagedEndpointKeyStore) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "ManagedEndpointKeyStore{closed}")
}

func NewManagedEndpointKeyStore(r *NativeWorkerRegistry) (*ManagedEndpointKeyStore, error) {
	if r == nil {
		return nil, errManagedEndpointKey
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var id string
	if err := r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errManagedEndpointKey
	}
	return &ManagedEndpointKeyStore{registry: r, installation: domain.ID(id), now: time.Now, sync: (*os.File).Sync}, nil
}

type managedEndpointKeyRecord struct {
	Reservation transport.ManagedEndpointKeyReservation `json:"reservation"`
	Private     []byte                                  `json:"private"`
}

// Reserve compares supplied evidence and binds the exact server intent to the
// configured control-plane origin and captured host session. It does not itself
// authenticate server provenance, the live socket, or the P principal/endpoint/
// native worker. Future ingress must perform those checks before calling Reserve;
// the retained subject remains closed evidence, not locally authenticated claims.
// A durable NULL reservation is committed before generating any random key. An
// interrupted reservation is permanently unavailable, including after file loss.
func (s *ManagedEndpointKeyStore) Reserve(subject transport.ManagedEndpointBindingIntent, configuredServer string, session transport.HostSessionPayload) (transport.ManagedEndpointKeyReservation, error) {
	return s.reserve(subject, configuredServer, session, false)
}

// RecoverReservation returns only a complete existing reservation for the exact
// supplied evidence. It never creates, repairs, or replaces retained key state.
func (s *ManagedEndpointKeyStore) RecoverReservation(subject transport.ManagedEndpointBindingIntent, configuredServer string, session transport.HostSessionPayload) (transport.ManagedEndpointKeyReservation, error) {
	return s.reserve(subject, configuredServer, session, true)
}

func (s *ManagedEndpointKeyStore) reserve(subject transport.ManagedEndpointBindingIntent, configuredServer string, session transport.HostSessionPayload, recovery bool) (transport.ManagedEndpointKeyReservation, error) {
	var empty transport.ManagedEndpointKeyReservation
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil {
		return empty, errManagedEndpointKey
	}
	canonical, err := subject.CanonicalBytes()
	if err != nil {
		return empty, err
	}
	// Use canonical UTC instants in all journal and digest representations.
	if json.Unmarshal(canonical, &subject) != nil {
		return empty, errManagedEndpointKey
	}
	server := textServiceServer(configuredServer)
	if server == "" || legacyTextServiceServer(configuredServer) != server || subject.TenantID.String() != session.TenantID || subject.AccountID.String() != session.AccountID || subject.OwnershipScope != session.OwnershipScope || subject.HostID.String() != session.HostID || subject.HostCredentialID.String() != session.HostCredentialID || subject.NativeAdmissionID.String() != session.NativeAdmissionID || subject.RunnerID.String() != session.RunnerID || !subject.RunnerConnectedAt.Equal(session.RunnerEpoch) || subject.BootID != session.BootID || !s.now().Before(subject.ExpiresAt) {
		return empty, errManagedEndpointKey
	}
	request, _ := json.Marshal(struct {
		Server  string                                 `json:"serverUrl"`
		Subject transport.ManagedEndpointBindingIntent `json:"subject"`
	}{server, subject})
	name := managedEndpointKeyScope(s.installation, server, subject)
	identity := managedEndpointSlotIdentity(s.installation, server, subject)
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	var dir *os.File
	if recovery {
		dir, err = nativeShareHolderExistingChild(root, nativeManagedEndpointKeyNamespace)
	} else {
		dir, err = nativeShareHolderChild(root, nativeManagedEndpointKeyNamespace)
	}
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLockMode(dir, !recovery)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if !s.now().Before(subject.ExpiresAt) {
		return empty, errManagedEndpointKey
	}
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	exec := func(q string, args ...any) error {
		_, err := conn.ExecContext(context.Background(), q, args...)
		return err
	}
	if err = exec("BEGIN IMMEDIATE"); err != nil {
		return empty, err
	}
	defer func() { _ = exec("ROLLBACK") }()
	var installation string
	if err = conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.installation) {
		return empty, errManagedEndpointKey
	}
	var storedScope, storedInstallation string
	var storedRequest, reserved []byte
	err = conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_managed_endpoint_keys WHERE enrollment_id=?`, subject.ID).Scan(&storedScope, &storedInstallation, &storedRequest, &reserved)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	if exists && (storedScope != name || storedInstallation != installation || !bytes.Equal(storedRequest, request) || len(reserved) == 0) {
		return empty, errManagedEndpointKey
	}
	if recovery && !exists {
		return empty, errManagedEndpointKey
	}
	var slotInstallation, public, anchor string
	var slotIdentity []byte
	var generation, format int
	var slotPublic sql.NullString
	err = conn.QueryRowContext(context.Background(), `SELECT installation_id,identity,key_generation,file_format,legacy_enrollment_id,x25519 FROM native_managed_endpoint_key_slots WHERE scope=?`, name).Scan(&slotInstallation, &slotIdentity, &generation, &format, &anchor, &slotPublic)
	slotExists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	if exists && !slotExists {
		return empty, errManagedEndpointKey
	}
	if slotExists && (slotInstallation != installation || !bytes.Equal(slotIdentity, identity) || generation != 1 || !slotPublic.Valid) {
		return empty, errManagedEndpointKey
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return empty, errManagedEndpointKey
	}
	file, fileErr := nativeShareHolderOpen(dir, name+".json", false)
	if slotExists {
		if fileErr != nil {
			return empty, errManagedEndpointKey
		}
		defer file.Close()
		if format == 1 {
			// The file's first enrollment is an immutable anchor. Its expiry is
			// irrelevant to custody; only the requested enrollment must be live.
			var anchorScope, anchorInstallation string
			var anchorRequest, anchorReserved []byte
			if err = conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_managed_endpoint_keys WHERE enrollment_id=?`, anchor).Scan(&anchorScope, &anchorInstallation, &anchorRequest, &anchorReserved); err != nil || anchorScope != name || anchorInstallation != installation {
				return empty, errManagedEndpointKey
			}
			anchorSubject, anchorServer, err := validateManagedEndpointRequest(anchorRequest)
			if err != nil || anchorSubject.ID.String() != anchor || !bytes.Equal(managedEndpointSlotIdentity(s.installation, anchorServer, anchorSubject), identity) {
				return empty, errManagedEndpointKey
			}
			record, err := loadManagedEndpointKey(file)
			if err != nil {
				return empty, err
			}
			defer clear(record.Private)
			raw, _ := record.Reservation.CanonicalBytes()
			if !bytes.Equal(raw, anchorReserved) || record.Reservation.Subject != anchorSubject || record.Reservation.ServerURL != anchorServer || record.Reservation.InstallationID != s.installation {
				return empty, errManagedEndpointKey
			}
			public = record.Reservation.X25519
		} else if format == 2 && anchor == "" {
			public, err = loadManagedEndpointSlotKey(file, identity)
			if err != nil {
				return empty, err
			}
		} else {
			return empty, errManagedEndpointKey
		}
		if !s.now().Before(subject.ExpiresAt) || public != slotPublic.String {
			return empty, errManagedEndpointKey
		}
		reservation := transport.ManagedEndpointKeyReservation{Subject: subject, ServerURL: server, InstallationID: s.installation, KeyGeneration: 1, X25519: public}
		reservation.EnrollmentDigest, err = reservation.Digest()
		if err != nil {
			return empty, errManagedEndpointKey
		}
		raw, _ := reservation.CanonicalBytes()
		if exists {
			if !bytes.Equal(raw, reserved) {
				return empty, errManagedEndpointKey
			}
			if err = exec("COMMIT"); err != nil {
				return empty, err
			}
			return reservation, nil
		}
		if err = exec(`INSERT INTO native_managed_endpoint_keys(enrollment_id,scope,installation_id,request,reservation) VALUES(?,?,?,?,NULL)`, subject.ID, name, installation, request); err != nil {
			return empty, err
		}
		if err = exec("COMMIT"); err != nil {
			return empty, err
		}
		if !s.now().Before(subject.ExpiresAt) {
			return empty, errManagedEndpointKey
		}
		if err = exec("BEGIN IMMEDIATE"); err != nil {
			return empty, err
		}
		if err = s.completeManagedEndpointReference(conn, subject.ID, name, installation, request, raw, identity, public); err != nil {
			return empty, err
		}
		if err = exec("COMMIT"); err != nil {
			return empty, err
		}
		return reservation, nil
	}
	if file != nil {
		file.Close()
	}
	if recovery || !errors.Is(fileErr, unix.ENOENT) {
		return empty, errManagedEndpointKey
	}
	if err = exec(`INSERT INTO native_managed_endpoint_key_slots(scope,installation_id,identity,key_generation,file_format,legacy_enrollment_id,x25519) VALUES(?,?,?,1,2,'',NULL)`, name, installation, identity); err != nil {
		return empty, err
	}
	if err = exec(`INSERT INTO native_managed_endpoint_keys(enrollment_id,scope,installation_id,request,reservation) VALUES(?,?,?,?,NULL)`, subject.ID, name, installation, request); err != nil {
		return empty, errManagedEndpointKey
	}
	if err = exec("COMMIT"); err != nil {
		return empty, err
	}
	if !s.now().Before(subject.ExpiresAt) {
		return empty, errManagedEndpointKey
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	private := key.Bytes()
	defer clear(private)
	reservation := transport.ManagedEndpointKeyReservation{Subject: subject, ServerURL: server, InstallationID: s.installation, KeyGeneration: 1, X25519: hex.EncodeToString(key.PublicKey().Bytes())}
	reservation.EnrollmentDigest, err = reservation.Digest()
	if err != nil {
		return empty, errManagedEndpointKey
	}
	raw, err := json.Marshal(managedEndpointSlotKeyRecord{Version: 2, Identity: identity, X25519: reservation.X25519, Private: private})
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	pending, err := nativeShareHolderOpen(dir, name+".pending", true)
	if err != nil {
		return empty, err
	}
	if _, err = pending.Write(raw); err == nil {
		err = s.sync(pending)
	}
	closeErr := pending.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	if err = unix.Linkat(int(dir.Fd()), name+".pending", int(dir.Fd()), name+".json", 0); err != nil {
		return empty, err
	}
	if err = unix.Unlinkat(int(dir.Fd()), name+".pending", 0); err != nil {
		return empty, err
	}
	if err = s.sync(dir); err != nil {
		return empty, err
	}
	if !s.now().Before(subject.ExpiresAt) {
		return empty, errManagedEndpointKey
	}
	if err = exec("BEGIN IMMEDIATE"); err != nil {
		return empty, err
	}
	publicRaw, _ := json.Marshal(reservation)
	result, err := conn.ExecContext(context.Background(), `UPDATE native_managed_endpoint_key_slots SET x25519=? WHERE scope=? AND installation_id=? AND identity=? AND key_generation=1 AND file_format=2 AND legacy_enrollment_id='' AND x25519 IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?)`, reservation.X25519, name, installation, identity, installation)
	if err != nil {
		return empty, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return empty, errManagedEndpointKey
	}
	if err = s.completeManagedEndpointReference(conn, subject.ID, name, installation, request, publicRaw, identity, reservation.X25519); err != nil {
		return empty, err
	}
	if err = exec("COMMIT"); err != nil {
		return empty, err
	}
	return reservation, nil
}

func loadManagedEndpointKey(file *os.File) (managedEndpointKeyRecord, error) {
	var r managedEndpointKeyRecord
	valid := false
	defer func() {
		if !valid {
			clear(r.Private)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(file, nativeShareHolderMaxBytes+1))
	if err != nil {
		return r, err
	}
	defer clear(raw)
	if len(raw) > nativeShareHolderMaxBytes {
		return r, errManagedEndpointKey
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
		return r, errManagedEndpointKey
	}
	encoded, err := json.Marshal(r)
	defer clear(encoded)
	if err != nil || !bytes.Equal(encoded, raw) {
		return r, errManagedEndpointKey
	}
	p := r.Reservation
	if _, err = p.CanonicalBytes(); err != nil {
		return r, errManagedEndpointKey
	}
	key, err := ecdh.X25519().NewPrivateKey(r.Private)
	if err != nil || p.X25519 != hex.EncodeToString(key.PublicKey().Bytes()) {
		return r, errManagedEndpointKey
	}
	valid = true
	return r, nil
}

func (d *Daemon) initManagedEndpointKeys() {
	if d.serveLockFile == nil || d.nativeRegistry == nil {
		return
	}
	if _, err := d.serveLockFile.Stat(); err != nil {
		return
	}
	store, err := NewManagedEndpointKeyStore(d.nativeRegistry)
	if err != nil {
		d.Log.Warn("closed managed endpoint keys unavailable")
		return
	}
	d.managedEndpointKeys = store
}
