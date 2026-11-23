//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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
// no export, activation, credential, challenge, or transport handler. A future
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
	if server == "" || subject.TenantID.String() != session.TenantID || subject.AccountID.String() != session.AccountID || subject.OwnershipScope != session.OwnershipScope || subject.HostID.String() != session.HostID || subject.HostCredentialID.String() != session.HostCredentialID || subject.NativeAdmissionID.String() != session.NativeAdmissionID || subject.RunnerID.String() != session.RunnerID || !subject.RunnerConnectedAt.Equal(session.RunnerEpoch) || subject.BootID != session.BootID || !s.now().Before(subject.ExpiresAt) {
		return empty, errManagedEndpointKey
	}
	request, _ := json.Marshal(struct {
		Server  string                                 `json:"serverUrl"`
		Subject transport.ManagedEndpointBindingIntent `json:"subject"`
	}{server, subject})
	// Key custody scope excludes enrollment identity, so another enrollment cannot
	// replace a reserved key for the same exact endpoint incarnation/generation.
	scopeRaw, _ := json.Marshal(struct {
		Installation                                              domain.ID
		Server                                                    string
		Tenant, Account, Principal, Instance, Endpoint, Admission domain.ID
		Generation                                                uint64
	}{s.installation, server, subject.TenantID, subject.AccountID, subject.PrincipalID, subject.InstanceID, subject.EndpointID, subject.NativeAdmissionID, 1})
	scopeSum := sha256.Sum256(scopeRaw)
	name := hex.EncodeToString(scopeSum[:])
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
	var stat unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return empty, errManagedEndpointKey
	}
	file, err := nativeShareHolderOpen(dir, name+".json", false)
	if exists {
		if file != nil {
			defer file.Close()
		}
		if err != nil || storedScope != name || storedInstallation != installation || !bytes.Equal(storedRequest, request) || len(reserved) == 0 {
			return empty, errManagedEndpointKey
		}
		record, err := loadManagedEndpointKey(file)
		if err != nil {
			return empty, err
		}
		defer clear(record.Private)
		raw, _ := json.Marshal(record.Reservation)
		expected := record.Reservation
		expected.Subject = subject
		expected.ServerURL = server
		expected.InstallationID = s.installation
		expected.KeyGeneration = 1
		if !bytes.Equal(raw, reserved) || expected != record.Reservation || !s.now().Before(subject.ExpiresAt) {
			return empty, errManagedEndpointKey
		}
		if !recovery {
			if err = s.sync(dir); err != nil {
				return empty, err
			}
		}
		if err = exec("COMMIT"); err != nil {
			return empty, err
		}
		return record.Reservation, nil
	}
	if file != nil {
		file.Close()
	}
	if recovery {
		return empty, errManagedEndpointKey
	}
	if !errors.Is(err, unix.ENOENT) {
		return empty, errManagedEndpointKey
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
	raw, err := json.Marshal(managedEndpointKeyRecord{Reservation: reservation, Private: private})
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
	public, _ := json.Marshal(reservation)
	result, err := conn.ExecContext(context.Background(), `UPDATE native_managed_endpoint_keys SET reservation=? WHERE enrollment_id=? AND scope=? AND installation_id=? AND request=? AND reservation IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?)`, public, subject.ID, name, installation, request, installation)
	if err != nil {
		return empty, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return empty, errManagedEndpointKey
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
