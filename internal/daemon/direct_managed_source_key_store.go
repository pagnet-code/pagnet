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

const nativeDirectManagedSourceKeyNamespace = "closed-direct-managed-source-keys"

var errDirectManagedSourceKey = errors.New("closed direct managed source key unavailable, unsafe or conflicting")

// DirectManagedSourceKeyStore retains binding-specific S keys. It never uses a
// source holder or managed endpoint slot and grants no activation authority.
// Callbacks must authenticate the exact instance, principal and native worker;
// matching the host session alone does not authenticate a source subject.
type DirectManagedSourceKeyStore struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	now          func() time.Time
	sync         func(*os.File) error
}

func (s DirectManagedSourceKeyStore) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "DirectManagedSourceKeyStore{closed}")
}
func NewDirectManagedSourceKeyStore(r *NativeWorkerRegistry) (*DirectManagedSourceKeyStore, error) {
	if r == nil {
		return nil, errDirectManagedSourceKey
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var id string
	if err := r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errDirectManagedSourceKey
	}
	return &DirectManagedSourceKeyStore{registry: r, installation: domain.ID(id), now: time.Now, sync: (*os.File).Sync}, nil
}
func directManagedSourceSessionMatches(s transport.DirectManagedSourceBindingV1, session transport.HostSessionPayload) bool {
	return session.OwnershipScope == "personal" && s.OwnershipScope == session.OwnershipScope && s.TenantID.String() == session.TenantID && s.AccountID.String() == session.AccountID && s.HostID.String() == session.HostID && s.HostCredentialID.String() == session.HostCredentialID && s.NativeAdmissionID.String() == session.NativeAdmissionID && s.ConnectionIncarnationID == s.NativeAdmissionID && s.RunnerID.String() == session.RunnerID && s.RunnerConnectedAt.Equal(session.RunnerEpoch) && s.BootID == session.BootID
}
func directManagedSourceSlotIdentity(installation domain.ID, server string, subject transport.DirectManagedSourceBindingV1) []byte {
	raw, _ := json.Marshal(struct {
		Installation domain.ID                              `json:"installationId"`
		Server       string                                 `json:"serverUrl"`
		Role         string                                 `json:"role"`
		Subject      transport.DirectManagedSourceBindingV1 `json:"subject"`
	}{installation, server, "S", subject})
	return raw
}
func directManagedSourceKeyScope(installation domain.ID, server string, subject transport.DirectManagedSourceBindingV1) string {
	sum := sha256.Sum256(directManagedSourceSlotIdentity(installation, server, subject))
	return hex.EncodeToString(sum[:])
}

type directManagedSourceKeyRecord struct {
	Reservation transport.DirectManagedSourceKeyReservation `json:"reservation"`
	Private     []byte                                      `json:"private"`
}

func loadDirectManagedSourceKey(file *os.File) (r directManagedSourceKeyRecord, err error) {
	valid := false
	defer func() {
		if !valid {
			clear(r.Private)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(file, nativeShareHolderMaxBytes+1))
	defer clear(raw)
	if err != nil {
		return r, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > nativeShareHolderMaxBytes || decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
		return r, errDirectManagedSourceKey
	}
	encoded, _ := json.Marshal(r)
	defer clear(encoded)
	if !bytes.Equal(raw, encoded) {
		return r, errDirectManagedSourceKey
	}
	if _, err = r.Reservation.CanonicalBytes(); err != nil {
		return r, errDirectManagedSourceKey
	}
	key, err := ecdh.X25519().NewPrivateKey(r.Private)
	if err != nil || r.Reservation.X25519 != hex.EncodeToString(key.PublicKey().Bytes()) {
		return r, errDirectManagedSourceKey
	}
	valid = true
	return r, nil
}

// Reserve commits a single allocation attempt before generating a private key.
// An interrupted attempt is never regenerated, including after loss of its file.
func (s *DirectManagedSourceKeyStore) Reserve(command transport.DirectManagedSourcePrepareCommand, server string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck) (transport.DirectManagedSourceKeyReservation, error) {
	return s.reserve(command, server, session, verify, false)
}
func (s *DirectManagedSourceKeyStore) RecoverReservation(command transport.DirectManagedSourcePrepareCommand, server string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck) (transport.DirectManagedSourceKeyReservation, error) {
	return s.reserve(command, server, session, verify, true)
}
func (s *DirectManagedSourceKeyStore) reserve(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck, recovery bool) (transport.DirectManagedSourceKeyReservation, error) {
	empty := transport.DirectManagedSourceKeyReservation{}
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || verify == nil {
		return empty, errDirectManagedSourceKey
	}
	request, err := command.CanonicalBytes()
	if err != nil {
		return empty, errDirectManagedSourceKey
	}
	command, err = transport.DecodeDirectManagedSourcePrepareCommand(request)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server || !directManagedSourceSessionMatches(command.Subject, session) || !s.now().Before(command.Subject.ExpiresAt) {
		return empty, errDirectManagedSourceKey
	}
	if err = verify(command, server, session); err != nil {
		return empty, err
	}
	var result transport.DirectManagedSourceKeyReservation
	err = s.withKeyLocked(!recovery, func(conn *sql.Conn, dir *os.File) error {
		subject := command.Subject
		name := directManagedSourceKeyScope(s.installation, server, subject)
		var installation string
		if err := conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != s.installation.String() || !s.now().Before(subject.ExpiresAt) {
			return errDirectManagedSourceKey
		}
		var scope, storedInstallation string
		var retained, reserved []byte
		err := conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,reservation FROM native_direct_managed_source_keys WHERE binding_id=?`, subject.ID).Scan(&scope, &storedInstallation, &retained, &reserved)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists && (scope != name || storedInstallation != installation || !bytes.Equal(retained, request) || len(reserved) == 0) {
			return errDirectManagedSourceKey
		}
		var stat unix.Stat_t
		if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errDirectManagedSourceKey
		}
		file, fileErr := nativeShareHolderOpen(dir, name+".json", false)
		if exists {
			if fileErr != nil {
				return errDirectManagedSourceKey
			}
			defer file.Close()
			record, err := loadDirectManagedSourceKey(file)
			defer clear(record.Private)
			raw, _ := record.Reservation.CanonicalBytes()
			if err != nil || record.Reservation.Subject != subject || record.Reservation.InstallationID != s.installation || record.Reservation.ServerURL != server || !bytes.Equal(raw, reserved) {
				return errDirectManagedSourceKey
			}
			result = record.Reservation
			return nil
		}
		if file != nil {
			file.Close()
		}
		if recovery || !errors.Is(fileErr, unix.ENOENT) {
			return errDirectManagedSourceKey
		}
		if _, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_keys(binding_id,scope,installation_id,request,reservation) VALUES(?,?,?,?,NULL)`, subject.ID, name, installation, request); err != nil {
			return err
		}
		if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return err
		}
		if !s.now().Before(subject.ExpiresAt) {
			return errDirectManagedSourceKey
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		private := key.Bytes()
		defer clear(private)
		reservation := transport.DirectManagedSourceKeyReservation{Subject: subject, ServerURL: server, InstallationID: s.installation, KeyGeneration: 1, X25519: hex.EncodeToString(key.PublicKey().Bytes())}
		reservation.EnrollmentDigest, err = reservation.Digest()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(directManagedSourceKeyRecord{reservation, private})
		defer clear(raw)
		if err != nil {
			return err
		}
		pending, err := nativeShareHolderOpen(dir, name+".pending", true)
		if err != nil {
			return err
		}
		if _, err = pending.Write(raw); err == nil {
			err = s.sync(pending)
		}
		closeErr := pending.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = unix.Linkat(int(dir.Fd()), name+".pending", int(dir.Fd()), name+".json", 0); err != nil {
			return err
		}
		if err = unix.Unlinkat(int(dir.Fd()), name+".pending", 0); err != nil {
			return err
		}
		if err = s.sync(dir); err != nil {
			return err
		}
		if !s.now().Before(subject.ExpiresAt) {
			return errDirectManagedSourceKey
		}
		if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		public, _ := reservation.CanonicalBytes()
		updated, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_keys SET reservation=? WHERE binding_id=? AND scope=? AND installation_id=? AND request=? AND reservation IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?)`, public, subject.ID, name, installation, request, installation)
		if err != nil {
			return err
		}
		if n, err := updated.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKey
		}
		result = reservation
		return nil
	})
	if err != nil {
		return empty, err
	}
	if err = verify(command, server, session); err != nil {
		return empty, err
	}
	if !s.now().Before(command.Subject.ExpiresAt) {
		return empty, errDirectManagedSourceKey
	}
	return result, nil
}

// Lock order is registry mutex, dedicated namespace flock, SQLite reservation.
func (s *DirectManagedSourceKeyStore) withKeyLocked(create bool, fn func(*sql.Conn, *os.File) error) error {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	var dir *os.File
	if create {
		dir, err = nativeShareHolderChild(root, nativeDirectManagedSourceKeyNamespace)
	} else {
		dir, err = nativeShareHolderExistingChild(root, nativeDirectManagedSourceKeyNamespace)
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLockMode(dir, create)
	if err != nil {
		return err
	}
	defer lock.Close()
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	if err = fn(conn, dir); err != nil {
		return err
	}
	_, err = conn.ExecContext(context.Background(), "COMMIT")
	return err
}
