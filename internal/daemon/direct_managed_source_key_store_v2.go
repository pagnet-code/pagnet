//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
	"golang.org/x/sys/unix"
)

const nativeDirectManagedSourceKeyNamespaceV2 = "closed-direct-managed-source-v2-keys"

var errDirectManagedSourceKeyV2 = errors.New("closed direct managed source key unavailable, unsafe or conflicting")

// DirectManagedSourceKeyStoreV2 is dormant and retains binding-specific S keys.
// Records and files have fixed byte bounds. Aggregate retention/retirement must
// be designed before enabling dispatch; custody tombstones cannot be pruned to
// regain capacity without reopening an already spent creation identity. It never uses a
// source holder or managed endpoint slot and grants no activation authority.
// Callbacks must authenticate the exact instance, principal and native worker;
// matching the host session alone does not authenticate a source subject.
type DirectManagedSourceKeyStoreV2 struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	now          func() time.Time
	sync         func(*os.File) error
}

func (s DirectManagedSourceKeyStoreV2) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "DirectManagedSourceKeyStoreV2{closed}")
}
func NewDirectManagedSourceKeyStoreV2(r *NativeWorkerRegistry) (*DirectManagedSourceKeyStoreV2, error) {
	if r == nil {
		return nil, errDirectManagedSourceKeyV2
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var id string
	if err := r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errDirectManagedSourceKeyV2
	}
	return &DirectManagedSourceKeyStoreV2{registry: r, installation: domain.ID(id), now: time.Now, sync: (*os.File).Sync}, nil
}
func directManagedSourceSessionMatchesV2(s transport.DirectManagedSourceBindingV2, session transport.HostSessionPayload) bool {
	return session.OwnershipScope == "personal" && s.OwnershipScope == session.OwnershipScope && s.TenantID.String() == session.TenantID && s.AccountID.String() == session.AccountID && s.HostID.String() == session.HostID && s.HostCredentialID.String() == session.HostCredentialID && s.NativeAdmissionID.String() == session.NativeAdmissionID && s.ConnectionIncarnationID == s.NativeAdmissionID && s.RunnerID.String() == session.RunnerID && s.RunnerConnectedAt.Equal(session.RunnerEpoch) && s.BootID == session.BootID
}
func directManagedSourceSlotIdentityV2(installation domain.ID, server string, subject transport.DirectManagedSourceBindingV2) []byte {
	raw, _ := json.Marshal(struct {
		Installation domain.ID                              `json:"installationId"`
		Server       string                                 `json:"serverUrl"`
		Role         string                                 `json:"role"`
		Subject      transport.DirectManagedSourceBindingV2 `json:"subject"`
	}{installation, server, "S", subject})
	return raw
}
func directManagedSourceKeyScopeV2(installation domain.ID, server string, subject transport.DirectManagedSourceBindingV2) string {
	sum := sha256.Sum256(append([]byte("pagnet/local-direct-managed-source-slot/v2/"), directManagedSourceSlotIdentityV2(installation, server, subject)...))
	return hex.EncodeToString(sum[:])
}

// Current server enrollment supports only the initial binding generation.
func directManagedSourceInitialBindingV2(subject transport.DirectManagedSourceBindingV2) bool {
	return subject.BindingGeneration == "1" && subject.PredecessorBindingID == "" && subject.PreviousCredentialID == ""
}

// The grant is process-local and consumable exactly once. Its durable journal
// fence is committed before issuance; losing it cannot authorize another attempt.
type directManagedSourceKeyCreationGrantV2 struct {
	mu           sync.Mutex
	request      []byte
	installation domain.ID
	server       string
	consumed     bool
}

func (g *directManagedSourceKeyCreationGrantV2) consume(request []byte, installation domain.ID, server string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.consumed {
		return false
	}
	g.consumed = true
	return bytes.Equal(g.request, request) && g.installation == installation && g.server == server
}

type directManagedSourceKeyRecordV2 struct {
	Reservation transport.DirectManagedSourceKeyReservationV2 `json:"reservation"`
	Private     []byte                                        `json:"private"`
}

func loadDirectManagedSourceKeyV2(file *os.File) (r directManagedSourceKeyRecordV2, err error) {
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
		return r, errDirectManagedSourceKeyV2
	}
	encoded, _ := json.Marshal(r)
	defer clear(encoded)
	if !bytes.Equal(raw, encoded) {
		return r, errDirectManagedSourceKeyV2
	}
	if _, err = r.Reservation.CanonicalBytes(); err != nil {
		return r, errDirectManagedSourceKeyV2
	}
	key, err := ecdh.X25519().NewPrivateKey(r.Private)
	if err != nil || r.Reservation.X25519 != hex.EncodeToString(key.PublicKey().Bytes()) {
		return r, errDirectManagedSourceKeyV2
	}
	valid = true
	return r, nil
}

// Reserve consumes BeginKeyReservation's process-local grant and commits a
// single allocation attempt before generating a private key.
// An interrupted attempt is never regenerated, including after loss of its file.
func (s *DirectManagedSourceKeyStoreV2) Reserve(command transport.DirectManagedSourcePrepareCommandV2, server string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheckV2, grant *directManagedSourceKeyCreationGrantV2) (transport.DirectManagedSourceKeyReservationV2, error) {
	return s.reserve(command, server, session, verify, false, grant)
}
func (s *DirectManagedSourceKeyStoreV2) RecoverReservation(command transport.DirectManagedSourcePrepareCommandV2, server string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheckV2) (transport.DirectManagedSourceKeyReservationV2, error) {
	return s.reserve(command, server, session, verify, true, nil)
}
func (s *DirectManagedSourceKeyStoreV2) reserve(command transport.DirectManagedSourcePrepareCommandV2, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheckV2, recovery bool, grant *directManagedSourceKeyCreationGrantV2) (transport.DirectManagedSourceKeyReservationV2, error) {
	empty := transport.DirectManagedSourceKeyReservationV2{}
	if s == nil || s.registry == nil || s.now == nil || s.sync == nil || verify == nil {
		return empty, errDirectManagedSourceKeyV2
	}
	request, err := command.CanonicalBytes()
	if err != nil {
		return empty, errDirectManagedSourceKeyV2
	}
	command, err = transport.DecodeDirectManagedSourcePrepareCommandV2(request)
	server := managedPrepareServerOrigin(configuredServer)
	if err != nil || server == "" || len(server) > 2048 || legacyTextServiceServer(configuredServer) != server || !directManagedSourceSessionMatchesV2(command.Subject, session) || !directManagedSourceInitialBindingV2(command.Subject) || !s.now().Before(command.Subject.EnrollmentExpiresAt) {
		return empty, errDirectManagedSourceKeyV2
	}
	if !recovery && !grant.consume(request, s.installation, server) {
		return empty, errDirectManagedSourceKeyV2
	}
	requestDigest := sha256.Sum256(request)
	if err = verify(command, server, session); err != nil {
		return empty, err
	}
	var result transport.DirectManagedSourceKeyReservationV2
	err = s.withKeyLocked(!recovery, func(conn *sql.Conn, dir *os.File) error {
		subject := command.Subject
		name := directManagedSourceKeyScopeV2(s.installation, server, subject)
		var installation string
		if err := conn.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != s.installation.String() || !s.now().Before(subject.EnrollmentExpiresAt) {
			return errDirectManagedSourceKeyV2
		}
		var scope, storedInstallation string
		var retained, retainedDigest, reserved []byte
		err := conn.QueryRowContext(context.Background(), `SELECT scope,installation_id,request,request_digest,reservation FROM native_direct_managed_source_v2_keys WHERE binding_id=?`, subject.ID).Scan(&scope, &storedInstallation, &retained, &retainedDigest, &reserved)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists && (scope != name || storedInstallation != installation || !bytes.Equal(retained, request) || !bytes.Equal(retainedDigest, requestDigest[:]) || len(reserved) == 0) {
			return errDirectManagedSourceKeyV2
		}
		var stat unix.Stat_t
		if err = unix.Fstatat(int(dir.Fd()), name+".pending", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return errDirectManagedSourceKeyV2
		}
		file, fileErr := nativeShareHolderOpen(dir, name+".json", false)
		if exists {
			if fileErr != nil {
				return errDirectManagedSourceKeyV2
			}
			defer file.Close()
			record, err := loadDirectManagedSourceKeyV2(file)
			defer clear(record.Private)
			raw, _ := record.Reservation.CanonicalBytes()
			if err != nil || record.Reservation.VerifySubject(subject) != nil || record.Reservation.InstallationID != s.installation || record.Reservation.ServerURL != server || !bytes.Equal(raw, reserved) {
				return errDirectManagedSourceKeyV2
			}
			result = record.Reservation
			return nil
		}
		if file != nil {
			file.Close()
		}
		if recovery || !errors.Is(fileErr, unix.ENOENT) {
			return errDirectManagedSourceKeyV2
		}
		// The in-memory grant supplements, never replaces, its durable fence.
		var started int
		if err = conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM native_direct_managed_source_v2_prepare_commands WHERE command_id=? AND binding_id=? AND installation_id=? AND server_url=? AND request=? AND request_digest=? AND state='reserved' AND key_started=1`, command.CommandID, subject.ID, installation, server, request, requestDigest[:]).Scan(&started); err != nil || started != 1 {
			return errDirectManagedSourceKeyV2
		}
		if _, err = conn.ExecContext(context.Background(), `INSERT INTO native_direct_managed_source_v2_keys(binding_id,scope,installation_id,request,request_digest,reservation) VALUES(?,?,?,?,?,NULL)`, subject.ID, name, installation, request, requestDigest[:]); err != nil {
			return err
		}
		if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return err
		}
		if !s.now().Before(subject.EnrollmentExpiresAt) {
			return errDirectManagedSourceKeyV2
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		private := key.Bytes()
		defer clear(private)
		reservation := transport.DirectManagedSourceKeyReservationV2{Subject: subject, ServerURL: server, InstallationID: s.installation, KeyGeneration: 1, X25519: hex.EncodeToString(key.PublicKey().Bytes())}
		reservation.EnrollmentDigest, err = reservation.Digest()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(directManagedSourceKeyRecordV2{reservation, private})
		defer clear(raw)
		if err != nil || len(raw) > nativeShareHolderMaxBytes {
			return errDirectManagedSourceKeyV2
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
		if !s.now().Before(subject.EnrollmentExpiresAt) {
			return errDirectManagedSourceKeyV2
		}
		if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		public, _ := reservation.CanonicalBytes()
		updated, err := conn.ExecContext(context.Background(), `UPDATE native_direct_managed_source_v2_keys SET reservation=? WHERE binding_id=? AND scope=? AND installation_id=? AND request=? AND reservation IS NULL AND EXISTS(SELECT 1 FROM native_registry_metadata WHERE name='installation_id' AND value=?)`, public, subject.ID, name, installation, request, installation)
		if err != nil {
			return err
		}
		if n, err := updated.RowsAffected(); err != nil || n != 1 {
			return errDirectManagedSourceKeyV2
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
	if !s.now().Before(command.Subject.EnrollmentExpiresAt) {
		return empty, errDirectManagedSourceKeyV2
	}
	return result, nil
}

// Lock order is registry mutex, dedicated namespace flock, SQLite reservation.
func (s *DirectManagedSourceKeyStoreV2) withKeyLocked(create bool, fn func(*sql.Conn, *os.File) error) error {
	return s.withKeyLockedScoped(create, func(conn *sql.Conn, dir *os.File, _ *func()) error {
		return fn(conn, dir)
	})
}

// withKeyLockedScoped owns registered custody through transaction completion,
// including panic unwinding. A failed ROLLBACK discards and closes the connection
// before release so an unfinished transaction cannot return to the pool.
func (s *DirectManagedSourceKeyStoreV2) withKeyLockedScoped(create bool, fn func(*sql.Conn, *os.File, *func()) error) error {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	var dir *os.File
	if create {
		dir, err = nativeShareHolderChild(root, nativeDirectManagedSourceKeyNamespaceV2)
	} else {
		dir, err = nativeShareHolderExistingChild(root, nativeDirectManagedSourceKeyNamespaceV2)
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
	var release func()
	committed := false
	defer func() {
		if !committed {
			if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				_ = conn.Close()
			}
		}
		if release != nil {
			release()
		}
	}()
	if err = fn(conn, dir, &release); err != nil {
		return err
	}
	_, err = conn.ExecContext(context.Background(), "COMMIT")
	committed = err == nil
	return err
}
