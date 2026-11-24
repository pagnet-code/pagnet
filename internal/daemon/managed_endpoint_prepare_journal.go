//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const managedEndpointPrepareJournalNamespace = "closed-managed-endpoint-prepare"

var errManagedEndpointPrepareJournal = errors.New("closed managed endpoint prepare journal unavailable, unsafe or conflicting")

// ManagedEndpointPrepareScopeCheck must independently verify current server,
// socket/session and local worker ownership for this exact command and configured
// server. It is called on every operation, including terminal replay. The journal
// authenticates nothing. The callback runs without registry, namespace or SQLite
// locks and may inspect the registry. Its result is revalidated against retained
// journal state before any transition.
type ManagedEndpointPrepareScopeCheck func(transport.ManagedEndpointPrepareCommand, string) error

// ManagedEndpointPrepareResult contains closed evidence only. Created is true
// only for the operation that durably reserved a new command; it does not grant
// key creation. Only BeginKeyReservation's KeyStarted grant permits Reserve.
// Every other reserved retry must recover, even after a process crash.
type ManagedEndpointPrepareResult struct {
	State   string
	ACK     []byte
	Created bool
	// KeyStarted grants only the operation that committed the start fence
	// permission to call Reserve. Every other reserved retry must recover only.
	KeyStarted bool
}

// ManagedEndpointPrepareJournal retains immutable command associations and exact
// canonical ACKs. It never generates or reserves keys, credentials or authority.
// Lock order is registry mutex, namespace flock, SQLite write reservation.
type ManagedEndpointPrepareJournal struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	now          func() time.Time
}

func (s ManagedEndpointPrepareJournal) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "ManagedEndpointPrepareJournal{closed}")
}

func NewManagedEndpointPrepareJournal(r *NativeWorkerRegistry) (*ManagedEndpointPrepareJournal, error) {
	if r == nil {
		return nil, errManagedEndpointPrepareJournal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var id string
	if err := r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errManagedEndpointPrepareJournal
	}
	return &ManagedEndpointPrepareJournal{registry: r, installation: domain.ID(id), now: time.Now}, nil
}

// Composition requires the same live serve lock as the other closed stores.
func (d *Daemon) newManagedEndpointPrepareJournal() (*ManagedEndpointPrepareJournal, error) {
	if d.serveLockFile == nil || d.nativeRegistry == nil {
		return nil, errManagedEndpointPrepareJournal
	}
	if _, err := d.serveLockFile.Stat(); err != nil {
		return nil, errManagedEndpointPrepareJournal
	}
	return NewManagedEndpointPrepareJournal(d.nativeRegistry)
}

func (s *ManagedEndpointPrepareJournal) Reserve(command transport.ManagedEndpointPrepareCommand, configuredServer string, verify ManagedEndpointPrepareScopeCheck) (ManagedEndpointPrepareResult, error) {
	return s.apply(command, configuredServer, verify, "", nil)
}

// Succeed accepts only a canonical ACK bound to the complete retained command.
// Terminal records may be retried with identical bytes, but never rewritten.
func (s *ManagedEndpointPrepareJournal) Succeed(command transport.ManagedEndpointPrepareCommand, configuredServer string, verify ManagedEndpointPrepareScopeCheck, ack []byte) (ManagedEndpointPrepareResult, error) {
	decoded, err := transport.DecodeManagedEndpointPrepareACK(ack, command)
	if err != nil {
		return ManagedEndpointPrepareResult{}, errManagedEndpointPrepareJournal
	}
	canonical, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, ack) {
		return ManagedEndpointPrepareResult{}, errManagedEndpointPrepareJournal
	}
	return s.apply(command, configuredServer, verify, "succeeded", canonical)
}

// Fail stores only the fixed, diagnostic-free protocol failure ACK.
func (s *ManagedEndpointPrepareJournal) Fail(command transport.ManagedEndpointPrepareCommand, configuredServer string, verify ManagedEndpointPrepareScopeCheck) (ManagedEndpointPrepareResult, error) {
	ack, err := (transport.ManagedEndpointPrepareFailureACK{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: command.CommandID, Error: transport.ManagedEndpointPrepareFailure}).CanonicalBytes()
	if err != nil {
		return ManagedEndpointPrepareResult{}, errManagedEndpointPrepareJournal
	}
	return s.apply(command, configuredServer, verify, "failed", ack)
}

// BeginKeyReservation durably grants exactly one key creation attempt. A crash
// after this commit and before key creation deliberately fails closed: retries
// must use RecoverReservation, never Reserve.
func (s *ManagedEndpointPrepareJournal) BeginKeyReservation(command transport.ManagedEndpointPrepareCommand, configuredServer string, verify ManagedEndpointPrepareScopeCheck) (ManagedEndpointPrepareResult, error) {
	return s.apply(command, configuredServer, verify, "key_started", nil)
}

type managedPrepareSnapshot struct {
	Enrollment, Installation, Server, Expiry, State string
	Request, Digest, ACK                            []byte
	KeyStarted                                      int
	Exists                                          bool
}

func (s *ManagedEndpointPrepareJournal) read(conn *sql.Conn, command transport.ManagedEndpointPrepareCommand, server string, request, digest []byte) (managedPrepareSnapshot, error) {
	var row managedPrepareSnapshot
	var installation string
	ctx := context.Background()
	if err := conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.installation) || !s.now().Before(command.Subject.ExpiresAt) {
		return row, errManagedEndpointPrepareJournal
	}
	err := conn.QueryRowContext(ctx, `SELECT enrollment_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started FROM native_managed_endpoint_prepare_commands WHERE command_id=?`, command.CommandID).Scan(&row.Enrollment, &row.Installation, &row.Server, &row.Request, &row.Digest, &row.Expiry, &row.State, &row.ACK, &row.KeyStarted)
	if errors.Is(err, sql.ErrNoRows) {
		return row, nil
	}
	if err != nil {
		return row, err
	}
	row.Exists = true
	if row.Enrollment != string(command.Subject.ID) || row.Installation != string(s.installation) || row.Server != server || row.Expiry != command.Subject.ExpiresAt.Format(time.RFC3339Nano) || !bytes.Equal(row.Request, request) || !bytes.Equal(row.Digest, digest) || (row.KeyStarted != 0 && row.KeyStarted != 1) {
		return row, errManagedEndpointPrepareJournal
	}
	switch row.State {
	case "reserved":
		if row.ACK != nil {
			return row, errManagedEndpointPrepareJournal
		}
	case "succeeded":
		if !managedEndpointPrepareSuccessForScope(row.ACK, command, row.Server, domain.ID(row.Installation)) {
			return row, errManagedEndpointPrepareJournal
		}
	case "failed":
		decoded, err := transport.DecodeManagedEndpointPrepareFailureACK(row.ACK, command.CommandID)
		if err != nil {
			return row, errManagedEndpointPrepareJournal
		}
		canonical, err := decoded.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, row.ACK) {
			return row, errManagedEndpointPrepareJournal
		}
	default:
		return row, errManagedEndpointPrepareJournal
	}
	return row, nil
}

// withLocked closes the transaction and every lock before returning, including
// during the initial snapshot. In particular no connection is held by verify.
func (s *ManagedEndpointPrepareJournal) withLocked(fn func(*sql.Conn) error) error {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := nativeShareHolderChild(root, managedEndpointPrepareJournalNamespace)
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx := context.Background()
	conn, err := s.registry.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "ROLLBACK") }()
	if err = fn(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func (s *ManagedEndpointPrepareJournal) apply(command transport.ManagedEndpointPrepareCommand, configuredServer string, verify ManagedEndpointPrepareScopeCheck, terminal string, ack []byte) (ManagedEndpointPrepareResult, error) {
	empty := ManagedEndpointPrepareResult{}
	if s == nil || s.registry == nil || s.now == nil || verify == nil {
		return empty, errManagedEndpointPrepareJournal
	}
	request, err := command.CanonicalBytes()
	if err != nil {
		return empty, errManagedEndpointPrepareJournal
	}
	command, err = transport.DecodeManagedEndpointPrepareCommand(request)
	server := textServiceServer(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server {
		return empty, errManagedEndpointPrepareJournal
	}
	digest := sha256.Sum256(request)
	var snapshot managedPrepareSnapshot
	err = s.withLocked(func(conn *sql.Conn) error {
		var err error
		snapshot, err = s.read(conn, command, server, request, digest[:])
		if err == nil && !snapshot.Exists && terminal != "" {
			return errManagedEndpointPrepareJournal
		}
		return err
	})
	if err != nil {
		return empty, err
	}
	if snapshot.Exists {
		command, err = transport.DecodeManagedEndpointPrepareCommand(snapshot.Request)
		if err != nil {
			return empty, errManagedEndpointPrepareJournal
		}
	}
	if verify(command, server) != nil {
		return empty, errManagedEndpointPrepareJournal
	}
	var result ManagedEndpointPrepareResult
	err = s.withLocked(func(conn *sql.Conn) error {
		row, err := s.read(conn, command, server, request, digest[:])
		if err != nil {
			return err
		}
		// An exact concurrent initial reservation is idempotent. Every observed
		// existing association must retain its state throughout verification.
		if snapshot.Exists {
			if !reflect.DeepEqual(snapshot, row) {
				return errManagedEndpointPrepareJournal
			}
		} else if row.Exists && (row.State != "reserved" || row.KeyStarted != 0) {
			return errManagedEndpointPrepareJournal
		}
		ctx := context.Background()
		if !row.Exists {
			if _, err = conn.ExecContext(ctx, `INSERT INTO native_managed_endpoint_prepare_commands(command_id,enrollment_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started) VALUES(?,?,?,?,?,?,?,'reserved',NULL,0)`, command.CommandID, command.Subject.ID, s.installation, server, request, digest[:], command.Subject.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
				return err
			}
			row.State = "reserved"
			result.Created = true
		}
		if terminal == "key_started" {
			if row.State != "reserved" {
				return errManagedEndpointPrepareJournal
			}
			updated, err := conn.ExecContext(ctx, `UPDATE native_managed_endpoint_prepare_commands SET key_started=1 WHERE command_id=? AND state='reserved' AND key_started=0`, command.CommandID)
			if err != nil {
				return err
			}
			n, err := updated.RowsAffected()
			if err != nil {
				return err
			}
			result.KeyStarted = n == 1
		} else if terminal != "" {
			if terminal == "succeeded" && !managedEndpointPrepareSuccessForScope(ack, command, server, s.installation) {
				return errManagedEndpointPrepareJournal
			}
			if row.State != "reserved" {
				if row.State != terminal || !bytes.Equal(row.ACK, ack) {
					return errManagedEndpointPrepareJournal
				}
			} else {
				if _, err = conn.ExecContext(ctx, `UPDATE native_managed_endpoint_prepare_commands SET state=?,ack=? WHERE command_id=? AND state='reserved'`, terminal, ack, command.CommandID); err != nil {
					return err
				}
				row.State, row.ACK = terminal, ack
			}
		}
		result.State, result.ACK = row.State, bytes.Clone(row.ACK)
		return nil
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}

// The wire decoder binds the command subject; custody provenance is additionally
// bound here to the journal's retained local installation and configured server.
func managedEndpointPrepareSuccessForScope(raw []byte, command transport.ManagedEndpointPrepareCommand, server string, installation domain.ID) bool {
	decoded, err := transport.DecodeManagedEndpointPrepareACK(raw, command)
	if err != nil || decoded.Reservation.ServerURL != server || decoded.Reservation.InstallationID != installation {
		return false
	}
	canonical, err := decoded.CanonicalBytes()
	return err == nil && bytes.Equal(canonical, raw)
}
