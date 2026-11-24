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

const directManagedSourcePrepareJournalNamespace = "closed-direct-managed-source-prepare"

var errDirectManagedSourcePrepareJournal = errors.New("closed direct managed source prepare journal unavailable, unsafe or conflicting")

// DirectManagedSourcePrepareScopeCheck must independently verify current server,
// socket/session and local worker ownership for this exact command and configured
// server. It is called on every operation, including terminal replay. The journal
// authenticates nothing. The callback runs without registry, namespace or SQLite
// locks and may inspect the registry. Its result is revalidated against retained
// journal state before any transition.
type DirectManagedSourcePrepareScopeCheck func(transport.DirectManagedSourcePrepareCommand, string, transport.HostSessionPayload) error

// DirectManagedSourcePrepareResult contains closed evidence only. Created is true
// only for the operation that durably reserved a new command; it does not grant
// key creation. Only BeginKeyReservation's KeyStarted grant permits Reserve.
// Every other reserved retry must recover, even after a process crash.
type DirectManagedSourcePrepareResult struct {
	State   string
	ACK     []byte
	Created bool
	// KeyStarted grants only the operation that committed the start fence
	// permission to call Reserve. Every other reserved retry must recover only.
	KeyStarted bool
}

// DirectManagedSourcePrepareJournal retains immutable command associations and exact
// canonical ACKs. It never generates or reserves keys, credentials or authority.
// Lock order is registry mutex, namespace flock, SQLite write reservation.
type DirectManagedSourcePrepareJournal struct {
	registry     *NativeWorkerRegistry
	installation domain.ID
	now          func() time.Time
}

func (s DirectManagedSourcePrepareJournal) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "DirectManagedSourcePrepareJournal{closed}")
}

func NewDirectManagedSourcePrepareJournal(r *NativeWorkerRegistry) (*DirectManagedSourcePrepareJournal, error) {
	if r == nil {
		return nil, errDirectManagedSourcePrepareJournal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var id string
	if err := r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil || !nativeShareEpochStageID(domain.ID(id)) {
		return nil, errDirectManagedSourcePrepareJournal
	}
	return &DirectManagedSourcePrepareJournal{registry: r, installation: domain.ID(id), now: time.Now}, nil
}

func (s *DirectManagedSourcePrepareJournal) Reserve(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck) (DirectManagedSourcePrepareResult, error) {
	return s.apply(command, configuredServer, session, verify, "", nil)
}

// Succeed accepts only a canonical ACK bound to the complete retained command.
// Terminal records may be retried with identical bytes, but never rewritten.
func (s *DirectManagedSourcePrepareJournal) Succeed(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck, ack []byte) (DirectManagedSourcePrepareResult, error) {
	decoded, err := transport.DecodeDirectManagedSourcePrepareACK(ack, command)
	if err != nil {
		return DirectManagedSourcePrepareResult{}, errDirectManagedSourcePrepareJournal
	}
	canonical, err := decoded.CanonicalBytes()
	if err != nil || !bytes.Equal(canonical, ack) {
		return DirectManagedSourcePrepareResult{}, errDirectManagedSourcePrepareJournal
	}
	return s.apply(command, configuredServer, session, verify, "succeeded", canonical)
}

// Fail stores only the fixed, diagnostic-free protocol failure ACK.
func (s *DirectManagedSourcePrepareJournal) Fail(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck) (DirectManagedSourcePrepareResult, error) {
	ack, err := (transport.DirectManagedSourcePrepareFailureACK{ProtocolVersion: transport.DirectManagedSourcePrepareProtocol, CommandID: command.CommandID, Error: transport.DirectManagedSourcePrepareFailure}).CanonicalBytes()
	if err != nil {
		return DirectManagedSourcePrepareResult{}, errDirectManagedSourcePrepareJournal
	}
	return s.apply(command, configuredServer, session, verify, "failed", ack)
}

// BeginKeyReservation durably grants exactly one key creation attempt. A crash
// after this commit and before key creation deliberately fails closed: retries
// must use RecoverReservation, never Reserve.
func (s *DirectManagedSourcePrepareJournal) BeginKeyReservation(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck) (DirectManagedSourcePrepareResult, error) {
	return s.apply(command, configuredServer, session, verify, "key_started", nil)
}

type directManagedSourcePrepareSnapshot struct {
	Enrollment, Installation, Server, Expiry, State string
	Request, Digest, ACK                            []byte
	KeyStarted                                      int
	Exists                                          bool
}

func (s *DirectManagedSourcePrepareJournal) read(conn *sql.Conn, command transport.DirectManagedSourcePrepareCommand, server string, request, digest []byte) (directManagedSourcePrepareSnapshot, error) {
	var row directManagedSourcePrepareSnapshot
	var installation string
	ctx := context.Background()
	if err := conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.installation) || !s.now().Before(command.Subject.ExpiresAt) {
		return row, errDirectManagedSourcePrepareJournal
	}
	err := conn.QueryRowContext(ctx, `SELECT binding_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started FROM native_direct_managed_source_prepare_commands WHERE command_id=?`, command.CommandID).Scan(&row.Enrollment, &row.Installation, &row.Server, &row.Request, &row.Digest, &row.Expiry, &row.State, &row.ACK, &row.KeyStarted)
	if errors.Is(err, sql.ErrNoRows) {
		return row, nil
	}
	if err != nil {
		return row, err
	}
	row.Exists = true
	if row.Enrollment != string(command.Subject.ID) || row.Installation != string(s.installation) || row.Server != server || row.Expiry != command.Subject.ExpiresAt.Format(time.RFC3339Nano) || !bytes.Equal(row.Request, request) || !bytes.Equal(row.Digest, digest) || (row.KeyStarted != 0 && row.KeyStarted != 1) {
		return row, errDirectManagedSourcePrepareJournal
	}
	switch row.State {
	case "reserved":
		if row.ACK != nil {
			return row, errDirectManagedSourcePrepareJournal
		}
	case "succeeded":
		if !directManagedSourcePrepareSuccessForScope(row.ACK, command, row.Server, domain.ID(row.Installation)) {
			return row, errDirectManagedSourcePrepareJournal
		}
	case "failed":
		decoded, err := transport.DecodeDirectManagedSourcePrepareFailureACK(row.ACK, command.CommandID)
		if err != nil {
			return row, errDirectManagedSourcePrepareJournal
		}
		canonical, err := decoded.CanonicalBytes()
		if err != nil || !bytes.Equal(canonical, row.ACK) {
			return row, errDirectManagedSourcePrepareJournal
		}
	default:
		return row, errDirectManagedSourcePrepareJournal
	}
	return row, nil
}

// withLocked closes the transaction and every lock before returning, including
// during the initial snapshot. In particular no connection is held by verify.
func (s *DirectManagedSourcePrepareJournal) withLocked(fn func(*sql.Conn) error) error {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := nativeShareHolderChild(root, directManagedSourcePrepareJournalNamespace)
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

func (s *DirectManagedSourcePrepareJournal) apply(command transport.DirectManagedSourcePrepareCommand, configuredServer string, session transport.HostSessionPayload, verify DirectManagedSourcePrepareScopeCheck, terminal string, ack []byte) (DirectManagedSourcePrepareResult, error) {
	empty := DirectManagedSourcePrepareResult{}
	if s == nil || s.registry == nil || s.now == nil || verify == nil {
		return empty, errDirectManagedSourcePrepareJournal
	}
	request, err := command.CanonicalBytes()
	if err != nil {
		return empty, errDirectManagedSourcePrepareJournal
	}
	command, err = transport.DecodeDirectManagedSourcePrepareCommand(request)
	server := textServiceServer(configuredServer)
	if err != nil || server == "" || legacyTextServiceServer(configuredServer) != server || !directManagedSourceSessionMatches(command.Subject, session) {
		return empty, errDirectManagedSourcePrepareJournal
	}
	digest := sha256.Sum256(request)
	var snapshot directManagedSourcePrepareSnapshot
	err = s.withLocked(func(conn *sql.Conn) error {
		var err error
		snapshot, err = s.read(conn, command, server, request, digest[:])
		if err == nil && !snapshot.Exists && terminal != "" {
			return errDirectManagedSourcePrepareJournal
		}
		return err
	})
	if err != nil {
		return empty, err
	}
	if snapshot.Exists {
		command, err = transport.DecodeDirectManagedSourcePrepareCommand(snapshot.Request)
		if err != nil {
			return empty, errDirectManagedSourcePrepareJournal
		}
	}
	if verify(command, server, session) != nil {
		return empty, errDirectManagedSourcePrepareJournal
	}
	var result DirectManagedSourcePrepareResult
	err = s.withLocked(func(conn *sql.Conn) error {
		row, err := s.read(conn, command, server, request, digest[:])
		if err != nil {
			return err
		}
		// An exact concurrent initial reservation is idempotent. Every observed
		// existing association must retain its state throughout verification.
		if snapshot.Exists {
			if !reflect.DeepEqual(snapshot, row) {
				return errDirectManagedSourcePrepareJournal
			}
		} else if row.Exists && (row.State != "reserved" || row.KeyStarted != 0) {
			return errDirectManagedSourcePrepareJournal
		}
		ctx := context.Background()
		if !row.Exists {
			if _, err = conn.ExecContext(ctx, `INSERT INTO native_direct_managed_source_prepare_commands(command_id,binding_id,installation_id,server_url,request,request_digest,expires_at,state,ack,key_started) VALUES(?,?,?,?,?,?,?,'reserved',NULL,0)`, command.CommandID, command.Subject.ID, s.installation, server, request, digest[:], command.Subject.ExpiresAt.Format(time.RFC3339Nano)); err != nil {
				return err
			}
			row.State = "reserved"
			result.Created = true
		}
		if terminal == "key_started" {
			if row.State != "reserved" {
				return errDirectManagedSourcePrepareJournal
			}
			updated, err := conn.ExecContext(ctx, `UPDATE native_direct_managed_source_prepare_commands SET key_started=1 WHERE command_id=? AND state='reserved' AND key_started=0`, command.CommandID)
			if err != nil {
				return err
			}
			n, err := updated.RowsAffected()
			if err != nil {
				return err
			}
			result.KeyStarted = n == 1
		} else if terminal != "" {
			if terminal == "succeeded" && !directManagedSourcePrepareSuccessForScope(ack, command, server, s.installation) {
				return errDirectManagedSourcePrepareJournal
			}
			if row.State != "reserved" {
				if row.State != terminal || !bytes.Equal(row.ACK, ack) {
					return errDirectManagedSourcePrepareJournal
				}
			} else {
				if _, err = conn.ExecContext(ctx, `UPDATE native_direct_managed_source_prepare_commands SET state=?,ack=? WHERE command_id=? AND state='reserved'`, terminal, ack, command.CommandID); err != nil {
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
	if verify(command, server, session) != nil || !s.now().Before(command.Subject.ExpiresAt) {
		return empty, errDirectManagedSourcePrepareJournal
	}
	return result, nil
}

// The wire decoder binds the command subject; custody provenance is additionally
// bound here to the journal's retained local installation and configured server.
func directManagedSourcePrepareSuccessForScope(raw []byte, command transport.DirectManagedSourcePrepareCommand, server string, installation domain.ID) bool {
	decoded, err := transport.DecodeDirectManagedSourcePrepareACK(raw, command)
	if err != nil || decoded.Reservation.ServerURL != server || decoded.Reservation.InstallationID != installation {
		return false
	}
	canonical, err := decoded.CanonicalBytes()
	return err == nil && bytes.Equal(canonical, raw)
}
