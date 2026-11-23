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
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

const managedEndpointPrepareJournalNamespace = "closed-managed-endpoint-prepare"

var errManagedEndpointPrepareJournal = errors.New("closed managed endpoint prepare journal unavailable, unsafe or conflicting")

// ManagedEndpointPrepareScopeCheck must independently verify current server,
// socket/session and local worker ownership for this exact command and configured
// server. It is called on every operation, including terminal replay. The journal
// authenticates nothing. The callback must not reenter the registry or its stores.
type ManagedEndpointPrepareScopeCheck func(transport.ManagedEndpointPrepareCommand, string) error

// ManagedEndpointPrepareResult contains closed evidence only. Created is true
// only for the operation that durably reserved a new command. A reserved retry
// must never start a replacement key reservation, even after a process crash.
type ManagedEndpointPrepareResult struct {
	State   string
	ACK     []byte
	Created bool
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

// newManagedEndpointPrepareJournal is deliberately unconnected to ingress.
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
	if err != nil || server == "" {
		return empty, errManagedEndpointPrepareJournal
	}
	digest := sha256.Sum256(request)
	expiry := command.Subject.ExpiresAt.Format(time.RFC3339Nano)
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	root, err := nativeShareHolderDirectory(s.registry.root)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	dir, err := nativeShareHolderChild(root, managedEndpointPrepareJournalNamespace)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	lock, err := nativeShareHolderLock(dir)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	conn, err := s.registry.db.Conn(context.Background())
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	ctx := context.Background()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return empty, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "ROLLBACK") }()
	var installation string
	if err = conn.QueryRowContext(ctx, `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); err != nil || installation != string(s.installation) {
		return empty, errManagedEndpointPrepareJournal
	}
	// This callback is an explicit caller obligation, never retained authorization.
	if err = verify(command, server); err != nil {
		return empty, errManagedEndpointPrepareJournal
	}
	if !s.now().Before(command.Subject.ExpiresAt) {
		return empty, errManagedEndpointPrepareJournal
	}
	var enrollment, storedInstallation, storedServer, storedExpiry, state string
	var storedRequest, storedDigest, storedACK []byte
	err = conn.QueryRowContext(ctx, `SELECT enrollment_id,installation_id,server_url,request,request_digest,expires_at,state,ack FROM native_managed_endpoint_prepare_commands WHERE command_id=?`, command.CommandID).Scan(&enrollment, &storedInstallation, &storedServer, &storedRequest, &storedDigest, &storedExpiry, &state, &storedACK)
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		if terminal != "" {
			return empty, errManagedEndpointPrepareJournal
		}
		if _, err = conn.ExecContext(ctx, `INSERT INTO native_managed_endpoint_prepare_commands(command_id,enrollment_id,installation_id,server_url,request,request_digest,expires_at,state,ack) VALUES(?,?,?,?,?,?,?,'reserved',NULL)`, command.CommandID, command.Subject.ID, s.installation, server, request, digest[:], expiry); err != nil {
			return empty, errManagedEndpointPrepareJournal
		}
		state = "reserved"
		created = true
	} else if err != nil {
		return empty, err
	} else {
		if enrollment != string(command.Subject.ID) || storedInstallation != string(s.installation) || storedServer != server || storedExpiry != expiry || !bytes.Equal(storedRequest, request) || !bytes.Equal(storedDigest, digest[:]) {
			return empty, errManagedEndpointPrepareJournal
		}
		switch state {
		case "reserved":
			if storedACK != nil {
				return empty, errManagedEndpointPrepareJournal
			}
		case "succeeded":
			decoded, e := transport.DecodeManagedEndpointPrepareACK(storedACK, command)
			if e != nil {
				return empty, errManagedEndpointPrepareJournal
			}
			canonical, e := decoded.CanonicalBytes()
			if e != nil || !bytes.Equal(canonical, storedACK) {
				return empty, errManagedEndpointPrepareJournal
			}
		case "failed":
			decoded, e := transport.DecodeManagedEndpointPrepareFailureACK(storedACK, command.CommandID)
			if e != nil {
				return empty, errManagedEndpointPrepareJournal
			}
			canonical, e := decoded.CanonicalBytes()
			if e != nil || !bytes.Equal(canonical, storedACK) {
				return empty, errManagedEndpointPrepareJournal
			}
		default:
			return empty, errManagedEndpointPrepareJournal
		}
		if terminal != "" {
			if state != "reserved" {
				if state != terminal || !bytes.Equal(storedACK, ack) {
					return empty, errManagedEndpointPrepareJournal
				}
			} else {
				if _, err = conn.ExecContext(ctx, `UPDATE native_managed_endpoint_prepare_commands SET state=?,ack=? WHERE command_id=? AND state='reserved'`, terminal, ack, command.CommandID); err != nil {
					return empty, err
				}
				state, storedACK = terminal, ack
			}
		}
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return empty, err
	}
	return ManagedEndpointPrepareResult{State: state, ACK: bytes.Clone(storedACK), Created: created}, nil
}
