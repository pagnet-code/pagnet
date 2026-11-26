//go:build linux || darwin

package daemon

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type localDirectManagedSourcePrepareV2 struct {
	d       *Daemon
	keys    *DirectManagedSourceKeyStoreV2
	journal *DirectManagedSourcePrepareJournalV2
}

// newLocalDirectManagedSourcePrepareV2 composes isolated V2 custody.
func newLocalDirectManagedSourcePrepareV2(d *Daemon) (*localDirectManagedSourcePrepareV2, error) {
	if d == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	keys, err := NewDirectManagedSourceKeyStoreV2(d.nativeRegistry)
	if err != nil {
		return nil, err
	}
	journal, err := NewDirectManagedSourcePrepareJournalV2(d.nativeRegistry)
	if err != nil {
		return nil, err
	}
	return &localDirectManagedSourcePrepareV2{d: d, keys: keys, journal: journal}, nil
}

func (e *localDirectManagedSourcePrepareV2) ready() bool {
	if e == nil || e.d == nil || e.keys == nil || e.journal == nil || e.d.nativeRegistry == nil || e.d.state == nil || e.d.serveLockFile == nil {
		return false
	}
	_, err := e.d.serveLockFile.Stat()
	if err != nil || e.keys.registry != e.d.nativeRegistry || e.journal.registry != e.d.nativeRegistry {
		return false
	}
	keys, err := NewDirectManagedSourceKeyStoreV2(e.d.nativeRegistry)
	if err != nil || keys.installation != e.keys.installation {
		return false
	}
	journal, err := NewDirectManagedSourcePrepareJournalV2(e.d.nativeRegistry)
	if err != nil || journal.installation != e.journal.installation || journal.installation != keys.installation {
		return false
	}
	root, err := nativeShareHolderDirectory(e.d.nativeRegistry.root)
	if err != nil {
		return false
	}
	defer root.Close()
	for _, name := range []string{nativeDirectManagedSourceKeyNamespaceV2, directManagedSourcePrepareJournalNamespaceV2} {
		dir, err := nativeShareHolderExistingChild(root, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false
		}
		dir.Close()
	}
	return true
}

func (e *localDirectManagedSourcePrepareV2) verifyPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommandV2) (*nativeWorkerPublicationToken, error) {
	if ctx.Err() != nil || !e.ready() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	active := func() bool {
		e.d.connMu.Lock()
		defer e.d.connMu.Unlock()
		if e.d.curConn != socket || e.d.nativeConn != native {
			return false
		}
		current, err := native.AuthenticatedNativeHostSession()
		return err == nil && reflect.DeepEqual(current, session)
	}
	if !active() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	token, err := e.d.directManagedSourcePreparePublicationTokenV2(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, command)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !active() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

func (e *localDirectManagedSourcePrepareV2) prepare(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommandV2) ([]byte, error) {
	// Serialize across sockets as well: a superseded socket cannot race recovery
	// against the first key creation attempt for this daemon.
	e.d.directManagedSourcePrepareMuV2.Lock()
	defer e.d.directManagedSourcePrepareMuV2.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	verify := func(retained transport.DirectManagedSourcePrepareCommandV2, server string, retainedSession transport.HostSessionPayload) error {
		if !reflect.DeepEqual(retainedSession, session) {
			return ErrManagedEndpointPrepareRetryable
		}
		_, err := e.verifyPublication(ctx, socket, native, session, server, retained)
		return err
	}
	return e.execute(session, endpoint, command, verify)
}

// execute composes the closed journals; verify is called outside their locks.
func (e *localDirectManagedSourcePrepareV2) execute(session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommandV2, verify DirectManagedSourcePrepareScopeCheckV2) ([]byte, error) {
	if err := verify(command, endpoint, session); err != nil {
		return nil, err
	}
	result, err := e.journal.Reserve(command, endpoint, session, verify)
	if err != nil {
		return nil, err
	}
	if result.State == "reserved" {
		result, err = e.journal.BeginKeyReservation(command, endpoint, session, verify)
		if err != nil {
			return nil, err
		}
		var reservation transport.DirectManagedSourceKeyReservationV2
		if result.KeyStarted {
			// The durable grant permits one creation attempt only.
			if err = verify(command, endpoint, session); err != nil {
				return nil, err
			}
			reservation, err = e.keys.Reserve(command, endpoint, session, verify, result.keyCreationGrant)
		} else {
			reservation, err = e.keys.RecoverReservation(command, endpoint, session, verify)
		}
		if err != nil {
			result, err = e.journal.Fail(command, endpoint, session, verify)
		} else {
			var ack []byte
			ack, err = (transport.DirectManagedSourcePrepareACKV2{ProtocolVersion: transport.DirectManagedSourcePrepareProtocolV2, CommandID: command.CommandID, Reservation: reservation}).CanonicalBytes()
			if err == nil {
				result, err = e.journal.Succeed(command, endpoint, session, verify, ack)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if err := verify(command, endpoint, session); err != nil {
		return nil, err
	}
	return result.ACK, nil
}

func (d *Daemon) directManagedSourcePreparePublicationTokenV2(ctx context.Context, captured ManagedEndpointPrepareScope, server string, command transport.DirectManagedSourcePrepareCommandV2) (*nativeWorkerPublicationToken, error) {

	return d.verifyDirectManagedSourcePrepareTokenV2(ctx, captured, server, command, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
}

// Verify the full source command before projecting its local native identity.
func (d *Daemon) verifyDirectManagedSourcePrepareTokenV2(ctx context.Context, captured ManagedEndpointPrepareScope, server string, command transport.DirectManagedSourcePrepareCommandV2, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	now := time.Now()
	if _, err := command.CanonicalBytes(); err != nil || !directManagedSourceSessionMatchesV2(command.Subject, captured.Session) || now.Before(command.Subject.CreatedAt) || !now.Before(command.Subject.EnrollmentExpiresAt) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return d.verifyNativeManagedSubjectToken(ctx, captured, server, nativeManagedSubjectFromSourceV2(command.Subject), verify)
}
