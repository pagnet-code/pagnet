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

type localDirectManagedSourcePrepare struct {
	d       *Daemon
	keys    *DirectManagedSourceKeyStore
	journal *DirectManagedSourcePrepareJournal
}

func (d *Daemon) initDirectManagedSourcePrepare() {
	if !d.DirectManagedSourcePrepareEnabled {
		return
	}
	keys, err := NewDirectManagedSourceKeyStore(d.nativeRegistry)
	if err != nil {
		return
	}
	journal, err := NewDirectManagedSourcePrepareJournal(d.nativeRegistry)
	if err == nil {
		executor := &localDirectManagedSourcePrepare{d: d, keys: keys, journal: journal}
		d.directManagedSourcePrepare = executor
		if d.DirectManagedSourcePoPEnabled {
			d.directManagedSourcePoP = executor
		}
	}
}

func (e *localDirectManagedSourcePrepare) ready() bool {
	if e == nil || e.d == nil || e.keys == nil || e.journal == nil || e.d.nativeRegistry == nil || e.d.state == nil || e.d.serveLockFile == nil {
		return false
	}
	_, err := e.d.serveLockFile.Stat()
	if err != nil || e.keys.registry != e.d.nativeRegistry || e.journal.registry != e.d.nativeRegistry {
		return false
	}
	keys, err := NewDirectManagedSourceKeyStore(e.d.nativeRegistry)
	if err != nil || keys.installation != e.keys.installation {
		return false
	}
	journal, err := NewDirectManagedSourcePrepareJournal(e.d.nativeRegistry)
	if err != nil || journal.installation != e.journal.installation || journal.installation != keys.installation {
		return false
	}
	root, err := nativeShareHolderDirectory(e.d.nativeRegistry.root)
	if err != nil {
		return false
	}
	defer root.Close()
	for _, name := range []string{nativeDirectManagedSourceKeyNamespace, directManagedSourcePrepareJournalNamespace} {
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

func (e *localDirectManagedSourcePrepare) verifyPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommand) (*nativeWorkerPublicationToken, error) {
	if !e.ready() {
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
	token, err := e.d.directManagedSourcePreparePublicationToken(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, command)
	if err != nil {
		return nil, err
	}
	if !active() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

func (e *localDirectManagedSourcePrepare) prepare(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommand) ([]byte, error) {
	// Serialize across sockets as well: a superseded socket cannot race recovery
	// against the first key creation attempt for this daemon.
	e.d.directManagedSourcePrepareMu.Lock()
	defer e.d.directManagedSourcePrepareMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	verify := func(retained transport.DirectManagedSourcePrepareCommand, server string, retainedSession transport.HostSessionPayload) error {
		if !reflect.DeepEqual(retainedSession, session) {
			return ErrManagedEndpointPrepareRetryable
		}
		_, err := e.verifyPublication(ctx, socket, native, session, server, retained)
		return err
	}
	return e.execute(session, endpoint, command, verify)
}

// execute composes the closed journals; verify is called outside their locks.
func (e *localDirectManagedSourcePrepare) execute(session transport.HostSessionPayload, endpoint string, command transport.DirectManagedSourcePrepareCommand, verify DirectManagedSourcePrepareScopeCheck) ([]byte, error) {
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
		var reservation transport.DirectManagedSourceKeyReservation
		if result.KeyStarted {
			// The durable grant permits one creation attempt only.
			if err = verify(command, endpoint, session); err != nil {
				return nil, err
			}
			reservation, err = e.keys.Reserve(command, endpoint, session, verify)
		} else {
			reservation, err = e.keys.RecoverReservation(command, endpoint, session, verify)
		}
		if err != nil {
			result, err = e.journal.Fail(command, endpoint, session, verify)
		} else {
			var ack []byte
			ack, err = (transport.DirectManagedSourcePrepareACK{ProtocolVersion: transport.DirectManagedSourcePrepareProtocol, CommandID: command.CommandID, Reservation: reservation}).CanonicalBytes()
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

func (e *localDirectManagedSourcePrepare) confirmPoP(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.DirectManagedSourcePoPChallenge) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	verify := func(retained transport.DirectManagedSourcePoPChallenge, server string, retainedSession transport.HostSessionPayload) error {
		if !reflect.DeepEqual(session, retainedSession) {
			return ErrManagedEndpointPrepareRetryable
		}
		_, err := e.verifyPoPPublication(ctx, socket, native, session, server, retained)
		return err
	}
	return e.keys.ConfirmPoP(challenge, endpoint, session, verify)
}

func (e *localDirectManagedSourcePrepare) verifyPoPPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.DirectManagedSourcePoPChallenge) (*nativeWorkerPublicationToken, error) {
	if _, err := challenge.CanonicalBytes(); err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	token, err := e.verifyPublication(ctx, socket, native, session, endpoint, challenge.Prepare)
	if err != nil {
		return nil, err
	}
	if e.keys.now().Before(challenge.IssuedAt) || !e.keys.now().Before(challenge.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

func (d *Daemon) directManagedSourcePreparePublicationToken(ctx context.Context, captured ManagedEndpointPrepareScope, server string, command transport.DirectManagedSourcePrepareCommand) (*nativeWorkerPublicationToken, error) {

	return d.verifyDirectManagedSourcePrepareToken(ctx, captured, server, command, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
}

// Verify the full source command before projecting its local native identity.
func (d *Daemon) verifyDirectManagedSourcePrepareToken(ctx context.Context, captured ManagedEndpointPrepareScope, server string, command transport.DirectManagedSourcePrepareCommand, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	if _, err := command.CanonicalBytes(); err != nil || !directManagedSourceSessionMatches(command.Subject, captured.Session) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return d.verifyNativeManagedSubjectToken(ctx, captured, server, nativeManagedSubjectFromSource(command.Subject), verify)
}
