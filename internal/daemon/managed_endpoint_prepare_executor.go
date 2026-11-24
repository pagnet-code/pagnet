//go:build linux || darwin

package daemon

import (
	"context"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

type localManagedEndpointPrepare struct {
	d       *Daemon
	keys    *ManagedEndpointKeyStore
	journal *ManagedEndpointPrepareJournal
}

func (d *Daemon) initManagedEndpointPrepare() {
	if !d.ManagedEndpointPrepareEnabled {
		return
	}
	keys, ok := d.managedEndpointKeys.(*ManagedEndpointKeyStore)
	if !ok {
		return
	}
	journal, err := d.newManagedEndpointPrepareJournal()
	if err == nil {
		executor := &localManagedEndpointPrepare{d: d, keys: keys, journal: journal}
		d.managedEndpointPrepare = executor
		if d.ManagedEndpointPoPEnabled {
			d.managedEndpointPoP = executor
		}
	}
}

func (e *localManagedEndpointPrepare) ready() bool {
	if e == nil || e.d == nil || e.keys == nil || e.journal == nil || e.d.nativeRegistry == nil || e.d.state == nil || e.d.serveLockFile == nil {
		return false
	}
	_, err := e.d.serveLockFile.Stat()
	if err != nil || e.keys.registry != e.d.nativeRegistry || e.journal.registry != e.d.nativeRegistry {
		return false
	}
	keys, err := NewManagedEndpointKeyStore(e.d.nativeRegistry)
	if err != nil || keys.installation != e.keys.installation {
		return false
	}
	journal, err := NewManagedEndpointPrepareJournal(e.d.nativeRegistry)
	return err == nil && journal.installation == e.journal.installation
}

func (e *localManagedEndpointPrepare) verifyPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.ManagedEndpointPrepareCommand) (*nativeWorkerPublicationToken, error) {
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
	token, err := e.d.managedEndpointPreparePublicationToken(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, command)
	if err != nil {
		return nil, err
	}
	if !active() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

func (e *localManagedEndpointPrepare) prepare(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, command transport.ManagedEndpointPrepareCommand) ([]byte, error) {
	// Serialize across sockets as well: a superseded socket cannot race recovery
	// against the first key creation attempt for this daemon.
	e.d.managedEndpointPrepareMu.Lock()
	defer e.d.managedEndpointPrepareMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	verify := func(retained transport.ManagedEndpointPrepareCommand, server string) error {
		_, err := e.verifyPublication(ctx, socket, native, session, server, retained)
		return err
	}
	return e.execute(session, endpoint, command, verify)
}

// execute composes the closed journals; verify is called outside their locks.
func (e *localManagedEndpointPrepare) execute(session transport.HostSessionPayload, endpoint string, command transport.ManagedEndpointPrepareCommand, verify ManagedEndpointPrepareScopeCheck) ([]byte, error) {
	if err := verify(command, endpoint); err != nil {
		return nil, err
	}
	result, err := e.journal.Reserve(command, endpoint, verify)
	if err != nil {
		return nil, err
	}
	if result.State == "reserved" {
		result, err = e.journal.BeginKeyReservation(command, endpoint, verify)
		if err != nil {
			return nil, err
		}
		var reservation transport.ManagedEndpointKeyReservation
		if result.KeyStarted {
			// The durable grant permits one creation attempt only.
			if err = verify(command, endpoint); err != nil {
				return nil, err
			}
			reservation, err = e.keys.Reserve(command.Subject, endpoint, session)
		} else {
			reservation, err = e.keys.RecoverReservation(command.Subject, endpoint, session)
		}
		if err != nil {
			result, err = e.journal.Fail(command, endpoint, verify)
		} else {
			var ack []byte
			ack, err = (transport.ManagedEndpointPrepareACK{ProtocolVersion: transport.ManagedEndpointPrepareProtocol, CommandID: command.CommandID, Reservation: reservation}).CanonicalBytes()
			if err == nil {
				result, err = e.journal.Succeed(command, endpoint, verify, ack)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if err := verify(command, endpoint); err != nil {
		return nil, err
	}
	return result.ACK, nil
}

func (e *localManagedEndpointPrepare) confirmPoP(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.ManagedEndpointPoPChallenge) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return e.keys.ConfirmPoP(ctx, e.d, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, challenge)
}

func (e *localManagedEndpointPrepare) verifyPoPPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.ManagedEndpointPoPChallenge) error {
	if err := e.verifyPublication(ctx, socket, native, session, endpoint, challenge.Prepare); err != nil {
		return err
	}
	if e.keys.now().Before(challenge.IssuedAt) || !e.keys.now().Before(challenge.ExpiresAt) {
		return ErrManagedEndpointPrepareRetryable
	}
	return nil
}
