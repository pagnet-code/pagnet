//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// localManagedDirectCredential is dormant custody only. Construction neither
// offers a protocol nor attaches a command handler or starts a native worker.
type localManagedDirectCredential struct{ *localManagedEndpointPrepare }

func newLocalManagedDirectCredential(d *Daemon) (*localManagedDirectCredential, error) {
	if d == nil || d.nativeRegistry == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	keys, err := NewManagedEndpointKeyStore(d.nativeRegistry)
	if err != nil {
		return nil, err
	}
	journal, err := NewManagedEndpointPrepareJournal(d.nativeRegistry)
	if err != nil {
		return nil, err
	}
	return &localManagedDirectCredential{&localManagedEndpointPrepare{d: d, keys: keys, journal: journal}}, nil
}

func (e *localManagedDirectCredential) ready() bool {
	return e != nil && e.localManagedEndpointPrepare != nil && e.localManagedEndpointPrepare.ready()
}

// Historical Prepare/PoP evidence is checked by InstallCredential in the same
// reserved snapshot as custody. It must never be renewed by running PoP again.
func (e *localManagedDirectCredential) verifyCredentialPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.ManagedDirectCredentialIssue) (*nativeWorkerPublicationToken, error) {
	if ctx.Err() != nil || !e.ready() || socket == nil || native == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	server := managedPrepareServerOrigin(endpoint)
	if _, err := issue.CanonicalBytes(); err != nil || issue.ChannelGeneration != 1 || !e.keys.credentialValid(issue) || issue.PoP.ACK.Reservation.InstallationID != e.keys.installation || server == "" || legacyTextServiceServer(endpoint) != server || server != managedPrepareServerOrigin(e.d.ServerURL) || server != issue.PoP.ACK.Reservation.ServerURL {
		return nil, ErrManagedEndpointPrepareRejected
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
	token, err := e.d.verifyNativeManagedSubjectToken(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, server, nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject), func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !active() || !e.keys.credentialValid(issue) {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

func (d *Daemon) managedDirectCredentialPublicationFence(token *nativeWorkerPublicationToken, captured ManagedEndpointPrepareScope, lane *directManagedSourceCredentialPublicationLane) ManagedDirectCredentialPublicationFence {
	return func(conn *sql.Conn, issue transport.ManagedDirectCredentialIssue, server string, session transport.HostSessionPayload) (func(), error) {
		if d == nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		if _, err := issue.CanonicalBytes(); err != nil || issue.ChannelGeneration != 1 || managedPrepareServerOrigin(d.ServerURL) != server {
			return nil, ErrManagedEndpointPrepareRejected
		}
		return d.credentialPublicationFence(token, captured, lane, nativeManagedSubjectFromEndpoint(issue.PoP.Prepare.Subject), managedPrepareSessionMatches(issue.PoP.Prepare.Subject, session), managedDirectCredentialProtocolV1, issue.IssuedAt, issue.InstallExpiresAt, issue.CredentialExpiresAt, issue.Budget.ExpiresAt)(conn, server, session)
	}
}

func (e *localManagedDirectCredential) installCredential(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.ManagedDirectCredentialIssue, lane *directManagedSourceCredentialPublicationLane) ([]byte, error) {
	if ctx.Err() != nil || !e.ready() || lane == nil || lane.done == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Cancellation and publication share the final lane lock. A cancellation that
	// loses to publication completes only after the transaction releases authority.
	stop := context.AfterFunc(ctx, lane.cancel)
	defer stop()
	var token *nativeWorkerPublicationToken
	verify := func(retained transport.ManagedDirectCredentialIssue, server string, host transport.HostSessionPayload) error {
		if !reflect.DeepEqual(host, session) || !reflect.DeepEqual(retained, issue) {
			return ErrManagedEndpointPrepareRejected
		}
		var err error
		token, err = e.verifyCredentialPublication(ctx, socket, native, session, server, retained)
		return err
	}
	fence := func(conn *sql.Conn, retained transport.ManagedDirectCredentialIssue, server string, host transport.HostSessionPayload) (func(), error) {
		if ctx.Err() != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
		release, err := e.d.managedDirectCredentialPublicationFence(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, retained, server, host)
		if err == nil && ctx.Err() != nil {
			return release, ErrManagedEndpointPrepareRetryable
		}
		return release, err
	}
	return e.keys.InstallCredential(issue, endpoint, session, verify, fence)
}

// executeCredential accepts only canonical target V1 issues. Public failures
// contain the credential identity and fixed transport code, never local errors.
// Runtime integration must guard ACK writes against current authority and bound
// transient immediate ACK collisions with the server's guarded write using a
// bounded retry policy before enabling a route; every retry must revalidate
// authority and the original V1 installation deadline. It must stop on session
// supersession or cancellation. This executor implements no ACK transport.
func (e *localManagedDirectCredential) executeCredential(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint, kind string, raw []byte, lane *directManagedSourceCredentialPublicationLane) ([]byte, error) {
	if kind != "host.managed_direct_credential" {
		return nil, ErrManagedEndpointPrepareRejected
	}
	issue, err := transport.DecodeManagedDirectCredentialIssue(raw)
	if err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	ack, err := e.installCredential(ctx, socket, native, session, endpoint, issue, lane)
	if err != nil {
		return (transport.ManagedDirectCredentialFailureACK{ProtocolVersion: transport.ManagedDirectCredentialProtocol, CredentialID: issue.CredentialID, Error: transport.ManagedDirectCredentialInstallFailure}).CanonicalBytes()
	}
	return ack, nil
}
