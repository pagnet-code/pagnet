//go:build linux || darwin

package daemon

import (
	"context"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// localDirectManagedSourcePoPV2 composes V2 custody.
type localDirectManagedSourcePoPV2 struct {
	*localDirectManagedSourcePrepareV2
}

func newLocalDirectManagedSourcePoPV2(d *Daemon) (*localDirectManagedSourcePoPV2, error) {
	prepare, err := newLocalDirectManagedSourcePrepareV2(d)
	if err != nil {
		return nil, err
	}
	return &localDirectManagedSourcePoPV2{prepare}, nil
}

func (e *localDirectManagedSourcePoPV2) ready() bool {
	return e != nil && e.localDirectManagedSourcePrepareV2 != nil && e.localDirectManagedSourcePrepareV2.ready()
}

func (e *localDirectManagedSourcePoPV2) confirmPoP(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.DirectManagedSourcePoPChallengeV2) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	verify := func(retained transport.DirectManagedSourcePoPChallengeV2, server string, retainedSession transport.HostSessionPayload) error {
		if !reflect.DeepEqual(session, retainedSession) {
			return ErrManagedEndpointPrepareRetryable
		}
		_, err := e.verifyPoPPublication(ctx, socket, native, session, server, retained)
		return err
	}
	return e.keys.ConfirmPoP(challenge, endpoint, session, verify)
}

func (e *localDirectManagedSourcePoPV2) verifyPoPPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, challenge transport.DirectManagedSourcePoPChallengeV2) (*nativeWorkerPublicationToken, error) {
	if ctx.Err() != nil || !e.ready() {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	if _, err := challenge.CanonicalBytes(); err != nil || challenge.ACK.Reservation.InstallationID != e.keys.installation || challenge.ACK.Reservation.ServerURL != managedPrepareServerOrigin(endpoint) {
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
	token, err := e.d.verifyDirectManagedSourcePoPTokenV2(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, challenge, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !active() || e.keys.now().Before(challenge.IssuedAt) || !e.keys.now().Before(challenge.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return token, nil
}

// Validate PoP as V2 evidence before projecting its existing native Qwen worker.
func (d *Daemon) verifyDirectManagedSourcePoPTokenV2(ctx context.Context, captured ManagedEndpointPrepareScope, server string, challenge transport.DirectManagedSourcePoPChallengeV2, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	now := time.Now()
	if _, err := challenge.CanonicalBytes(); err != nil || now.Before(challenge.IssuedAt) || !now.Before(challenge.ExpiresAt) || challenge.ACK.Reservation.ServerURL != managedPrepareServerOrigin(server) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return d.verifyDirectManagedSourcePrepareTokenV2(ctx, captured, server, challenge.Prepare, verify)
}
