//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// localDirectManagedSourceCredentialV2 composes isolated V2 custody.
type localDirectManagedSourceCredentialV2 struct{ *localDirectManagedSourcePoPV2 }

func newLocalDirectManagedSourceCredentialV2(d *Daemon) (*localDirectManagedSourceCredentialV2, error) {
	pop, err := newLocalDirectManagedSourcePoPV2(d)
	if err != nil {
		return nil, err
	}
	return &localDirectManagedSourceCredentialV2{pop}, nil
}

func (e *localDirectManagedSourceCredentialV2) ready() bool {
	return e != nil && e.localDirectManagedSourcePoPV2 != nil && e.localDirectManagedSourcePoPV2.ready()
}

// Credential installation uses successful historical Prepare/PoP evidence. Never
// re-enter live PoP verification or backdate a clock to make that evidence live.
func (e *localDirectManagedSourceCredentialV2) verifyCredentialPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssueV2) (*nativeWorkerPublicationToken, error) {
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
	negotiation := &directManagedSourceCredentialNegotiationV2{socket: socket, native: native, session: session}
	if !negotiation.valid() || !e.keys.credentialValid(issue) || issue.PoP.ACK.Reservation.InstallationID != e.keys.installation || legacyTextServiceServer(endpoint) != managedPrepareServerOrigin(endpoint) || managedPrepareServerOrigin(endpoint) != issue.PoP.ACK.Reservation.ServerURL {
		return nil, ErrManagedEndpointPrepareRejected
	}
	token, err := e.d.verifyDirectManagedSourceCredentialTokenV2(ctx, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, endpoint, issue, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
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

func (d *Daemon) verifyDirectManagedSourceCredentialTokenV2(ctx context.Context, captured ManagedEndpointPrepareScope, endpoint string, issue transport.DirectManagedSourceCredentialIssueV2, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	now := time.Now()
	if _, err := issue.CanonicalBytes(); err != nil || !directManagedSourceSessionMatchesV2(issue.PoP.Prepare.Subject, captured.Session) || now.Before(issue.IssuedAt) || !now.Before(issue.InstallExpiresAt) || !now.Before(issue.CredentialExpiresAt) || !now.Before(issue.BudgetExpiresAt) || issue.PoP.ACK.Reservation.ServerURL != managedPrepareServerOrigin(endpoint) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return d.verifyNativeManagedSubjectToken(ctx, captured, endpoint, nativeManagedSubjectFromSourceV2(issue.PoP.Prepare.Subject), verify)
}

func (e *localDirectManagedSourceCredentialV2) installCredential(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssueV2, lane *directManagedSourceCredentialPublicationLane) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var token *nativeWorkerPublicationToken
	verify := func(retained transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) error {
		if !reflect.DeepEqual(host, session) || !reflect.DeepEqual(retained, issue) {
			return ErrManagedEndpointPrepareRejected
		}
		var err error
		token, err = e.verifyCredentialPublication(ctx, socket, native, session, server, retained)
		return err
	}
	fence := func(conn *sql.Conn, retained transport.DirectManagedSourceCredentialIssueV2, server string, host transport.HostSessionPayload) (func(), error) {
		return e.d.directManagedSourceCredentialPublicationFenceV2(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, retained, server, host)
	}
	return e.keys.InstallCredential(issue, endpoint, session, verify, fence)
}

// The caller owns writeMu before entering here. This wrapper never mutates a
// credential row, and uses only direct locked helpers under its reservation.
func (e *localDirectManagedSourceCredentialV2) publishCredentialACK(ctx context.Context, token *nativeWorkerPublicationToken, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssueV2, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	return e.publishCredentialACKWithToken(ctx, token, socket, native, session, managedPrepareServerOrigin(endpoint), issue, lane, payload, write)
}

// publishCredentialACKWithToken runs only after fresh verification. Its direct
// helpers validate retained custody without reentering the key-store lock.
func (e *localDirectManagedSourceCredentialV2) publishCredentialACKWithToken(ctx context.Context, token *nativeWorkerPublicationToken, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssueV2, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return err
	}
	if _, err := transport.DecodeDirectManagedSourceCredentialACKV2(payload); err != nil {
		return ErrManagedEndpointPrepareRetryable
	}
	return e.keys.withCredentialACKReserved(ctx, func(conn *sql.Conn, dir *os.File, release *func()) error {
		if err := e.keys.validateCredentialEvidence(conn, issue, endpoint); err != nil {
			return err
		}
		row, exists, err := e.keys.credentialRow(conn, issue, raw)
		if err != nil || !exists || row.State != "installed" || !bytes.Equal(row.ACK, payload) {
			return errDirectManagedSourceKeyV2
		}
		private, err := e.keys.loadPoPKey(conn, dir, issue.PoP.ACK.Reservation, issue.PoP.Prepare)
		defer clear(private)
		if err != nil {
			return err
		}
		secret, ack, err := transport.DeriveDirectManagedSourceCredentialHostV2(issue, private, e.keys.now())
		defer clear(secret)
		if err != nil {
			return err
		}
		canonical, _ := ack.CanonicalBytes()
		hash, _ := transport.DirectManagedSourceCredentialHashV2(ack.TranscriptHash, secret)
		if hash != row.CredentialHash || !bytes.Equal(canonical, payload) {
			return errDirectManagedSourceKeyV2
		}
		record, err := json.Marshal(directManagedSourceCredentialFileV2{row.IssueDigest, secret, canonical})
		defer clear(record)
		if err != nil {
			return err
		}
		name := directManagedSourceKeyScopeV2(e.keys.installation, endpoint, issue.PoP.Prepare.Subject) + ".credential"
		if err := e.keys.publishCredential(dir, name, record, true); err != nil {
			return err
		}
		*release, err = e.d.directManagedSourceCredentialPublicationFenceV2(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, issue, endpoint, session)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrManagedEndpointPrepareRetryable
		}
		return write()
	})
}
