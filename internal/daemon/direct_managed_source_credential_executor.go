//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
	"os"
	"reflect"
	"time"
)

// Verify the complete source issue before projecting its worker identity. The
// ownership IPC and registry reads remain outside all publication locks.
func (e *localDirectManagedSourcePrepare) verifyCredentialPublication(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssue) (*nativeWorkerPublicationToken, error) {
	if _, err := issue.CanonicalBytes(); err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	lane := &directManagedSourceCredentialConnection{native: native}
	if !e.d.directManagedSourceCredentialReady() || !lane.negotiated(session) || !e.keys.credentialValid(issue) || managedPrepareServerOrigin(endpoint) != issue.PoP.ACK.Reservation.ServerURL || issue.PoP.ACK.Reservation.InstallationID != e.keys.installation {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return e.verifyPoPPublication(ctx, socket, native, session, endpoint, issue.PoP)
}

func (e *localDirectManagedSourcePrepare) installCredential(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssue, lane *directManagedSourceCredentialPublicationLane) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var token *nativeWorkerPublicationToken
	verify := func(retained transport.DirectManagedSourceCredentialIssue, server string, host transport.HostSessionPayload) error {
		if !reflect.DeepEqual(host, session) || !reflect.DeepEqual(retained, issue) {
			return ErrManagedEndpointPrepareRejected
		}
		var err error
		token, err = e.verifyCredentialPublication(ctx, socket, native, session, server, retained)
		return err
	}
	fence := func(conn *sql.Conn, retained transport.DirectManagedSourceCredentialIssue, server string, host transport.HostSessionPayload) (func(), error) {
		return e.d.directManagedSourceCredentialPublicationFence(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, retained, server, host)
	}
	return e.keys.InstallCredential(issue, endpoint, session, verify, fence)
}

// The caller owns writeMu before entering here. This wrapper never mutates a
// credential row, and uses only direct locked helpers under its reservation.
func (e *localDirectManagedSourcePrepare) publishCredentialACK(ctx context.Context, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssue, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	token, err := e.verifyCredentialPublication(ctx, socket, native, session, endpoint, issue)
	if err != nil {
		return err
	}
	return e.publishCredentialACKWithToken(token, socket, native, session, managedPrepareServerOrigin(endpoint), issue, lane, payload, write)
}

// publishCredentialACKWithToken runs only after fresh verification. Its direct
// helpers validate retained custody without reentering the key-store lock.
func (e *localDirectManagedSourcePrepare) publishCredentialACKWithToken(token *nativeWorkerPublicationToken, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.DirectManagedSourceCredentialIssue, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return err
	}
	_, successErr := transport.DecodeDirectManagedSourceCredentialACK(payload)
	return e.keys.withKeyLockedScoped(false, func(conn *sql.Conn, dir *os.File, release *func()) error {
		if successErr != nil {
			row, exists, err := e.keys.credentialRow(conn, issue, raw)
			if err != nil {
				return err
			}
			// An installation may have committed before a later verifier failed.
			// Never turn that uncertain outcome into a failure response.
			if exists && row.State == "installed" {
				return ErrManagedEndpointPrepareRetryable
			}
		}
		if successErr == nil {
			if err := e.keys.validateCredentialEvidence(conn, issue, endpoint); err != nil {
				return err
			}
			row, exists, err := e.keys.credentialRow(conn, issue, raw)
			if err != nil || !exists || row.State != "installed" || !bytes.Equal(row.ACK, payload) {
				return errDirectManagedSourceKey
			}
			private, err := e.keys.loadPoPKey(conn, dir, issue.PoP.ACK.Reservation, issue.PoP.Prepare)
			defer clear(private)
			if err != nil {
				return err
			}
			secret, ack, err := transport.DeriveDirectManagedSourceCredentialHost(issue, private, e.keys.now())
			defer clear(secret)
			if err != nil {
				return err
			}
			canonical, _ := ack.CanonicalBytes()
			hash, _ := transport.DirectManagedSourceCredentialHash(ack.TranscriptHash, secret)
			if hash != row.CredentialHash || !bytes.Equal(canonical, payload) {
				return errDirectManagedSourceKey
			}
			record, err := json.Marshal(directManagedSourceCredentialFile{row.IssueDigest, secret})
			defer clear(record)
			if err != nil {
				return err
			}
			name := directManagedSourceKeyScope(e.keys.installation, endpoint, issue.PoP.Prepare.Subject) + ".credential"
			if err := e.keys.publishCredential(dir, name, record, true); err != nil {
				return err
			}
		}
		*release, err = e.d.directManagedSourceCredentialPublicationFence(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, issue, endpoint, session)
		if err != nil {
			return err
		}
		return write()
	})
}
