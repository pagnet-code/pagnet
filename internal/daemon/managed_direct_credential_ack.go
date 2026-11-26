//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/transport"
)

// withCredentialACKReserved never waits for registry or target namespace owners
// while the caller holds the socket writer.
func (s *ManagedEndpointKeyStore) withCredentialACKReserved(ctx context.Context, fn func(*sql.Conn, *os.File, *func()) error) error {
	return withDirectManagedSourceCredentialACKReserved(ctx, s.registry, nativeManagedEndpointKeyNamespace, fn)
}

// The caller owns writeMu before entering here. This wrapper never mutates a
// credential row, and uses only direct locked helpers under its reservation.
func (e *localManagedDirectCredential) publishCredentialACK(ctx context.Context, token *nativeWorkerPublicationToken, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.ManagedDirectCredentialIssue, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	return e.publishCredentialACKWithToken(ctx, token, socket, native, session, managedPrepareServerOrigin(endpoint), issue, lane, payload, write)
}

// publishCredentialACKWithToken runs only after fresh verification. Its direct
// helpers validate retained custody without reentering the key-store lock.
func (e *localManagedDirectCredential) publishCredentialACKWithToken(ctx context.Context, token *nativeWorkerPublicationToken, socket *websocket.Conn, native *NativeObservationConnection, session transport.HostSessionPayload, endpoint string, issue transport.ManagedDirectCredentialIssue, lane *directManagedSourceCredentialPublicationLane, payload []byte, write func() error) error {
	raw, err := issue.CanonicalBytes()
	if err != nil {
		return err
	}
	if ack, err := transport.DecodeManagedDirectCredentialACK(payload); err != nil || ack.CredentialID != issue.CredentialID {
		return ErrManagedEndpointPrepareRetryable
	}
	return e.keys.withCredentialACKReserved(ctx, func(conn *sql.Conn, dir *os.File, release *func()) error {
		if !e.keys.credentialValid(issue) {
			return errManagedEndpointKey
		}
		if err := e.keys.validateCredentialEvidence(conn, issue, endpoint); err != nil {
			return err
		}
		row, exists, err := e.keys.credentialRow(conn, issue, raw)
		if err != nil || !exists || row.State != "installed" || !bytes.Equal(row.ACK, payload) {
			return errManagedEndpointKey
		}
		private, err := e.keys.loadPoPKey(conn, dir, issue.PoP.ACK.Reservation)
		defer clear(private)
		if err != nil {
			return err
		}
		secret, ack, err := transport.DeriveManagedDirectCredentialHost(issue, private, e.keys.now())
		defer clear(secret)
		if err != nil {
			return err
		}
		canonical, _ := ack.CanonicalBytes()
		hash, _ := transport.ManagedDirectCredentialHash(ack.TranscriptHash, secret)
		if hash != row.CredentialHash || !bytes.Equal(canonical, payload) {
			return errManagedEndpointKey
		}
		record, err := json.Marshal(managedDirectCredentialFile{row.IssueDigest, secret, canonical})
		defer clear(record)
		if err != nil {
			return err
		}
		name := managedDirectCredentialName(e.keys.installation, endpoint, issue)
		if err := e.keys.publishCredential(dir, name, record, true); err != nil {
			return err
		}
		*release, err = e.d.managedDirectCredentialPublicationFence(token, ManagedEndpointPrepareScope{Socket: socket, Connection: native, Session: session}, lane)(conn, issue, endpoint, session)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrManagedEndpointPrepareRetryable
		}
		return write()
	})
}
