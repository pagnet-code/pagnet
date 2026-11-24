package daemon

import (
	"errors"
	"reflect"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

var (
	ErrManagedEndpointPrepareRejected  = errors.New("managed endpoint prepare authority mismatch")
	ErrManagedEndpointPrepareRetryable = errors.New("managed endpoint prepare authority unavailable")
)

// ManagedEndpointPrepareScope must be captured from the authenticated host.session
// on this exact socket. It conveys no authority when supplied by a wire command.
type ManagedEndpointPrepareScope struct {
	Socket     *websocket.Conn
	Connection *NativeObservationConnection
	Session    transport.HostSessionPayload
}

// Dispatch counters can advance without changing the immutable owner binding.
func sameManagedPrepareOwnership(a, b transport.NativeWorkerOwnership) bool {
	a.LastDispatchSequence, a.RetiredFloor = 0, 0
	b.LastDispatchSequence, b.RetiredFloor = 0, 0
	return transport.SameNativeWorkerOwnership(a, b)
}

// nativeWorkerPublicationToken pins the immutable binding verified outside the
// publication locks. Dispatch counters may advance without revoking the token.
type nativeWorkerPublicationToken struct {
	instanceID string
	link       *nativeWorkerLink
	proxy      *NativeWorkerProxy
	ownership  transport.NativeWorkerOwnership
	subject    nativeManagedSubject
}

// publishNativeWorker holds the current worker and connection authority through
// write. Lock order is writeMu → nativeWorkersMu → link.mu → proxy publication
// RLock → connMu → native.mu. The caller holds writeMu. The callback sets the deadline
// and writes the frame; IPC, disk access and connection cleanup happen outside.
func (d *Daemon) publishNativeWorker(token *nativeWorkerPublicationToken, captured ManagedEndpointPrepareScope, laneDone <-chan struct{}, expires time.Time, write func(time.Time) error) error {
	if token == nil || token.link == nil || token.proxy == nil || captured.Connection == nil {
		return ErrManagedEndpointPrepareRetryable
	}
	d.nativeWorkersMu.Lock()
	defer d.nativeWorkersMu.Unlock()
	token.link.mu.Lock()
	defer token.link.mu.Unlock()
	token.proxy.publicationMu.RLock()
	defer token.proxy.publicationMu.RUnlock()
	d.connMu.Lock()
	defer d.connMu.Unlock()
	captured.Connection.mu.Lock()
	defer captured.Connection.mu.Unlock()
	if d.nativeWorkers[token.instanceID] != token.link || token.link.proxy != token.proxy || token.link.conn != captured.Socket || token.proxy.connection != captured.Connection || !sameManagedPrepareOwnership(token.link.ownership, token.ownership) || d.curConn != captured.Socket || d.nativeConn != captured.Connection || captured.Connection.session == nil || !reflect.DeepEqual(*captured.Connection.session, captured.Session) {
		return ErrManagedEndpointPrepareRetryable
	}
	for _, done := range []<-chan struct{}{token.proxy.done, captured.Connection.closed, laneDone} {
		select {
		case <-done:
			return ErrManagedEndpointPrepareRetryable
		default:
		}
	}
	now := time.Now()
	if !now.Before(expires) {
		return ErrManagedEndpointPrepareRejected
	}
	deadline := now.Add(d.writeTimeout)
	if expires.Before(deadline) {
		deadline = expires
	}
	return write(deadline)
}

// nativeManagedSubject contains only the shared local ownership identity.
type nativeManagedSubject struct {
	TenantID                domain.ID
	AccountID               domain.ID
	HostID                  domain.ID
	HostCredentialID        domain.ID
	NativeAdmissionID       domain.ID
	ConnectionIncarnationID domain.ID
	RunnerID                domain.ID
	RunnerConnectedAt       time.Time
	BootID                  string
	InstanceID              domain.ID
	OwnershipID             domain.ID
	OwnershipGeneration     string
	PrincipalID             domain.ID
	NativeGeneration        string
	NativeSessionID         string
	OriginID                domain.ID
	ExpiresAt               time.Time
}
