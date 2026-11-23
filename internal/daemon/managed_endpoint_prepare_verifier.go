//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
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

// VerifyManagedEndpointPrepare checks closed server evidence against fresh local
// ownership. EndpointID is authenticated server subject data: State has no local
// endpoint mapping, so successful verification does not prove such a mapping.
// This method neither reserves keys nor admits native execution.
func (d *Daemon) VerifyManagedEndpointPrepare(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand) error {
	return d.verifyManagedEndpointPrepare(ctx, captured, configuredServer, command, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
}

// Dispatch counters can advance without changing the immutable owner binding.
func sameManagedPrepareOwnership(a, b transport.NativeWorkerOwnership) bool {
	a.LastDispatchSequence, a.RetiredFloor = 0, 0
	b.LastDispatchSequence, b.RetiredFloor = 0, 0
	return transport.SameNativeWorkerOwnership(a, b)
}

func managedPrepareSessionMatches(s transport.ManagedEndpointBindingIntent, session transport.HostSessionPayload) bool {
	return session.OwnershipScope == "personal" && s.TenantID.String() == session.TenantID && s.AccountID.String() == session.AccountID && s.HostID.String() == session.HostID && s.HostCredentialID.String() == session.HostCredentialID && s.NativeAdmissionID.String() == session.NativeAdmissionID && s.ConnectionIncarnationID == s.NativeAdmissionID && s.RunnerID.String() == session.RunnerID && s.RunnerConnectedAt.Equal(session.RunnerEpoch) && s.BootID == session.BootID
}

func (d *Daemon) verifyManagedEndpointPrepare(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) error {
	if _, err := command.CanonicalBytes(); err != nil {
		return ErrManagedEndpointPrepareRejected
	}
	s := command.Subject
	server := textServiceServer(configuredServer)
	if captured.Socket == nil || captured.Connection == nil || server == "" || !managedPrepareSessionMatches(s, captured.Session) || !time.Now().Before(s.ExpiresAt) {
		return ErrManagedEndpointPrepareRejected
	}
	if d.state == nil || d.nativeRegistry == nil {
		return ErrManagedEndpointPrepareRetryable
	}
	// Lock order: briefly copy the link under nativeWorkersMu, then ownership under
	// link.mu. Never nest these locks, or hold either across IPC or disk access.
	// Registry/state reads and socket admission checks run with neither lock held.
	selectLink := func() (*nativeWorkerLink, *NativeWorkerProxy, transport.NativeWorkerOwnership, error) {
		d.nativeWorkersMu.Lock()
		link := d.nativeWorkers[s.InstanceID.String()]
		d.nativeWorkersMu.Unlock()
		if link == nil || link.conn != captured.Socket || link.proxy == nil || link.proxy.connection != captured.Connection {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		p := link.proxy
		select {
		case <-p.done:
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		default:
		}
		session, err := captured.Connection.AuthenticatedNativeHostSession()
		if err != nil {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		if !managedPrepareSessionMatches(s, session) || captured.Connection.serverURL != server || captured.Connection.hostID != session.HostID || captured.Connection.bootID != session.BootID {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRejected
		}
		link.mu.Lock()
		ownership := link.ownership
		link.mu.Unlock()
		if ownership.ID != s.OwnershipID.String() || ownership.InstanceID != s.InstanceID.String() || ownership.OwnershipGeneration != s.OwnershipGeneration || ownership.Runtime != string(domain.RuntimeQwenCode) || ownership.State != "active" || ownership.DeletionProof != nil {
			return nil, nil, ownership, ErrManagedEndpointPrepareRejected
		}
		record, err := d.nativeRegistry.Lookup(s.InstanceID.String())
		if err != nil {
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		if err := d.nativeRegistry.checkRecoveryFence(record.Scope.InstanceID, record.Scope.Generation); err != nil {
			if errors.Is(err, errNativeWorkerRecoveryFenced) {
				return nil, nil, ownership, ErrManagedEndpointPrepareRejected
			}
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		if _, err := d.nativeRegistry.lookupGC(record.Scope.InstanceID); !errors.Is(err, sql.ErrNoRows) {
			if err == nil {
				return nil, nil, ownership, ErrManagedEndpointPrepareRejected
			}
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		row, ok, err := d.state.GetInstance(s.InstanceID.String())
		if err != nil {
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		scope := record.Scope
		if !ok || row.AgentPrincipalID != s.PrincipalID.String() || row.Runtime != string(domain.RuntimeQwenCode) || row.Profile != record.Profile || record.Spec.Runtime != domain.RuntimeQwenCode || record.Spec.TenantID != scope.TenantID || record.LaunchState != "launched" || scope != p.scope || scope.ServerURL != server || scope.TenantID != session.TenantID || scope.AccountID != session.AccountID || scope.HostID != session.HostID || scope.InstanceID != s.InstanceID.String() || scope.Generation != s.OwnershipGeneration || record.ProfileFingerprint != sessionworker.NativeProfileFingerprint(record.Spec) || p.profile != record.ProfileFingerprint || sessionworker.NativeProfileFingerprint(p.bootstrap.Native) != p.profile || ownership.ProfileFingerprint != record.ProfileFingerprint || ownership.Profile != record.Profile || record.Ownership == nil || !sameManagedPrepareOwnership(*record.Ownership, ownership) {
			return nil, nil, ownership, ErrManagedEndpointPrepareRejected
		}
		return link, p, ownership, nil
	}
	link, p, ownership, err := selectLink()
	if err != nil {
		return err
	}
	result, err := verify(ctx, p, ownership)
	if err != nil {
		// Owner RPC errors arrive as public wire strings through proxy.call.
		// Only its explicit ownership conflict is terminal; lost IPC is retryable.
		if errors.Is(err, ErrManagedEndpointPrepareRejected) || errors.Is(err, sessionworker.ErrConflict) || err.Error() == sessionworker.ErrConflict.Error() {
			return ErrManagedEndpointPrepareRejected
		}
		return ErrManagedEndpointPrepareRetryable
	}
	if result == nil {
		return ErrManagedEndpointPrepareRejected
	}
	snapshot := result.Snapshot
	actualStart, identityErr := proc.StartIdentity(snapshot.PID)
	var origin transport.NativeObservationOrigin
	if identityErr != nil || actualStart != snapshot.NativeStartIdentity || snapshot.Scope != p.scope || snapshot.IdentityPending || snapshot.ActualRuntime != domain.RuntimeQwenCode || snapshot.ProfileFingerprint != p.profile || snapshot.PID <= 0 || snapshot.NativeStartIdentity == "" || snapshot.NativeGeneration != s.NativeGeneration || snapshot.NativeSessionID != s.NativeSessionID || json.Unmarshal(snapshot.Origin, &origin) != nil || origin.ID != s.OriginID.String() || origin.TenantID != s.TenantID.String() || origin.HostID != s.HostID.String() || origin.InstanceID != s.InstanceID.String() || origin.Runtime != string(domain.RuntimeQwenCode) || origin.NativeGeneration != s.NativeGeneration || (origin.NativeSessionID != "" && origin.NativeSessionID != s.NativeSessionID) {
		return ErrManagedEndpointPrepareRejected
	}
	// Origin admission may belong to an earlier socket while the native session
	// survives reconnect. Only current host.session authority is pinned above.
	after, proxy, fresh, err := selectLink()
	if err != nil {
		return err
	}
	if after != link || proxy != p || !sameManagedPrepareOwnership(fresh, ownership) {
		return ErrManagedEndpointPrepareRetryable
	}
	d.nativeWorkersMu.Lock()
	current := d.nativeWorkers[s.InstanceID.String()]
	d.nativeWorkersMu.Unlock()
	if current != link {
		return ErrManagedEndpointPrepareRetryable
	}
	if !time.Now().Before(s.ExpiresAt) {
		return ErrManagedEndpointPrepareRejected
	}
	return nil
}
