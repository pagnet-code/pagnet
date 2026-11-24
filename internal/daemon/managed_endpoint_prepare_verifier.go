//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/proc"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

// VerifyManagedEndpointPrepare checks closed server evidence against fresh local
// ownership. EndpointID is authenticated server subject data: State has no local
// endpoint mapping, so successful verification does not prove such a mapping.
// This method neither reserves keys nor admits native execution.
func (d *Daemon) VerifyManagedEndpointPrepare(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand) error {
	_, err := d.managedEndpointPreparePublicationToken(ctx, captured, configuredServer, command)
	return err
}

func (d *Daemon) managedEndpointPreparePublicationToken(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand) (*nativeWorkerPublicationToken, error) {
	return d.verifyManagedEndpointPrepareToken(ctx, captured, configuredServer, command, func(ctx context.Context, p *NativeWorkerProxy, ownership transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error) {
		response, err := p.call(ctx, sessionworker.Request{Type: "ownership_verify", OwnershipVerify: &sessionworker.NativeOwnershipVerifyRequest{Ownership: ownership}})
		if err != nil {
			return nil, err
		}
		return response.OwnershipVerify, nil
	})
}

// managedPrepareServerOrigin normalizes comparison copies only. Escaped path
// separators retain their spelling and identity; only literal trailing slashes
// are ignored. Rebuilding a decoded Path could merge distinct server routes.
// Fragments and scoped IPv6 hosts are excluded before host case normalization.
func managedPrepareServerOrigin(value string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || strings.Contains(value, "#") || strings.Contains(u.Hostname(), "%") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return textServiceServer(value)
}

func managedPrepareSessionMatches(s transport.ManagedEndpointBindingIntent, session transport.HostSessionPayload) bool {
	return session.OwnershipScope == "personal" && s.TenantID.String() == session.TenantID && s.AccountID.String() == session.AccountID && s.HostID.String() == session.HostID && s.HostCredentialID.String() == session.HostCredentialID && s.NativeAdmissionID.String() == session.NativeAdmissionID && s.ConnectionIncarnationID == s.NativeAdmissionID && s.RunnerID.String() == session.RunnerID && s.RunnerConnectedAt.Equal(session.RunnerEpoch) && s.BootID == session.BootID
}

func (d *Daemon) verifyManagedEndpointPrepare(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) error {
	_, err := d.verifyManagedEndpointPrepareToken(ctx, captured, configuredServer, command, verify)
	return err
}

func (d *Daemon) verifyManagedEndpointPrepareToken(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, command transport.ManagedEndpointPrepareCommand, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	if _, err := command.CanonicalBytes(); err != nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	s := command.Subject
	// Canonicalize comparison copies only: raw URLs remain part of the exact
	// registry, proxy and owner scope identity.
	server := managedPrepareServerOrigin(configuredServer)
	if captured.Socket == nil || captured.Connection == nil || server == "" || !managedPrepareSessionMatches(s, captured.Session) || !time.Now().Before(s.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	if d.state == nil || d.nativeRegistry == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	// Verification copies map/link state without holding locks across IPC or disk.
	// The returned token must be rechecked under the publication fence before a
	// success frame is written; verification alone does not reserve ownership.
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
		if !managedPrepareSessionMatches(s, session) || managedPrepareServerOrigin(captured.Connection.serverURL) != server || captured.Connection.hostID != session.HostID || captured.Connection.bootID != session.BootID {
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
		if !ok || row.AgentPrincipalID != s.PrincipalID.String() || row.Runtime != string(domain.RuntimeQwenCode) || row.Profile != record.Profile || record.Spec.Runtime != domain.RuntimeQwenCode || record.Spec.TenantID != scope.TenantID || record.LaunchState != "launched" || scope != p.scope || managedPrepareServerOrigin(scope.ServerURL) != server || scope.TenantID != session.TenantID || scope.AccountID != session.AccountID || scope.HostID != session.HostID || scope.InstanceID != s.InstanceID.String() || scope.Generation != s.OwnershipGeneration || record.ProfileFingerprint != sessionworker.NativeProfileFingerprint(record.Spec) || p.profile != record.ProfileFingerprint || sessionworker.NativeProfileFingerprint(p.bootstrap.Native) != p.profile || ownership.ProfileFingerprint != record.ProfileFingerprint || ownership.Profile != record.Profile || record.Ownership == nil || !sameManagedPrepareOwnership(*record.Ownership, ownership) {
			return nil, nil, ownership, ErrManagedEndpointPrepareRejected
		}
		return link, p, ownership, nil
	}
	link, p, ownership, err := selectLink()
	if err != nil {
		return nil, err
	}
	result, err := verify(ctx, p, ownership)
	if err != nil {
		// Owner RPC errors arrive as public wire strings through proxy.call.
		// Only its explicit ownership conflict is terminal; lost IPC is retryable.
		if errors.Is(err, ErrManagedEndpointPrepareRejected) || errors.Is(err, sessionworker.ErrConflict) || err.Error() == sessionworker.ErrConflict.Error() {
			return nil, ErrManagedEndpointPrepareRejected
		}
		return nil, ErrManagedEndpointPrepareRetryable
	}
	if result == nil {
		return nil, ErrManagedEndpointPrepareRejected
	}
	snapshot := result.Snapshot
	actualStart, identityErr := proc.StartIdentity(snapshot.PID)
	var origin transport.NativeObservationOrigin
	if identityErr != nil || actualStart != snapshot.NativeStartIdentity || snapshot.Scope != p.scope || snapshot.IdentityPending || snapshot.ActualRuntime != domain.RuntimeQwenCode || snapshot.ProfileFingerprint != p.profile || snapshot.PID <= 0 || snapshot.NativeStartIdentity == "" || snapshot.NativeGeneration != s.NativeGeneration || snapshot.NativeSessionID != s.NativeSessionID || json.Unmarshal(snapshot.Origin, &origin) != nil || origin.ID != s.OriginID.String() || origin.TenantID != s.TenantID.String() || origin.HostID != s.HostID.String() || origin.InstanceID != s.InstanceID.String() || origin.Runtime != string(domain.RuntimeQwenCode) || origin.NativeGeneration != s.NativeGeneration || (origin.NativeSessionID != "" && origin.NativeSessionID != s.NativeSessionID) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	// Origin admission may belong to an earlier socket while the native session
	// survives reconnect. Only current host.session authority is pinned above.
	after, proxy, fresh, err := selectLink()
	if err != nil {
		return nil, err
	}
	if after != link || proxy != p || !sameManagedPrepareOwnership(fresh, ownership) {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	d.nativeWorkersMu.Lock()
	current := d.nativeWorkers[s.InstanceID.String()]
	d.nativeWorkersMu.Unlock()
	if current != link {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	if !time.Now().Before(s.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	return &nativeWorkerPublicationToken{instanceID: s.InstanceID.String(), link: link, proxy: p, ownership: ownership}, nil
}
