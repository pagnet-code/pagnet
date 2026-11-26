//go:build linux || darwin

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
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
	return nativeManagedSessionMatches(nativeManagedSubjectFromEndpoint(s), session)
}

func nativeManagedSessionMatches(s nativeManagedSubject, session transport.HostSessionPayload) bool {
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
	return d.verifyNativeManagedSubjectToken(ctx, captured, configuredServer, nativeManagedSubjectFromEndpoint(command.Subject), verify)
}

// verifyNativeManagedSubjectToken authenticates the exact selected native instance,
// principal and worker independently of the role-specific wire protocol.
func (d *Daemon) verifyNativeManagedSubjectToken(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, s nativeManagedSubject, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	return d.verifyNativeManagedSubjectTokenContextMode(ctx, false, captured, configuredServer, s, verify)
}

// The injected verifier must provide its own bounded RPC and failure lifecycle.
// Endpoint operations supply the bounded ownership RPC and its abort lifecycle.
func (d *Daemon) verifyNativeManagedSubjectTokenContext(ctx context.Context, captured ManagedEndpointPrepareScope, configuredServer string, s nativeManagedSubject, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	return d.verifyNativeManagedSubjectTokenContextMode(ctx, true, captured, configuredServer, s, verify)
}

func (d *Daemon) verifyNativeManagedSubjectTokenContextMode(ctx context.Context, bounded bool, captured ManagedEndpointPrepareScope, configuredServer string, s nativeManagedSubject, verify func(context.Context, *NativeWorkerProxy, transport.NativeWorkerOwnership) (*sessionworker.NativeOwnershipVerifyResult, error)) (*nativeWorkerPublicationToken, error) {
	if bounded && ctx.Err() != nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	// Canonicalize comparison copies only: raw URLs remain part of the exact
	// registry, proxy and owner scope identity.
	server := managedPrepareServerOrigin(configuredServer)
	if captured.Socket == nil || captured.Connection == nil || server == "" || !nativeManagedSessionMatches(s, captured.Session) || !time.Now().Before(s.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	if d.state == nil || d.nativeRegistry == nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	acquire := func(mu *sync.Mutex) (func(), error) {
		if bounded {
			return directEndpointTryLock(ctx, mu)
		}
		mu.Lock()
		return mu.Unlock, nil
	}
	lookup := d.nativeRegistry.Lookup
	recovery := d.nativeRegistry.checkRecoveryFence
	gc := d.nativeRegistry.lookupGC
	instance := d.state.GetInstance
	sessionCopy := captured.Connection.AuthenticatedNativeHostSession
	if bounded {
		lookup = func(id string) (NativeWorkerRecord, error) {
			return directEndpointRegistryLookupContext(ctx, d.nativeRegistry, id)
		}
		recovery = func(id, generation string) error {
			return directEndpointRegistryRecoveryFenceContext(ctx, d.nativeRegistry, id, generation)
		}
		gc = func(id string) (nativeWorkerGC, error) {
			return directEndpointRegistryGCContext(ctx, d.nativeRegistry, id)
		}
		instance = func(id string) (*InstanceRow, bool, error) {
			return directEndpointStateInstanceContext(ctx, d.state, id)
		}
		sessionCopy = func() (transport.HostSessionPayload, error) {
			return authenticatedNativeHostSessionContext(ctx, captured.Connection)
		}
	}
	// Verification copies map/link state without holding locks across IPC or disk.
	// The returned token must be rechecked under the publication fence before a
	// success frame is written; verification alone does not reserve ownership.
	selectLink := func() (*nativeWorkerLink, *NativeWorkerProxy, transport.NativeWorkerOwnership, error) {
		unlock, err := acquire(&d.nativeWorkersMu)
		if err != nil {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		link := d.nativeWorkers[s.InstanceID.String()]
		unlock()
		if link == nil || link.conn != captured.Socket || link.proxy == nil || link.proxy.connection != captured.Connection {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		p := link.proxy
		select {
		case <-p.done:
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		default:
		}
		session, err := sessionCopy()
		if err != nil {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		if !nativeManagedSessionMatches(s, session) || managedPrepareServerOrigin(captured.Connection.serverURL) != server || captured.Connection.hostID != session.HostID || captured.Connection.bootID != session.BootID {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRejected
		}
		unlock, err = acquire(&link.mu)
		if err != nil {
			return nil, nil, transport.NativeWorkerOwnership{}, ErrManagedEndpointPrepareRetryable
		}
		ownership := link.ownership
		unlock()
		if ownership.ID != s.OwnershipID.String() || ownership.InstanceID != s.InstanceID.String() || ownership.OwnershipGeneration != s.OwnershipGeneration || ownership.Runtime != string(domain.RuntimeQwenCode) || ownership.State != "active" || ownership.DeletionProof != nil {
			return nil, nil, ownership, ErrManagedEndpointPrepareRejected
		}
		record, err := lookup(s.InstanceID.String())
		if err != nil {
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		if err := recovery(record.Scope.InstanceID, record.Scope.Generation); err != nil {
			if errors.Is(err, errNativeWorkerRecoveryFenced) {
				return nil, nil, ownership, ErrManagedEndpointPrepareRejected
			}
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		if _, err := gc(record.Scope.InstanceID); !errors.Is(err, sql.ErrNoRows) {
			if err == nil {
				return nil, nil, ownership, ErrManagedEndpointPrepareRejected
			}
			return nil, nil, ownership, ErrManagedEndpointPrepareRetryable
		}
		row, ok, err := instance(s.InstanceID.String())
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
	var observationEpoch uint64
	if bounded {
		observationEpoch, err = p.directEndpointObservationEpochContext(ctx)
		if err != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
	} else {
		observationEpoch = p.directEndpointObservationEpoch()
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
	// The authenticated worker's current snapshot is an independent lifecycle
	// observation. A stale requested subject must not suppress its revocation.
	if snapshot.Scope != p.scope || snapshot.ActualRuntime != domain.RuntimeQwenCode || snapshot.ProfileFingerprint != p.profile {
		return nil, ErrManagedEndpointPrepareRejected
	}
	var verifiedEndpointEpoch uint64
	if bounded {
		verifiedEndpointEpoch, err = p.observeDirectEndpointSnapshotContext(ctx, snapshot, observationEpoch)
		if err != nil {
			return nil, ErrManagedEndpointPrepareRetryable
		}
	} else {
		verifiedEndpointEpoch = p.observeDirectEndpointSnapshot(snapshot, observationEpoch)
	}
	actualStart, identityErr := proc.StartIdentity(snapshot.PID)
	if identityErr != nil || actualStart != snapshot.NativeStartIdentity {
		if bounded {
			_ = p.beginDirectEndpointTransitionContext(ctx)
		} else {
			p.beginDirectEndpointTransition()
		}
		return nil, ErrManagedEndpointPrepareRejected
	}
	var origin transport.NativeObservationOrigin
	if snapshot.IdentityPending || snapshot.PID <= 0 || snapshot.NativeStartIdentity == "" || snapshot.NativeGeneration != s.NativeGeneration || snapshot.NativeSessionID != s.NativeSessionID || json.Unmarshal(snapshot.Origin, &origin) != nil || origin.ID != s.OriginID.String() || origin.TenantID != s.TenantID.String() || origin.HostID != s.HostID.String() || origin.InstanceID != s.InstanceID.String() || origin.Runtime != string(domain.RuntimeQwenCode) || origin.NativeGeneration != s.NativeGeneration || (origin.NativeSessionID != "" && origin.NativeSessionID != s.NativeSessionID) {
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
	unlock, err := acquire(&d.nativeWorkersMu)
	if err != nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	current := d.nativeWorkers[s.InstanceID.String()]
	unlock()
	if current != link {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	if !time.Now().Before(s.ExpiresAt) {
		return nil, ErrManagedEndpointPrepareRejected
	}
	if bounded && ctx.Err() != nil {
		return nil, ErrManagedEndpointPrepareRetryable
	}
	return &nativeWorkerPublicationToken{endpointEpoch: verifiedEndpointEpoch, instanceID: s.InstanceID.String(), link: link, proxy: p, ownership: ownership, subject: s}, nil
}

func nativeManagedSubjectFromEndpoint(s transport.ManagedEndpointBindingIntent) nativeManagedSubject {
	return nativeManagedSubject{TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID, HostCredentialID: s.HostCredentialID, NativeAdmissionID: s.NativeAdmissionID, ConnectionIncarnationID: s.ConnectionIncarnationID, RunnerID: s.RunnerID, RunnerConnectedAt: s.RunnerConnectedAt, BootID: s.BootID, InstanceID: s.InstanceID, OwnershipID: s.OwnershipID, OwnershipGeneration: s.OwnershipGeneration, PrincipalID: s.PrincipalID, NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID, OriginID: s.OriginID, ExpiresAt: s.ExpiresAt}
}

func nativeManagedSubjectFromSource(s transport.DirectManagedSourceBindingV1) nativeManagedSubject {
	return nativeManagedSubject{TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID, HostCredentialID: s.HostCredentialID, NativeAdmissionID: s.NativeAdmissionID, ConnectionIncarnationID: s.ConnectionIncarnationID, RunnerID: s.RunnerID, RunnerConnectedAt: s.RunnerConnectedAt, BootID: s.BootID, InstanceID: s.InstanceID, OwnershipID: s.OwnershipID, OwnershipGeneration: s.OwnershipGeneration, PrincipalID: s.PrincipalID, NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID, OriginID: s.OriginID, ExpiresAt: s.ExpiresAt}
}

func nativeManagedSubjectFromSourceV2(s transport.DirectManagedSourceBindingV2) nativeManagedSubject {
	return nativeManagedSubject{TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID, HostCredentialID: s.HostCredentialID, NativeAdmissionID: s.NativeAdmissionID, ConnectionIncarnationID: s.ConnectionIncarnationID, RunnerID: s.RunnerID, RunnerConnectedAt: s.RunnerConnectedAt, BootID: s.BootID, InstanceID: s.InstanceID, OwnershipID: s.OwnershipID, OwnershipGeneration: s.OwnershipGeneration, PrincipalID: s.PrincipalID, NativeGeneration: s.NativeGeneration, NativeSessionID: s.NativeSessionID, OriginID: s.OriginID, ExpiresAt: s.EnrollmentExpiresAt}
}
